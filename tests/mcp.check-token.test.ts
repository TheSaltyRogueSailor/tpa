// check_token through a real MCP client, with a stubbed fetch (no network in tests).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createTpaShieldServer, resolveSolanaRpcUrl } from "../mcp/server.js";
import { checkToken, isSolanaAddress } from "../mcp/token.js";
import { DEFAULT_SOLANA_RPC_URL, parseMintAccount, type FetchLike } from "../mcp/token-gate/guard.js";
import { healthy, rugLike } from "./fixtures/token-gate.js";

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SAFE = "So11111111111111111111111111111111111111112";
const SPL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const T22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const USDT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
const PYUSD = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
/** Not on the allowlist, same authorities as USDC. */
const LOOKALIKE = "Vote111111111111111111111111111111111111111";
const AUTHORITIES = { mintAuthority: "BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG", freezeAuthority: "7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar" };

/** Shape of a jsonParsed getAccountInfo result for a mint. */
function mintAccount(info: Record<string, unknown>, owner = SPL) {
  return { owner, data: { program: owner === SPL ? "spl-token" : "spl-token-2022", parsed: { type: "mint", info: { decimals: 6, isInitialized: true, supply: "1000000000000000", mintAuthority: null, freezeAuthority: null, ...info } } } };
}

type Route = { rpc?: unknown | "down"; rugcheck?: unknown | "down" };
function stubFetch(routes: Record<string, Route>, calls: string[] = []): FetchLike {
  return async (url, init) => {
    calls.push(url);
    if (url === DEFAULT_SOLANA_RPC_URL || url.startsWith("https://rpc.test")) {
      const mint = JSON.parse(init?.body ?? "{}").params?.[0] as string;
      const route = routes[mint]?.rpc;
      if (route === "down") throw new Error("network down");
      return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value: route ?? null } }) };
    }
    const match = /^https:\/\/api\.rugcheck\.xyz\/v1\/tokens\/([^/]+)\/report$/.exec(url);
    if (match) {
      const route = routes[decodeURIComponent(match[1]!)]?.rugcheck;
      if (route === "down" || route === undefined) return { ok: false, status: 503, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => route };
    }
    throw new Error(`unexpected URL in test: ${url}`);
  };
}

const cleanReport = { rugged: false, creatorTokens: [], risks: [] };
const routes: Record<string, Route> = {
  [SAFE]: { rpc: mintAccount({}), rugcheck: cleanReport },
  [USDC]: { rpc: mintAccount(AUTHORITIES), rugcheck: cleanReport },
  [USDT]: { rpc: mintAccount(AUTHORITIES), rugcheck: cleanReport },
  [LOOKALIKE]: { rpc: mintAccount(AUTHORITIES), rugcheck: cleanReport },
};

let client: Client;
const calls: string[] = [];

async function token(args: Record<string, unknown>) {
  const response = await client.callTool({ name: "check_token", arguments: args });
  const content = response.content as Array<{ text: string }>;
  return JSON.parse(content[0]!.text) as Record<string, any>;
}

beforeAll(async () => {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createTpaShieldServer({ tokenGate: { fetchImpl: stubFetch(routes, calls), rpcTimeoutMs: 200, rugcheckTimeoutMs: 200 } }).connect(serverSide);
  client = new Client({ name: "check-token-test", version: "0.0.0" });
  await client.connect(clientSide);
});
afterAll(async () => { await client.close(); });

describe("check_token over MCP", () => {
  it("is listed as a read-only, open-world tool", async () => {
    const tool = (await client.listTools()).tools.find(entry => entry.name === "check_token");
    expect(tool?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, openWorldHint: true });
  });

  it("warns (not passes) a clean mint with no trade history, and keeps the pre-flight note", async () => {
    const body = await token({ mint: SAFE });
    expect(body.decision).toBe("warn");
    expect(body.reasons).toEqual([]);
    expect(body.warnings.map((w: { code: string }) => w.code)).toEqual(["trade_history_not_provided", "creator_unknown"]);
    expect(body.note).toMatch(/not an approval/);
    expect(body.details.rugcheck).toEqual({ rugged: false, creatorTokens: 0, dangerRisks: [], warnRisks: [] });
  });

  it("blocks a mint with active mint and freeze authority (honeypot risk)", async () => {
    const body = await token({ mint: LOOKALIKE });
    expect(body.decision).toBe("block");
    expect(body.reasons.map((r: { code: string }) => r.code)).toEqual(["mint_authority_active", "freeze_authority_active"]);
    expect(body.reasons[1].text).toMatch(/honeypot/);
    expect(body.reasons[1].layer).toBe("contract");
  });

  it("warns instead of blocks for allowlisted USDC and USDT when the only blocks are mint and freeze authority", async () => {
    for (const mint of [USDC, USDT]) {
      const body = await token({ mint });
      expect(body.decision, mint).toBe("warn");
      expect(body.reasons).toEqual([]);
      const codes = body.warnings.map((w: { code: string }) => w.code);
      expect(codes.slice(0, 3)).toEqual(["issuer_controlled_stablecoin", "mint_authority_active", "freeze_authority_active"]);
      expect(body.warnings[0].detail).toMatch(mint === USDC ? /USDC \(Circle\)/ : /USDT \(Tether\)/);
    }
  });

  it("still blocks an allowlisted stablecoin on any other block reason", async () => {
    const cases: Array<[Route, string]> = [
      [{ rpc: mintAccount(AUTHORITIES), rugcheck: { rugged: true, creatorTokens: [], risks: [] } }, "rugcheck_rugged"],
      [{ rpc: mintAccount(AUTHORITIES), rugcheck: { rugged: false, creatorTokens: [], risks: [{ name: "Honeypot detected", level: "danger" }] } }, "rugcheck_danger"],
      [{ rpc: mintAccount({ ...AUTHORITIES, extensions: [{ extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 50 } } }] }), rugcheck: cleanReport }, "transfer_fee"],
      [{ rpc: "down", rugcheck: cleanReport }, "mint_info_unavailable"],
    ];
    const saved = routes[USDC]!;
    try {
      for (const [route, code] of cases) {
        routes[USDC] = route;
        const body = await token({ mint: USDC });
        expect(body.decision, code).toBe("block");
        const codes = body.reasons.map((r: { code: string }) => r.code);
        expect(codes).toContain(code);
        expect(body.warnings.map((w: { code: string }) => w.code)).not.toContain("issuer_controlled_stablecoin");
      }
      routes[USDC] = saved;
      const dumped = await token({ mint: USDC, creatorHistory: { launchesLastHour: 0, priorDumps: 1, priorTokens: 1 } });
      expect(dumped.decision).toBe("block");
      expect(dumped.reasons.map((r: { code: string }) => r.code)).toEqual(["mint_authority_active", "freeze_authority_active", "creator_dumped_before"]);
    } finally {
      routes[USDC] = saved;
    }
  });

  it("does not apply the allowance when the token program is not the expected one", async () => {
    const saved = routes[USDC]!;
    routes[USDC] = { rpc: mintAccount(AUTHORITIES, T22), rugcheck: cleanReport };
    try {
      expect((await token({ mint: USDC })).decision).toBe("block");
    } finally {
      routes[USDC] = saved;
    }
  });

  it("PYUSD: warns with authorities only, but blocks on its Token-2022 permanent delegate and transfer hook", async () => {
    routes[PYUSD] = { rpc: mintAccount(AUTHORITIES, T22), rugcheck: cleanReport };
    const authoritiesOnly = await token({ mint: PYUSD });
    expect(authoritiesOnly.decision).toBe("warn");
    expect(authoritiesOnly.warnings[0].code).toBe("issuer_controlled_stablecoin");
    routes[PYUSD] = { rpc: mintAccount({ ...AUTHORITIES, extensions: [{ extension: "permanentDelegate" }, { extension: "transferHook" }, { extension: "metadataPointer" }] }, T22), rugcheck: cleanReport };
    const live = await token({ mint: PYUSD });
    expect(live.decision).toBe("block");
    expect(live.reasons.map((r: { code: string }) => r.code)).toEqual(["mint_authority_active", "freeze_authority_active", "token2022_dangerous_extension", "token2022_dangerous_extension"]);
  });

  it("degrades to a rugcheck_unavailable warning when RugCheck is down", async () => {
    const mint = "11111111111111111111111111111112";
    routes[mint] = { rpc: mintAccount({}), rugcheck: "down" };
    const body = await token({ mint });
    expect(body.decision).toBe("warn");
    expect(body.warnings.map((w: { code: string }) => w.code)).toContain("rugcheck_unavailable");
  });

  it("fails closed when the mint cannot be read", async () => {
    const mint = "SysvarC1ock11111111111111111111111111111111";
    routes[mint] = { rpc: "down", rugcheck: cleanReport };
    const body = await token({ mint });
    expect(body.decision).toBe("block");
    expect(body.reasons[0].code).toBe("mint_info_unavailable");
  });

  it("blocks Token-2022 transfer hooks and transfer fees", async () => {
    const mint = "SysvarRent111111111111111111111111111111111";
    routes[mint] = { rpc: mintAccount({ extensions: [{ extension: "transferHook", state: {} }, { extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 300 } } }] }, T22), rugcheck: cleanReport };
    const body = await token({ mint });
    expect(body.reasons.map((r: { code: string }) => r.code)).toEqual(["token2022_dangerous_extension", "transfer_fee"]);
    expect(body.details.mintInfo.program).toBe("token-2022");
  });

  it("blocks on RugCheck rugged flag and honeypot-class danger risks; other risks warn", async () => {
    const mint = "Stake11111111111111111111111111111111111111";
    routes[mint] = { rpc: mintAccount({}), rugcheck: { rugged: true, creatorTokens: [], risks: [
      { name: "Freeze Authority still enabled", level: "danger" }, { name: "Low amount of LP Providers", level: "danger" }, { name: "Mutable metadata", level: "warn" },
    ] } };
    const body = await token({ mint });
    expect(body.decision).toBe("block");
    expect(body.reasons.map((r: { code: string }) => r.code).sort()).toEqual(["rugcheck_danger", "rugcheck_rugged"]);
    expect(body.warnings.map((w: { detail: string }) => w.detail)).toContain("rugcheck:Mutable metadata");
  });

  it("evaluates holders and creator selling when pump.fun trades are given", async () => {
    const { curve, creator } = rugLike();
    const body = await token({ mint: SAFE, creator, trades: curve.trades });
    expect(body.decision).toBe("block");
    const codes = body.reasons.map((r: { code: string }) => r.code);
    expect(codes).toContain("creator_holds");
    expect(codes).toContain("creator_selling");
    expect(body.details.metrics.creatorSoldPct).toBeGreaterThan(30);
  });

  it("passes a clean mint with a healthy launch, the creator and a clean RugCheck report", async () => {
    const { curve, creator } = healthy();
    const body = await token({ mint: SAFE, creator, trades: curve.trades });
    expect(body.decision).toBe("pass");
    expect(body.reasons).toEqual([]);
    expect(body.warnings).toEqual([]);
  });

  it("blocks creators with prior dumps from the provided history", async () => {
    const body = await token({ mint: SAFE, creatorHistory: { launchesLastHour: 1, priorDumps: 2, priorTokens: 3 } });
    expect(body.reasons.map((r: { code: string }) => r.code)).toEqual(["creator_dumped_before"]);
  });

  it("rejects an invalid mint address without any network call", async () => {
    const before = calls.length;
    const body = await token({ mint: "not-a-mint" });
    expect(body.decision).toBe("block");
    expect(body.reasons[0].code).toBe("mint_address_invalid");
    expect(calls.length).toBe(before);
  });

  it("can skip RugCheck, and then never calls it", async () => {
    const before = calls.length;
    const body = await token({ mint: SAFE, rugcheck: false });
    expect(body.warnings.map((w: { code: string }) => w.code)).toContain("rugcheck_skipped");
    expect(calls.slice(before).some(url => url.includes("rugcheck"))).toBe(false);
  });

  it("only ever calls the configured RPC and RugCheck", () => {
    for (const url of calls) expect(url === DEFAULT_SOLANA_RPC_URL || url.startsWith("https://api.rugcheck.xyz/v1/tokens/")).toBe(true);
  });

  it("explain_decision and get_policy know the token gate", async () => {
    const explain = await client.callTool({ name: "explain_decision", arguments: { code: "freeze_authority_active" } });
    expect(JSON.parse((explain.content as Array<{ text: string }>)[0]!.text)).toMatchObject({ category: "token safety (check_token)", known: true });
    const policy = await client.callTool({ name: "get_policy", arguments: {} });
    const body = JSON.parse((policy.content as Array<{ text: string }>)[0]!.text);
    expect(body.tokenGate.thresholdsVersion).toBe("1.1.0");
    expect(body.tokenGate.issuerControlledStablecoins.mints.map((m: { symbol: string }) => m.symbol)).toEqual(["USDC", "USDT", "PYUSD"]);
    const stable = await client.callTool({ name: "explain_decision", arguments: { code: "issuer_controlled_stablecoin" } });
    expect(JSON.parse((stable.content as Array<{ text: string }>)[0]!.text)).toMatchObject({ category: "token safety (check_token)", known: true });
    expect(body.preflightChecks.check_token).toMatch(/honeypot/);
  });
});

describe("token gate helpers", () => {
  it("validates Solana addresses offline", () => {
    expect(isSolanaAddress(USDC)).toBe(true);
    expect(isSolanaAddress(SAFE)).toBe(true);
    expect(isSolanaAddress("0x1234")).toBe(false);
    expect(isSolanaAddress("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1l")).toBe(false);
    expect(isSolanaAddress("1111111111111111111111111111111")).toBe(false);
  });

  it("parses only token mint accounts", () => {
    expect(parseMintAccount(null)).toBeNull();
    expect(parseMintAccount({ owner: SPL, data: { parsed: { type: "account", info: {} } } })).toBeNull();
    expect(parseMintAccount(mintAccount({}))).toMatchObject({ program: "spl-token", mintAuthority: null, freezeAuthority: null, supply: 1e9 });
  });

  it("uses a custom RPC URL when configured, and refuses non-https overrides", async () => {
    const seen: string[] = [];
    await checkToken({ mint: SAFE, rugcheck: false }, { rpcUrl: "https://rpc.test/", fetchImpl: stubFetch(routes, seen) });
    expect(seen).toEqual(["https://rpc.test/"]);
    expect(resolveSolanaRpcUrl(undefined)).toBe(DEFAULT_SOLANA_RPC_URL);
    expect(resolveSolanaRpcUrl("http://127.0.0.1:8899")).toBe("http://127.0.0.1:8899/");
    expect(() => resolveSolanaRpcUrl("http://evil.example")).toThrow(/https/);
  });

  it("times out a hanging RPC and fails closed", async () => {
    const hang: FetchLike = (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    const started = Date.now();
    const result = await checkToken({ mint: SAFE }, { fetchImpl: hang, rpcTimeoutMs: 50, rugcheckTimeoutMs: 50 });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(result.decision).toBe("block");
    expect(result.reasons[0]!.code).toBe("mint_info_unavailable");
    expect(result.warnings.map(w => w.code)).toContain("rugcheck_unavailable");
  });
});
