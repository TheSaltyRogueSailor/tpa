/**
 * Real Metal (alta-testnet) client for the USDZ rail, plus the env-flag selection that falls back to the
 * in-memory mock. Nothing here runs unless METAL_LIVE=1 AND an RPC URL and payer key are available, so tests
 * and CI never need secrets and never touch the chain.
 *
 * Per docs.metalntwx.com:
 *   - Testnet chain id 63825 (0xf951)                         (JSON-RPC reference, "Get the chain ID")
 *   - *USDZ at 0x...b5d5, 18 decimals, the default gas token   (Reference > Contract Addresses; Build > Direct payment)
 *   - MIP20Factory 0x...0f4c, isMIP20(token) before use          (Contract Addresses; Direct payment)
 *   - transfer via @metalntwx/metal-ts signMip20Contract (0x7f envelope, gas paid in USDZ, gas price 1 base unit)
 *   - settlement: successful receipt + Transfer(from,to,value) log from the token + receipt block <=
 *     consensus_status.finalized.number + canonical block hash at that height matches (Settlement and Finality)
 *
 * Secrets: METAL_RPC_URL (contains the endpoint id, which is the credential), METAL_API_KEY and METAL_PAYER_KEY
 * are never logged. Every error leaving this module is passed through maskSecrets().
 */
import { readFileSync, existsSync } from "node:fs";
import { createPublicClient, createWalletClient, defineChain, encodeFunctionData, erc20Abi, getAddress, http, parseAbi, parseEventLogs, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { estimateGasLimit, signMip20Contract } from "@metalntwx/metal-ts";
import { createMockMetalClient, METAL_TESTNET, PaymentRefused, type MetalClient } from "./payments.js";

export const METAL_MIP20_FACTORY = "0x0000000000000000000000000000000000000f4c" as const;
const USDZ = METAL_TESTNET.usdz as Address;
const GAS_FALLBACK = 200_000n;

/* ---------------------------------- secrets ---------------------------------- */
/** Minimal KEY=VALUE parser (no interpolation); comments and blank lines are ignored. */
export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trim().startsWith("#")) continue;
    out[m[1]!] = m[2]!.replace(/^(['"])(.*)\1$/, "$2");
  }
  return out;
}
/** Process env wins over the gitignored files, so CI/shell can override. Files are only read when asked. */
export function loadMetalEnv(env: NodeJS.ProcessEnv = process.env, files = [".env.metal", ".env.metal-wallet", ".env.metal-demo"]): Record<string, string | undefined> {
  const merged: Record<string, string | undefined> = {};
  for (const f of files) if (existsSync(f)) Object.assign(merged, parseEnvFile(readFileSync(f, "utf8")));
  for (const [k, v] of Object.entries(env)) if (v !== undefined && v !== "") merged[k] = v;
  return merged;
}
export function maskSecrets(text: string, secrets: Array<string | undefined>): string {
  let out = text;
  const parts = new Set<string>();
  for (const s of secrets) {
    if (!s || s.length < 6) continue;
    parts.add(s);
    try { const u = new URL(s); for (const seg of u.pathname.split("/")) if (seg.length >= 6 && !/^v\d+$/.test(seg)) parts.add(seg); } catch { /* not a URL */ }
    if (/^0x[0-9a-fA-F]{64}$/.test(s)) parts.add(s.slice(2));
  }
  for (const p of [...parts].sort((a, b) => b.length - a.length)) out = out.split(p).join("<masked>");
  return out;
}

/* -------------------------------- live client -------------------------------- */
export type MetalLiveConfig = { rpcUrl: string; payerKey: Hex; apiKey?: string; receiptTimeoutMs?: number; finalityTimeoutMs?: number };
export const metalTestnet = (rpcUrl: string) => defineChain({
  id: METAL_TESTNET.chainId, name: "Metal Testnet", nativeCurrency: { name: "USDZ", symbol: "USDZ", decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } },
});

export function createMetalTestnetClient(config: MetalLiveConfig): MetalClient & { readonly payer: Address; verifyNetwork(): Promise<void> } {
  const secrets = [config.rpcUrl, config.apiKey, config.payerKey];
  const mask = (e: unknown) => maskSecrets(e instanceof Error ? e.message : String(e), secrets);
  const fail = (reason: string, e: unknown): never => { throw new PaymentRefused(reason, `Metal testnet: ${mask(e)}`); };
  const chain = metalTestnet(config.rpcUrl);
  const account = privateKeyToAccount(config.payerKey);
  const publicClient = createPublicClient({ chain, transport: http(config.rpcUrl) }) as PublicClient;
  const walletClient = createWalletClient({ chain, account, transport: http(config.rpcUrl) });
  let verified: Promise<void> | undefined;
  let queue: Promise<unknown> = Promise.resolve(); // serialize per signing account (docs: avoid nonce reuse)

  async function verifyNetwork() {
    const id = await publicClient.getChainId();
    if (id !== METAL_TESTNET.chainId) throw new Error(`wrong chain id ${id}, expected ${METAL_TESTNET.chainId}`);
    const isMip20 = await publicClient.readContract({ address: METAL_MIP20_FACTORY, abi: parseAbi(["function isMIP20(address token) view returns (bool)"]), functionName: "isMIP20", args: [USDZ] });
    if (!isMip20) throw new Error("USDZ address is not a MIP20 token");
    const decimals = await publicClient.readContract({ address: USDZ, abi: erc20Abi, functionName: "decimals" });
    if (decimals !== METAL_TESTNET.decimals) throw new Error(`USDZ decimals ${decimals}, expected ${METAL_TESTNET.decimals}`);
  }
  const ensure = () => (verified ??= verifyNetwork().catch(e => { verified = undefined; throw e; }));

  async function waitFinalized(blockNumber: bigint, blockHash: Hex) {
    const deadline = Date.now() + (config.finalityTimeoutMs ?? 60_000);
    while (Date.now() < deadline) {
      const status = await publicClient.request({ method: "consensus_status" as never, params: [] as never }) as { finalized?: { number?: number | string } };
      const fin = status?.finalized?.number;
      if (fin !== undefined && BigInt(fin) >= blockNumber) {
        const block = await publicClient.getBlock({ blockNumber });
        if (block.hash?.toLowerCase() !== blockHash.toLowerCase()) throw new Error("canonical block hash differs from receipt");
        return true;
      }
      await new Promise(r => setTimeout(r, 250));
    }
    return false;
  }

  /** Receipt + matching USDZ Transfer log + finality for an already signed transfer. Shared by transfer and reconcile. */
  async function settle(txHash: Hex, recipient: Address, amount: bigint, receipt: Awaited<ReturnType<PublicClient["getTransactionReceipt"]>>) {
    if (receipt.status !== "success") throw new PaymentRefused("metal_tx_reverted", `Metal testnet: transaction ${txHash} reverted.`);
    const transfers = parseEventLogs({ abi: erc20Abi, eventName: "Transfer", logs: receipt.logs });
    const match = transfers.some(l => l.address.toLowerCase() === USDZ.toLowerCase() && getAddress(l.args.from) === account.address && getAddress(l.args.to) === recipient && l.args.value === amount);
    if (!match) throw new PaymentRefused("metal_transfer_not_found", `Metal testnet: no matching USDZ Transfer to the merchant in ${txHash} (possible ReceivePolicy quarantine).`);
    let finalized = false;
    try { finalized = await waitFinalized(receipt.blockNumber, receipt.blockHash); } catch (e) { fail("metal_finality_check", `${mask(e)} (tx ${txHash})`); }
    if (!finalized) throw new PaymentRefused("metal_not_final", `Metal testnet: ${txHash} executed but is not final yet; keep pending, do not resend.`);
    return { txHash, finalized };
  }

  async function transferOnce(from: string, to: string, amount: bigint, onSigned?: (txHash: string) => Promise<void>) {
    if (getAddress(from) !== account.address) throw new PaymentRefused("payer_mismatch", "Metal testnet: payer address does not match the signing key.");
    if (amount <= 0n) throw new PaymentRefused("invalid_amount", "Metal testnet: amount must be positive.");
    const recipient = getAddress(to);
    try { await ensure(); } catch (e) { fail("metal_network_check", e); }
    let signed;
    try {
      const data = encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [recipient, amount] });
      const gasLimit = await estimateGasLimit(publicClient, account.address, USDZ, data, GAS_FALLBACK, false);
      const maxFeePerGas = 1n; // eth_gasPrice on Metal is 0x1 (one gas-token base unit per gas)
      const balance = await publicClient.readContract({ address: USDZ, abi: erc20Abi, functionName: "balanceOf", args: [account.address] });
      if (balance < amount + gasLimit * maxFeePerGas) throw new PaymentRefused("insufficient_usdz", "Metal testnet: insufficient USDZ for amount plus gas (fund the payer from the Metal faucet).");
      signed = await signMip20Contract({ publicClient, walletClient, address: USDZ, abi: erc20Abi, functionName: "transfer", args: [recipient, amount], gasToken: USDZ, gasLimit, gasFallback: gasLimit, maxFeePerGas });
    } catch (e) { if (e instanceof PaymentRefused) throw e; fail("metal_sign_failed", e); }
    const txHash = signed!.txHash; // computed before broadcast; if send/receipt fails, check this hash, never resend blindly
    if (onSigned) await onSigned(txHash); // the dispatch ledger records the hash durably before broadcast; a throw here aborts the send
    try { await signed!.send(); } catch (e) { fail("metal_broadcast_failed", `${mask(e)} (tx ${txHash})`); }
    let receipt;
    try { receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: config.receiptTimeoutMs ?? 60_000 }); }
    catch (e) { fail("metal_receipt_pending", `${mask(e)} (tx ${txHash}; do not resend, check this hash)`); }
    return settle(txHash, recipient, amount, receipt!);
  }

  async function reconcileOnce(txHash: string, from: string, to: string, amount: bigint) {
    if (getAddress(from) !== account.address) throw new PaymentRefused("payer_mismatch", "Metal testnet: payer address does not match the signing key.");
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return null;
    let receipt;
    try { receipt = await publicClient.getTransactionReceipt({ hash: txHash as Hex }); }
    catch { return null; } // not mined (or not found yet): stay pending, never resend
    return settle(txHash as Hex, getAddress(to), amount, receipt);
  }

  return {
    chainId: METAL_TESTNET.chainId, mode: "testnet", payer: account.address, verifyNetwork: ensure,
    async balanceOf(address) {
      try { return await publicClient.readContract({ address: USDZ, abi: erc20Abi, functionName: "balanceOf", args: [getAddress(address)] }); }
      catch (e) { return fail("metal_read_failed", e); }
    },
    transfer({ from, to, amount, onSigned }) {
      // The MIP20 transfer has no memo field; the TPA mandate hash stays in the adapter's result detail.
      const run = queue.then(() => transferOnce(from, to, amount, onSigned));
      queue = run.catch(() => undefined);
      return run;
    },
    reconcile({ txHash, from, to, amount }) {
      const run = queue.then(() => reconcileOnce(txHash, from, to, amount));
      queue = run.catch(() => undefined);
      return run;
    },
  };
}

/* --------------------------------- selection --------------------------------- */
export type MetalSelection = { client: MetalClient; payer: string; live: boolean; reason: string; merchantAddress?: string };
/**
 * METAL_LIVE=1 + METAL_RPC_URL + METAL_PAYER_KEY -> real alta-testnet client. Anything missing -> mock, with the
 * reason (never a secret value). The gitignored .env.metal / .env.metal-wallet / .env.metal-demo files are only read
 * when the flag is on. .env.metal-demo holds non-secret defaults such as METAL_MERCHANT_ADDRESS.
 */
export function selectMetalClient(options: { env?: NodeJS.ProcessEnv; files?: string[]; mockPayer: string; mockBalance: bigint }): MetalSelection {
  const env = options.env ?? process.env;
  const mock = (reason: string): MetalSelection => ({ client: createMockMetalClient({ [options.mockPayer]: options.mockBalance }), payer: options.mockPayer, live: false, reason });
  if (env.METAL_LIVE !== "1") return mock("METAL_LIVE not set");
  const cfg = loadMetalEnv(env, options.files);
  if (!cfg.METAL_RPC_URL) return mock("METAL_LIVE=1 but METAL_RPC_URL missing");
  if (!cfg.METAL_PAYER_KEY) return mock("METAL_LIVE=1 but METAL_PAYER_KEY missing");
  if (!/^0x[0-9a-fA-F]{64}$/.test(cfg.METAL_PAYER_KEY)) return mock("METAL_LIVE=1 but METAL_PAYER_KEY is malformed");
  try { new URL(cfg.METAL_RPC_URL); } catch { return mock("METAL_LIVE=1 but METAL_RPC_URL is malformed"); }
  const client = createMetalTestnetClient({ rpcUrl: cfg.METAL_RPC_URL, apiKey: cfg.METAL_API_KEY, payerKey: cfg.METAL_PAYER_KEY as Hex });
  let merchantAddress: string | undefined;
  if (cfg.METAL_MERCHANT_ADDRESS) {
    try { merchantAddress = getAddress(cfg.METAL_MERCHANT_ADDRESS); } catch { return mock("METAL_LIVE=1 but METAL_MERCHANT_ADDRESS is malformed"); }
  }
  return { client, payer: client.payer, live: true, reason: "METAL_LIVE=1 with RPC URL and payer key", merchantAddress };
}
