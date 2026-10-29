import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { maskSecrets, parseEnvFile, selectMetalClient } from "../shopper/metal.js";
import { createFileDispatchStore, createMetalUsdzAdapter, PaymentRefused, type ConsumeReceipt } from "../shopper/payments.js";
import { boundLedger, reviewCheckout } from "./support/dispatch.js";

// Obviously fake values: nothing here talks to a network.
const FAKE_KEY = `0x${"11".repeat(32)}`;
const FAKE_URL = "https://rpc.invalid/v1/fake-endpoint-id-123456";
const base = { mockPayer: "0x000000000000000000000000000000000000a11c", mockBalance: 10n ** 18n };

describe("Metal live/mock selection", () => {
  it("falls back to the mock when METAL_LIVE is not set, without reading the secret files", () => {
    const dir = mkdtempSync(join(tmpdir(), "metal-"));
    const file = join(dir, ".env.metal");
    writeFileSync(file, `METAL_RPC_URL=${FAKE_URL}\nMETAL_PAYER_KEY=${FAKE_KEY}\n`);
    const s = selectMetalClient({ ...base, env: {}, files: [file] });
    expect(s).toMatchObject({ live: false, payer: base.mockPayer, reason: "METAL_LIVE not set" });
    expect(s.client.mode).toBe("mock");
  });

  it.each([
    [{ METAL_LIVE: "1" }, "METAL_RPC_URL missing"],
    [{ METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL }, "METAL_PAYER_KEY missing"],
    [{ METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL, METAL_PAYER_KEY: "0x1234" }, "METAL_PAYER_KEY is malformed"],
    [{ METAL_LIVE: "1", METAL_RPC_URL: "not a url", METAL_PAYER_KEY: FAKE_KEY }, "METAL_RPC_URL is malformed"],
  ])("falls back to the mock when credentials are missing (%o)", (env, reason) => {
    const s = selectMetalClient({ ...base, env, files: [] });
    expect(s.live).toBe(false);
    expect(s.client.mode).toBe("mock");
    expect(s.reason).toContain(reason);
    expect(s.reason).not.toContain(FAKE_URL);
  });

  it("selects the live testnet client only with the flag and both credentials", () => {
    const s = selectMetalClient({ ...base, env: { METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL, METAL_PAYER_KEY: FAKE_KEY }, files: [] });
    expect(s.live).toBe(true);
    expect(s.client.mode).toBe("testnet");
    expect(s.client.chainId).toBe(63825);
    expect(s.payer).toBe(privateKeyToAccount(FAKE_KEY as `0x${string}`).address);
    expect(JSON.stringify(s)).not.toContain(FAKE_KEY.slice(2));
  });

  it("takes a non-secret METAL_MERCHANT_ADDRESS default and rejects a malformed one", () => {
    const env = { METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL, METAL_PAYER_KEY: FAKE_KEY };
    const ok = selectMetalClient({ ...base, env: { ...env, METAL_MERCHANT_ADDRESS: "0x692519584dee2d0a9c88782d8cf3b46d46f817ee" }, files: [] });
    expect(ok.merchantAddress).toBe("0x692519584DEE2D0A9C88782d8cF3B46d46f817EE");
    const bad = selectMetalClient({ ...base, env: { ...env, METAL_MERCHANT_ADDRESS: "0xnope" }, files: [] });
    expect(bad).toMatchObject({ live: false, reason: expect.stringContaining("METAL_MERCHANT_ADDRESS is malformed") });
  });

  it("the live adapter still refuses to pay without a TPA consume receipt (no network call)", async () => {
    const s = selectMetalClient({ ...base, env: { METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL, METAL_PAYER_KEY: FAKE_KEY }, files: [] });
    const adapter = createMetalUsdzAdapter(s.client, s.payer, boundLedger([], createFileDispatchStore(join(mkdtempSync(join(tmpdir(), "metal-ledger-")), "journal.json"))));
    const bad = { consumed: false, intentId: "", mandateHash: "x" } as unknown as ConsumeReceipt;
    await expect(adapter.pay({ receipt: bad, checkoutId: "c", checkout: reviewCheckout() })).rejects.toMatchObject({ reason: "no_tpa_receipt" });
  });
});

describe("Metal secret handling", () => {
  it("masks the RPC URL, its endpoint id and the private key in error text", () => {
    const text = `request to ${FAKE_URL} failed; id fake-endpoint-id-123456; key ${FAKE_KEY} / ${FAKE_KEY.slice(2)}`;
    const masked = maskSecrets(text, [FAKE_URL, FAKE_KEY]);
    expect(masked).not.toContain("fake-endpoint-id-123456");
    expect(masked).not.toContain(FAKE_KEY.slice(2));
    expect(masked).toContain("<masked>");
  });

  it("parses KEY=VALUE env files, ignoring comments", () => {
    expect(parseEnvFile("# c\nA=1\nexport B=\"two\"\n\nC = 3 \n")).toEqual({ A: "1", B: "two", C: "3" });
  });
});
