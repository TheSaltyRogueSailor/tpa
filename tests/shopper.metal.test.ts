import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { maskSecrets, parseEnvFile, selectMetalClient } from "../shopper/metal.js";
import { createMetalUsdzAdapter, PaymentRefused, type ConsumeReceipt } from "../shopper/payments.js";

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

  it("the live adapter still refuses to pay without a TPA consume receipt (no network call)", async () => {
    const s = selectMetalClient({ ...base, env: { METAL_LIVE: "1", METAL_RPC_URL: FAKE_URL, METAL_PAYER_KEY: FAKE_KEY }, files: [] });
    const adapter = createMetalUsdzAdapter(s.client, s.payer, { m: "0x00000000000000000000000000000000000ba5e1" });
    const bad = { consumed: false, intentId: "", mandateHash: "x" } as unknown as ConsumeReceipt;
    await expect(adapter.pay({ receipt: bad, merchant: { id: "m", name: "M" }, currency: "USD", amountBaseUnits: "100", checkoutId: "c" })).rejects.toBeInstanceOf(PaymentRefused);
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
