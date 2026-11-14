import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createTpaShieldServer } from "../mcp/server.js";
import { checkPayment } from "../mcp/checks.js";

const approved = {
  currency: "USD",
  recipient: "user:42",
  merchant: { id: "acme-store", name: "Acme Store" },
  items: [
    { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" },
    { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" },
  ],
  shipping: { method: "standard", costBaseUnits: "500" },
  taxBaseUnits: "280",
  totalBaseUnits: "3780",
};
/** Synthetic checksummed Dogecoin address (version 0x1e, hash160 of twenty 0x11 bytes). Not a real wallet. */
const DOGE_ADDRESS = "D6hLULEGDRbk86j58t5iWmeinqM6acA16V";
const DOGE_BAD_CHECKSUM = "D6hLULEGDRbk86j58t5iWmeinqM6acA162";

let client: Client;

async function call(name: string, args: Record<string, unknown> = {}) {
  const response = await client.callTool({ name, arguments: args });
  const content = response.content as Array<{ type: string; text: string }>;
  return { isError: response.isError === true, body: JSON.parse(content[0]!.text) as Record<string, any> };
}

beforeAll(async () => {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createTpaShieldServer().connect(serverSide);
  client = new Client({ name: "tpa-shield-test", version: "0.0.0" });
  await client.connect(clientSide);
});
afterAll(async () => { await client.close(); });

describe("TPA Shield MCP server", () => {
  it("lists exactly the read-only tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map(tool => tool.name).sort()).toEqual(["check_checkout", "check_payment", "check_token", "check_transfer", "explain_decision", "get_policy"]);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.destructiveHint).toBe(false);
    }
    for (const tool of tools.filter(entry => entry.name !== "check_token")) {
      expect(tool.annotations?.openWorldHint).toBe(false);
    }
  });

  it("check_checkout passes a consistent checkout and returns it normalized", async () => {
    const { body } = await call("check_checkout", { checkout: { ...approved, items: [...approved.items].reverse() } });
    expect(body.decision).toBe("pass");
    expect(body.reasons).toEqual([]);
    expect(body.normalized.items.map((item: { sku: string }) => item.sku)).toEqual(["MUG-01", "TEE-02"]);
    expect(body.normalized.subtotalBaseUnits).toBe("3000");
  });

  it("check_checkout blocks a wrong total, a duplicate SKU, a bad recipient and unknown fields", async () => {
    expect((await call("check_checkout", { checkout: { ...approved, totalBaseUnits: "9999" } })).body.reasons[0].code).toBe("checkout_total_inconsistent");
    expect((await call("check_checkout", { checkout: { ...approved, items: [approved.items[0], approved.items[0]], totalBaseUnits: "3780" } })).body.reasons[0].code).toBe("checkout_duplicate_sku");
    expect((await call("check_checkout", { checkout: { ...approved, recipient: "0xdeadbeef" } })).body.reasons[0].code).toBe("recipient_invalid");
    expect((await call("check_checkout", { checkout: { ...approved, privateKey: "x" } })).body.reasons[0].code).toBe("checkout_invalid");
  });

  it("check_payment passes an unchanged checkout", async () => {
    const { body } = await call("check_payment", { approved, presented: structuredClone(approved) });
    expect(body.decision).toBe("pass");
    expect(body.note).toMatch(/not an approval/);
  });

  it("check_payment blocks the same attacks the TPA service blocks", async () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ ...approved, merchant: { id: "evil-store", name: "Evil Store" } }, "terms_changed:merchant_mismatch"],
      [{ ...approved, items: [approved.items[0], { ...approved.items[1], unitPriceBaseUnits: "1750" }], totalBaseUnits: "4030" }, "terms_changed:items_mismatch"],
      [{ ...approved, recipient: "user:666" }, "terms_changed:recipient_mismatch"],
      [{ ...approved, shipping: { method: "express", costBaseUnits: "500" } }, "terms_changed:shipping_mismatch"],
      [{ ...approved, taxBaseUnits: "300", totalBaseUnits: "3800" }, "terms_changed:tax_mismatch"],
      [{ ...approved, totalBaseUnits: "3781" }, "terms_changed:checkout_total_inconsistent"],
    ];
    for (const [presented, code] of cases) {
      const { body } = await call("check_payment", { approved, presented });
      expect(body.decision, code).toBe("block");
      expect(body.reasons[0].code).toBe(code);
      expect(body.reasons[0].text.length).toBeGreaterThan(5);
    }
  });

  it("check_payment refuses when the approved terms are themselves invalid", async () => {
    const { body } = await call("check_payment", { approved: { ...approved, totalBaseUnits: "1" }, presented: { ...approved, totalBaseUnits: "1" } });
    expect(body.decision).toBe("block");
    expect(body.reasons[0].code).toBe("approved_invalid");
  });

  it("check_transfer validates USD and DOGE transfers and blocks changed terms", async () => {
    expect((await call("check_transfer", { transfer: { currency: "USD", recipient: "user:7", amount: "12.49" } })).body).toMatchObject({ decision: "pass", normalized: { amountBaseUnits: "1249" } });
    expect((await call("check_transfer", { transfer: { currency: "DOGE", recipient: DOGE_ADDRESS, amountBaseUnits: "100000000" } })).body.decision).toBe("pass");
    expect((await call("check_transfer", { transfer: { currency: "DOGE", recipient: DOGE_BAD_CHECKSUM, amountBaseUnits: "1" } })).body.reasons[0].code).toBe("recipient_invalid");
    expect((await call("check_transfer", { transfer: { currency: "USD", recipient: "user:7", amount: "1.234" } })).body.reasons[0].code).toBe("amount_invalid");
    expect((await call("check_transfer", { transfer: { currency: "USD", recipient: "user:7", amountBaseUnits: "0" } })).body.reasons[0].code).toBe("transfer_invalid");
    const changed = await call("check_transfer", {
      transfer: { currency: "USD", recipient: "user:7", amountBaseUnits: "5000" },
      approved: { currency: "USD", recipient: "user:7", amountBaseUnits: "1249" },
    });
    expect(changed.body.reasons[0].code).toBe("terms_changed:legacy_mismatch");
  });

  it("get_policy states the read-only boundary and what it does not check", async () => {
    const { body } = await call("get_policy");
    expect(body.readOnly).toBe(true);
    expect(body.mode.paymentExecution).toBe(false);
    expect(body.notIncluded.join(" ")).toMatch(/Pyth/);
    expect(body.tokenGate.blocks.join(" ")).toMatch(/honeypot/);
    expect(body.enforcedOnlyByTheFullTpaService.join(" ")).toMatch(/passkey/);
  });

  it("explain_decision explains known and unknown codes", async () => {
    expect((await call("explain_decision", { code: "terms_changed:merchant_mismatch" })).body).toMatchObject({ text: "Merchant changed after approval", category: "terms changed after approval", known: true });
    expect((await call("explain_decision", { code: "intent" })).body.category).toBe("single use / replay");
    expect((await call("explain_decision", { code: "made_up_code" })).body).toMatchObject({ known: false, category: "unknown" });
  });

  it("rejects malformed tool arguments without throwing", async () => {
    const response = await client.callTool({ name: "check_transfer", arguments: { transfer: { currency: "BTC", recipient: "x" } } });
    expect(response.isError).toBe(true);
  });

  it("never echoes key-like fields back", () => {
    const decision = checkPayment(approved, { ...approved, privateKey: "secret" });
    expect(JSON.stringify(decision)).not.toContain("secret");
    expect(decision.decision).toBe("block");
  });
});
