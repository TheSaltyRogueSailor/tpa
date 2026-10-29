import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { planCart } from "../shopper/agent.js";
import { CATALOG } from "../shopper/catalog.js";
import { createShopperRig, SHOPPER_PAYER_METAL_ADDRESS, type ShopperRig } from "../shopper/flow.js";
import { centsToUsdz, createMockAiriAdapter, PaymentRefused } from "../shopper/payments.js";
import { boundLedger, reviewCheckout } from "./support/dispatch.js";

const INTENT = { text: "Coffee brewing setup for the office: beans, filters, mugs", budgetCents: 12_000 };
let rig: ShopperRig;
beforeAll(async () => { rig = await createShopperRig({ metal: "mock" }); });
afterAll(async () => { await rig.close(); });

describe("TPA Shopper planner", () => {
  it("picks relevant in-stock items and never plans past the budget", () => {
    const plan = planCart(INTENT, CATALOG);
    expect(plan.lines.length).toBeGreaterThan(0);
    expect(plan.estimatedTotalCents).toBeLessThanOrEqual(INTENT.budgetCents);
    expect(plan.lines.map(l => l.sku)).not.toContain("KETTLE-GOOSE");
    expect(plan.lines.map(l => l.sku)).not.toContain("WARRANTY-PLUS");
  });
});

describe("TPA Shopper end to end", () => {
  it("happy path on Airwallex (mock Airi): TAP verified, mandate approved, exact match, paid, order number", async () => {
    rig.merchant.setAttack(null);
    const r = await rig.shop(INTENT);
    expect(r.outcome).toBe("PAID");
    expect(r.payment?.rail).toBe("airwallex-airi");
    expect(r.orderNumber).toMatch(/^HS-\d+$/);
    const audit = await rig.auditLog(r.intentId);
    expect(audit.map(a => a.action)).toEqual(expect.arrayContaining(["consumed"]));
  });

  it("happy path on Metal (mock USDZ, 18 decimals)", async () => {
    rig.merchant.setAttack(null);
    const before = await rig.metal.balanceOf(SHOPPER_PAYER_METAL_ADDRESS);
    const r = await rig.shop({ ...INTENT, rail: "metal" });
    expect(r.outcome).toBe("PAID");
    expect(r.payment?.reference).toMatch(/^0x[a-f0-9]{64}$/);
    expect(before - await rig.metal.balanceOf(SHOPPER_PAYER_METAL_ADDRESS)).toBe(centsToUsdz(r.quote!.totalBaseUnits));
  });

  it.each([
    ["price_swap", "terms_changed:items_mismatch"],
    ["inject_item", "terms_changed:items_mismatch"],
    ["swap_merchant", "terms_changed:merchant_mismatch"],
  ] as const)("merchant attack %s is blocked by TPA with %s and nothing is paid", async (attack, code) => {
    rig.merchant.setAttack(attack);
    const ordersBefore = rig.merchant.orders.size;
    const r = await rig.shop(INTENT);
    rig.merchant.setAttack(null);
    expect(r).toMatchObject({ outcome: "BLOCKED", blockedBy: "tpa", reason: code });
    expect(rig.merchant.orders.size).toBe(ordersBefore);
    const audit = await rig.auditLog(r.intentId);
    expect(audit.some(a => a.outcome === "refused" || a.reasonCode.includes("terms_changed"))).toBe(true);
  });

  it("unapproved spend: paying without the owner's passkey approval is blocked", async () => {
    const r = await rig.shop({ ...INTENT, ownerApproves: false });
    expect(r).toMatchObject({ outcome: "BLOCKED", blockedBy: "tpa", reason: "intent" });
  });

  it("TAP: a replayed agent-payer-auth request and an unsigned bot are rejected by the merchant", async () => {
    const r = await rig.replayCapturedCheckout();
    expect(r.firstStatus).toBe(200);
    expect(r.replay).toMatchObject({ status: 401, reason: "nonce_replayed" });
    expect(r.unsigned).toMatchObject({ status: 401, reason: "not_signed" });
  });

  it("payment rails refuse to move money without a TPA consume receipt", async () => {
    const rail = createMockAiriAdapter(boundLedger([]));
    await expect(rail.pay({ receipt: { consumed: false as never, intentId: "x", mandateHash: "0".repeat(64) }, checkoutId: "c", checkout: reviewCheckout() }))
      .rejects.toBeInstanceOf(PaymentRefused);
  });
});
