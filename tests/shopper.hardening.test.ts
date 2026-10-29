/**
 * Regression tests for the Manus review findings 1-3: dispatch bound to the consumed
 * mandate and checkout, one durable reservation per intent with reconcile-before-retry,
 * and merchant completion only against a settled dispatch.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createShopperRig, SHOPPER_PAYER_METAL_ADDRESS, type ShopperRig } from "../shopper/flow.js";
import { createFileDispatchStore, PaymentRefused, type PaymentRequest, type PaymentResult } from "../shopper/payments.js";
import type { Quote } from "../shopper/merchant.js";
import { boundLedger } from "./support/dispatch.js";

const INTENT = { text: "Coffee brewing setup for the office: beans, filters, mugs", budgetCents: 12_000 };
let rig: ShopperRig;
let dir: string;
beforeAll(async () => { rig = await createShopperRig({ metal: "mock" }); dir = mkdtempSync(join(tmpdir(), "tpa-dispatch-")); });
afterAll(async () => { await rig.close(); rmSync(dir, { recursive: true, force: true }); });

const req = (over: Partial<PaymentRequest> = {}): PaymentRequest => ({ receipt: { consumed: true, intentId: "i1", mandateHash: "a".repeat(64) }, merchant: { id: "m", name: "M" }, currency: "USD", amountBaseUnits: "100", checkoutId: "chk_1", ...over });
const T = { payee: "0xpayee", railAmount: "100" };
const ledger0 = (store?: Parameters<typeof boundLedger>[1]) => boundLedger([req()], store);
const ok = (reference: string): PaymentResult => ({ rail: "r", mode: "mock", status: "succeeded", reference, detail: {} });

describe("finding 1: a caller-built receipt is not enough to move money", () => {
  it("refuses a well-formed receipt for an intent the TPA store never consumed", async () => {
    await expect(rig.rails.metal.pay(req({ merchant: { id: "harbor-supply", name: "Harbor Supply Co." } }))).rejects.toMatchObject({ reason: "dispatch_not_bound" });
  });

  it("refuses to re-pay a consumed intent for a different amount, checkout or rail, and replays the same payment idempotently", async () => {
    rig.merchant.setAttack(null);
    const r = await rig.shop({ ...INTENT, rail: "metal" });
    expect(r.outcome).toBe("PAID");
    const base: PaymentRequest = { receipt: { consumed: true, intentId: r.intentId!, mandateHash: r.mandateHash! }, merchant: r.quote!.merchant, currency: "USD", amountBaseUnits: r.quote!.totalBaseUnits, checkoutId: r.quote!.checkoutId };
    const before = await rig.metal.balanceOf(SHOPPER_PAYER_METAL_ADDRESS);
    await expect(rig.rails.metal.pay({ ...base, amountBaseUnits: String(Number(base.amountBaseUnits) + 1) })).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    await expect(rig.rails.metal.pay({ ...base, checkoutId: "chk_other" })).rejects.toMatchObject({ reason: "dispatch_conflict" });
    await expect(rig.rails.airwallex.pay(base)).rejects.toMatchObject({ reason: "dispatch_conflict" });
    expect((await rig.rails.metal.pay(base)).reference).toBe(r.payment!.reference);
    expect(await rig.metal.balanceOf(SHOPPER_PAYER_METAL_ADDRESS)).toBe(before);
  });
});

describe("finding 2: one dispatch per intent, durable, never re-signed blindly", () => {
  it("concurrent pay() calls for one intent run the transfer once", async () => {
    const ledger = ledger0();
    const execute = vi.fn(async () => { await new Promise(r => setTimeout(r, 10)); return ok("0xabc"); });
    const [a, b] = await Promise.all([ledger.run("r", req(), T, execute), ledger.run("r", req(), T, execute)]);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
  });

  it("a signed-but-unknown transfer survives a restart and is reconciled, not resent", async () => {
    const journalPath = join(dir, "journal.json");
    const first = ledger0(createFileDispatchStore(journalPath));
    await expect(first.run("r", req(), T, async ({ onSigned }) => { await onSigned("0xdead"); throw new PaymentRefused("metal_receipt_pending", "pending"); })).rejects.toMatchObject({ reason: "metal_receipt_pending" });
    const restarted = ledger0(createFileDispatchStore(journalPath));
    const execute = vi.fn(async () => ok("0xnew"));
    await expect(restarted.run("r", req(), T, execute)).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    await expect(restarted.run("r", req(), T, execute, async () => null)).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(await restarted.run("r", req(), T, execute, async rec => ok(rec.txHash!))).toMatchObject({ reference: "0xdead" });
    expect(execute).not.toHaveBeenCalled();
  });

  it("a different payee or rail amount for the same intent is a conflict, never a second payment", async () => {
    const ledger = ledger0();
    await ledger.run("r", req(), T, async () => ok("0x2"));
    await expect(ledger.run("r", req(), { ...T, payee: "0xother" }, async () => ok("0x3"))).rejects.toMatchObject({ reason: "dispatch_conflict" });
    await expect(ledger.run("r", req(), { ...T, railAmount: "101" }, async () => ok("0x3"))).rejects.toMatchObject({ reason: "dispatch_conflict" });
  });

  it("a failure before signing releases the reservation so a retry may pay", async () => {
    const ledger = ledger0();
    await expect(ledger.run("r", req(), T, async () => { throw new PaymentRefused("insufficient_usdz", "no funds"); })).rejects.toBeInstanceOf(PaymentRefused);
    expect(await ledger.run("r", req(), T, async () => ok("0x1"))).toMatchObject({ reference: "0x1" });
  });
});

describe("finding 3: the merchant completes orders only against a settled payment", () => {
  async function signed(method: "POST", path: string, tag: "agent-browser-auth" | "agent-payer-auth", body: Record<string, unknown>, container?: Record<string, unknown>) {
    const s = rig.agentTap.signRequest({ authority: rig.merchant.authority, path, tag, nowSeconds: Math.floor(Date.now() / 1000) });
    const payload = container ? { ...body, agenticPaymentContainer: rig.agentTap.signContainer(s.nonce, container) } : body;
    const res = await fetch(`${rig.merchant.baseUrl}${path}`, { method, headers: { ...s.headers, "content-type": "application/json" }, body: JSON.stringify(payload) });
    return { status: res.status, json: await res.json() as Record<string, unknown> };
  }

  it("a validly TAP-signed completion with an invented payment reference gets no order", async () => {
    const quote = (await signed("POST", "/checkout/quote", "agent-browser-auth", { lines: [{ sku: "FILTER-100", qty: 1 }] })).json as unknown as Quote;
    const before = rig.merchant.orders.size;
    const done = await signed("POST", `/checkout/${quote.checkoutId}/complete`, "agent-payer-auth", {}, { checkoutId: quote.checkoutId, paymentReference: "0xforged", rail: "metal-usdz" });
    expect(done.status).toBe(402);
    expect(done.json.reason).toBe("payment_unverified");
    expect(rig.merchant.orders.size).toBe(before);
  });

  it("a real payment reference cannot complete a different checkout", async () => {
    rig.merchant.setAttack(null);
    const paid = await rig.shop(INTENT);
    const other = (await signed("POST", "/checkout/quote", "agent-browser-auth", { lines: [{ sku: "FILTER-100", qty: 1 }] })).json as unknown as Quote;
    const done = await signed("POST", `/checkout/${other.checkoutId}/complete`, "agent-payer-auth", {}, { checkoutId: other.checkoutId, paymentReference: paid.payment!.reference, rail: paid.payment!.rail });
    expect(done.status).toBe(402);
  });
});
