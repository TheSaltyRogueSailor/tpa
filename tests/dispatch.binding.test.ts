/**
 * v3.1 dispatch binding (Michael's test list): both reproductions refused before signing, every field drift,
 * missing binding, signature / snapshot tampering, concurrent and restart replay, late first execution, expiry during
 * preparation, post-expiry read-only recovery, fee cap, legacy rows, and one exact mock happy path with its audit.
 * Mock rails and in-memory / temp-file stores only: nothing leaves the process.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createShopperRig, DEMO_AIRI_FIXTURES } from "../shopper/flow.js";
import {
  LEGACY_BINDING_LABEL, PaymentRefused, createDispatchLedger, createFileDispatchStore, createMemoryDispatchStore, createMetalUsdzAdapter, createMockAiriAdapter,
  createMockMetalClient, type BoundIntent, type DispatchRecord, type MetalClient,
} from "../shopper/payments.js";
import { paymentTargetHash } from "../src/binding.js";
import { canonicalTpaMandate, TPA_CHECKOUT_LEDGER_DOMAIN, type TpaCheckoutInput } from "../src/domain.js";
import type { TpaDispatchStore } from "../src/dispatch.js";
import { ONE_DOLLAR_USDZ, PAYEE, PAYER, boundFixture, boundLedger, consumedLookup, reviewCheckout, sha256, type Fixture } from "./support/dispatch.js";

let dir: string;
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), "tpa-binding-")); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

/** $44.96 two-line checkout: price, qty, substitution, shipping and tax all have something to drift. */
const BASKET: TpaCheckoutInput = reviewCheckout({
  merchant: { id: "harbor-supply", name: "Harbor Supply Co." },
  items: [{ sku: "COF-BEANS-1KG", qty: 1, unitPriceBaseUnits: "2400" }, { sku: "FILTER-100", qty: 2, unitPriceBaseUnits: "600" }],
  shipping: { method: "standard", costBaseUnits: "599" }, taxBaseUnits: "297", totalBaseUnits: "4496",
});
const BASKET_USDZ = 4496n * 10n ** 16n;

/** A Metal mock rig whose transfer calls are counted (a call means something could have been signed). */
function metalRig(fixtures: Fixture[], options: { store?: TpaDispatchStore; now?: () => number; fee?: bigint } = {}) {
  const client = createMockMetalClient({ [PAYER]: 1_000n * ONE_DOLLAR_USDZ }, options.fee ?? 0n);
  const transfer = vi.spyOn(client, "transfer");
  const ledger = boundLedger(fixtures, options.store, options.now);
  return { client, transfer, ledger, adapter: createMetalUsdzAdapter(client, PAYER, ledger), payerBalance: () => client.balanceOf(PAYER), payeeBalance: () => client.balanceOf(PAYEE) };
}

describe("the two reproductions are refused before anything is signed", () => {
  it("same total, different checkout: items_mismatch", async () => {
    const fx = boundFixture({ intentId: "repro-1", quoteId: "chk_r1", checkout: BASKET });
    const r = metalRig([fx]);
    const sameTotal = reviewCheckout({ ...BASKET, items: [{ sku: "COF-BEANS-1KG", qty: 1, unitPriceBaseUnits: "1200" }, { sku: "FILTER-100", qty: 4, unitPriceBaseUnits: "600" }] });
    expect(sameTotal.totalBaseUnits).toBe(BASKET.totalBaseUnits);
    await expect(r.adapter.pay(fx.request({ checkout: sameTotal }))).rejects.toMatchObject({ reason: "items_mismatch" });
    expect(r.transfer).not.toHaveBeenCalled();
    expect(await r.payeeBalance()).toBe(0n);
  });
  it("changed recipient: recipient_mismatch", async () => {
    const fx = boundFixture({ intentId: "repro-2", quoteId: "chk_r2", checkout: BASKET });
    const r = metalRig([fx]);
    await expect(r.adapter.pay(fx.request({ checkout: { ...BASKET, recipient: "user:9999" } }))).rejects.toMatchObject({ reason: "recipient_mismatch" });
    expect(r.transfer).not.toHaveBeenCalled();
  });
});

describe("every field drift is refused before signing", () => {
  const fx = boundFixture({ intentId: "drift", quoteId: "chk_drift", checkout: BASKET });
  const items = BASKET.items;
  const cases: [string, Partial<TpaCheckoutInput> | { checkoutId: string }, string][] = [
    ["price + 1 cent", { items: [{ ...items[0]!, unitPriceBaseUnits: "2401" }, items[1]!], totalBaseUnits: "4497" }, "items_mismatch"],
    ["extra item", { items: [...items, { sku: "MUG-2", qty: 1, unitPriceBaseUnits: "0" }] }, "items_mismatch"],
    ["quantity", { items: [items[0]!, { ...items[1]!, qty: 3 }], totalBaseUnits: "5096" }, "items_mismatch"],
    ["substitution (same price)", { items: [items[0]!, { ...items[1]!, sku: "FILTER-200" }] }, "items_mismatch"],
    ["shipping method", { shipping: { method: "express", costBaseUnits: "599" } }, "shipping_mismatch"],
    ["shipping cost", { shipping: { method: "standard", costBaseUnits: "600" }, totalBaseUnits: "4497" }, "shipping_mismatch"],
    ["tax", { taxBaseUnits: "298", totalBaseUnits: "4497" }, "tax_mismatch"],
    ["merchant id", { merchant: { id: "harbor-supply-2", name: "Harbor Supply Co." } }, "merchant_mismatch"],
    ["merchant name", { merchant: { id: "harbor-supply", name: "Harbor Supply Inc." } }, "merchant_mismatch"],
    ["recipient", { recipient: "user:7002" }, "recipient_mismatch"],
    ["quote", { checkoutId: "chk_other" }, "quote_mismatch"],
  ];
  it.each(cases)("%s", async (_name, change, reason) => {
    const r = metalRig([fx]);
    const request = "checkoutId" in change ? fx.request(change) : fx.request({ checkout: { ...BASKET, ...change } });
    await expect(r.adapter.pay(request)).rejects.toMatchObject({ reason });
    expect(r.transfer).not.toHaveBeenCalled();
  });
  it("the exact signed checkout pays exactly once, the exact rail amount to the signed payee", async () => {
    const r = metalRig([fx]);
    const result = await r.adapter.pay(fx.request());
    expect(result.detail).toMatchObject({ to: PAYEE, amountBaseUnits: BASKET_USDZ.toString(), finalized: "true" });
    expect(await r.payeeBalance()).toBe(BASKET_USDZ);
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(r.transfer.mock.calls[0]![0]).toMatchObject({ to: PAYEE, amount: BASKET_USDZ, feeCap: 1_000_000n });
  });
});

describe("missing or tampered binding", () => {
  const fx = boundFixture({ intentId: "tamper", quoteId: "chk_t" });
  const ledgerWith = (lookup: (id: string) => Promise<BoundIntent | null>) => createDispatchLedger({ store: createMemoryDispatchStore(), lookupIntent: lookup });
  const execute = vi.fn(async () => { throw new Error("must not execute"); });

  it("a consumed v3.0 checkout mandate is refused (checkout_binding_missing); v2.0 is not bound", async () => {
    const v3 = { type: "TPA-mandate", version: "3.0", action: "checkout-authorization", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot",
      merchant: fx.mandate.merchant, items: fx.mandate.items, shipping: fx.mandate.shipping, subtotalBaseUnits: "100", taxBaseUnits: "0", amountBaseUnits: "100", recipient: "user:7001", feeBaseUnits: "0",
      nonce: "2".repeat(64), issuedAt: fx.mandate.issuedAt, expires: fx.mandate.expires, scope: "single_use", ledgerDomain: TPA_CHECKOUT_LEDGER_DOMAIN };
    const v3Hash = sha256(canonicalTpaMandate(v3));
    const l3 = ledgerWith(async () => ({ id: fx.intentId, mandateHash: v3Hash, state: "consumed", mandate: v3 }));
    await expect(l3.run("metal-usdz", fx.request({ receipt: { consumed: true, intentId: fx.intentId, mandateHash: v3Hash } }), execute)).rejects.toMatchObject({ reason: "checkout_binding_missing" });
    const v2 = { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "100", recipient: "user:7001",
      feeBaseUnits: "0", nonce: "1".repeat(64), issuedAt: fx.mandate.issuedAt, expires: fx.mandate.expires, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" };
    const v2Hash = sha256(canonicalTpaMandate(v2));
    const l2 = ledgerWith(async () => ({ id: fx.intentId, mandateHash: v2Hash, state: "consumed", mandate: v2 }));
    await expect(l2.run("metal-usdz", fx.request({ receipt: { consumed: true, intentId: fx.intentId, mandateHash: v2Hash } }), execute)).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(execute).not.toHaveBeenCalled();
  });
  it("a signature that fails verification (reader throws) or an unconsumed / revoked intent is not bound", async () => {
    await expect(ledgerWith(async () => { throw new Error("mandate_signature_invalid"); }).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    await expect(ledgerWith(async () => ({ ...fx.intent, state: "authorized" })).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    await expect(ledgerWith(async () => ({ ...fx.intent, revokedAtMs: 1 })).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    await expect(ledgerWith(async () => ({ ...fx.intent, mandateHash: "0".repeat(64) })).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(execute).not.toHaveBeenCalled();
  });
  it("a mandate whose target or hashes were edited does not verify (binding_invalid)", async () => {
    const editedTarget = { ...fx.mandate, paymentTarget: { ...fx.mandate.paymentTarget, payee: "evm:0x00000000000000000000000000000000000000ee" } };
    await expect(ledgerWith(async () => ({ ...fx.intent, mandate: editedTarget })).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "binding_invalid" });
    const consistent = { ...editedTarget, paymentTargetHash: paymentTargetHash(editedTarget.paymentTarget) };
    await expect(ledgerWith(async () => ({ ...fx.intent, mandate: consistent })).run("metal-usdz", fx.request(), execute)).rejects.toMatchObject({ reason: "binding_invalid" });
    expect(execute).not.toHaveBeenCalled();
  });
  it("a stored v3.1 row whose snapshot or columns were edited is refused, never reconciled or paid", async () => {
    const r = metalRig([fx]);
    const inner = createMemoryDispatchStore();
    let edit: ((row: DispatchRecord) => DispatchRecord) | null = null;
    const store: TpaDispatchStore = { ...inner, get: async id => { const row = await inner.get(id); return row && edit ? edit(row) : row; } };
    const crashing: MetalClient = { ...r.client, transfer: async input => { await r.client.transfer(input); throw new Error("crash after broadcast"); } };
    const ledger = boundLedger([fx], store);
    await expect(createMetalUsdzAdapter(crashing, PAYER, ledger).pay(fx.request())).rejects.toThrow("crash after broadcast");
    expect((await inner.get(fx.intentId))?.status).toBe("sent");
    const adapter = createMetalUsdzAdapter(r.client, PAYER, ledger);
    expect(r.transfer).toHaveBeenCalledTimes(1); // the one broadcast before the crash
    edit = row => ({ ...row, payee: "0x00000000000000000000000000000000000000ee" });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "binding_invalid" });
    edit = row => ({ ...row, railAmount: "1" });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "binding_invalid" });
    edit = row => ({ ...row, snapshot: { ...row.snapshot!, target: { ...row.snapshot!.target, payee: "evm:0x00000000000000000000000000000000000000ee" } } });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "binding_invalid" });
    edit = row => { const { snapshot: _s, ...rest } = row; return rest; };
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "binding_invalid" });
    edit = row => { const t = { ...row.snapshot!.target, payee: "evm:0x00000000000000000000000000000000000000ee" }; const h = paymentTargetHash(t);
      return { ...row, payee: "0x00000000000000000000000000000000000000ee", paymentTargetHash: h, snapshot: { ...row.snapshot!, target: t, paymentTargetHash: h } }; };
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "dispatch_conflict" });
    expect(r.transfer).toHaveBeenCalledTimes(1);
    edit = null;
    expect(await adapter.pay(fx.request())).toMatchObject({ reference: (await inner.get(fx.intentId))!.txHash });
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(await r.payeeBalance()).toBe(ONE_DOLLAR_USDZ);
  });
});

describe("replay", () => {
  it("concurrent pay() calls for one intent sign once", async () => {
    const fx = boundFixture({ intentId: "conc", quoteId: "chk_c" });
    const r = metalRig([fx]);
    const [a, b, c] = await Promise.all([r.adapter.pay(fx.request()), r.adapter.pay(fx.request()), r.adapter.pay(fx.request())]);
    expect(new Set([a.reference, b.reference, c.reference]).size).toBe(1);
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(await r.payeeBalance()).toBe(ONE_DOLLAR_USDZ);
  });
  it("concurrent pay() calls through two processes sharing a journal: one reservation wins", async () => {
    const fx = boundFixture({ intentId: "conc2", quoteId: "chk_c2" });
    const path = join(dir, "conc2.json");
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const transfer = vi.spyOn(client, "transfer");
    const one = createMetalUsdzAdapter(client, PAYER, boundLedger([fx], createFileDispatchStore(path)));
    const two = createMetalUsdzAdapter(client, PAYER, boundLedger([fx], createFileDispatchStore(path)));
    const settled = await Promise.allSettled([one.pay(fx.request()), two.pay(fx.request())]);
    expect(transfer).toHaveBeenCalledTimes(1);
    for (const s of settled) if (s.status === "rejected") expect(s.reason).toMatchObject({ reason: expect.stringMatching(/^dispatch_(in_progress|pending_reconcile)$/) });
    expect(await one.pay(fx.request())).toMatchObject({ reference: (settled.find(s => s.status === "fulfilled") as PromiseFulfilledResult<{ reference: string }> | undefined)?.value.reference ?? expect.any(String) });
    expect(transfer).toHaveBeenCalledTimes(1);
  });
  it("after a restart: a settled intent returns the stored result; a sent one reconciles; nothing is resent", async () => {
    const fx = boundFixture({ intentId: "restart", quoteId: "chk_rs" });
    const path = join(dir, "restart.json");
    const r = metalRig([fx], { store: createFileDispatchStore(path) });
    const crashing: MetalClient = { ...r.client, transfer: async input => { await r.client.transfer(input); throw new Error("process died"); } };
    await expect(createMetalUsdzAdapter(crashing, PAYER, r.ledger).pay(fx.request())).rejects.toThrow("process died");
    expect(r.transfer).toHaveBeenCalledTimes(1);
    const restarted = createMetalUsdzAdapter(r.client, PAYER, boundLedger([fx], createFileDispatchStore(path)));
    const first = await restarted.pay(fx.request());
    const again = await createMetalUsdzAdapter(r.client, PAYER, boundLedger([fx], createFileDispatchStore(path))).pay(fx.request());
    expect(again.reference).toBe(first.reference);
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(await r.payeeBalance()).toBe(ONE_DOLLAR_USDZ);
  });
  it("after a restart on the mock Airi rail an unknown provider outcome stays pending, never paid twice", async () => {
    const fx = boundFixture({ intentId: "airi-rs", quoteId: "chk_ars", rail: "airwallex-airi" });
    const store = createMemoryDispatchStore();
    const first = createMockAiriAdapter(boundLedger([fx], store));
    const paid = await first.pay(fx.request());
    expect(paid.detail).toMatchObject({ to: "awx-mock-fixture:review-fixture", amountBaseUnits: "100", fee: "0" });
    expect(await first.pay(fx.request())).toEqual(paid);
    // A fresh adapter on the same store returns the settled row without a new provider call.
    const second = createMockAiriAdapter(boundLedger([fx], store));
    expect(await second.pay(fx.request())).toEqual(paid);
    expect(second.attempts.size).toBe(0);
  });
});

describe("freshness", () => {
  it("late first execution after approval expiry is refused and reserves nothing", async () => {
    const issuedAt = Math.floor(Date.now() / 1000) - 400;
    const fx = boundFixture({ intentId: "late", quoteId: "chk_late", issuedAt, quoteTtlSeconds: 900, conversionTtlSeconds: 900 });
    const store = createMemoryDispatchStore();
    const r = metalRig([fx], { store });
    await expect(r.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(await store.get(fx.intentId)).toBeNull();
    expect(r.transfer).not.toHaveBeenCalled();
  });
  it("mandate lifetime is capped by the quote and the conversion lock (zero tolerance)", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const fx = boundFixture({ intentId: "cap", quoteId: "chk_cap", issuedAt, quoteTtlSeconds: 30, conversionTtlSeconds: 20 });
    expect(fx.mandate.expires).toBe(issuedAt + 20);
    const r = metalRig([fx], { now: () => (issuedAt + 20) * 1000 });
    await expect(r.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(r.transfer).not.toHaveBeenCalled();
  });
  it("expiry while waiting for the reservation lock refuses and releases", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const fx = boundFixture({ intentId: "lockwait", quoteId: "chk_lw", issuedAt });
    let clock = issuedAt * 1000;
    const inner = createMemoryDispatchStore();
    const store: TpaDispatchStore = { ...inner, reserve: async record => { clock = fx.mandate.expires * 1000; return inner.reserve(record); } };
    const r = metalRig([fx], { store, now: () => clock });
    await expect(r.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(await inner.get(fx.intentId)).toBeNull();
    expect(r.transfer).not.toHaveBeenCalled();
  });
  it("expiry during async preparation refuses at the signing boundary (never signed), and releases", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const fx = boundFixture({ intentId: "prep", quoteId: "chk_prep", issuedAt });
    let clock = issuedAt * 1000;
    const store = createMemoryDispatchStore();
    const r = metalRig([fx], { store, now: () => clock });
    const slow: MetalClient = { ...r.client, transfer: input => { clock = fx.mandate.quote.expires * 1000; return r.client.transfer(input); } };
    await expect(createMetalUsdzAdapter(slow, PAYER, r.ledger).pay(fx.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(await store.get(fx.intentId)).toBeNull();
    expect(await r.payeeBalance()).toBe(0n);
    expect(r.client.signatures).toHaveLength(0);
  });
  it("revocation during preparation refuses before signing", async () => {
    const fx = boundFixture({ intentId: "revoke", quoteId: "chk_rv" });
    let revoked = false;
    const store = createMemoryDispatchStore();
    const ledger = createDispatchLedger({ store, lookupIntent: async id => { const i = await consumedLookup(fx)(id); return i && revoked ? { ...i, revokedAtMs: 1 } : i; } });
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const slow: MetalClient = { ...client, transfer: input => { revoked = true; return client.transfer(input); } };
    await expect(createMetalUsdzAdapter(slow, PAYER, ledger).pay(fx.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(await store.get(fx.intentId)).toBeNull();
    expect(await client.balanceOf(PAYEE)).toBe(0n);
    expect(client.signatures).toHaveLength(0);
  });
  it("after expiry an already-sent payment may still be recovered read-only; nothing is signed or resent", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const fx = boundFixture({ intentId: "postexp", quoteId: "chk_pe", issuedAt });
    let clock = issuedAt * 1000;
    const store = createMemoryDispatchStore();
    const r = metalRig([fx], { store, now: () => clock });
    const crashing: MetalClient = { ...r.client, transfer: async input => { await r.client.transfer(input); throw new Error("lost receipt"); } };
    await expect(createMetalUsdzAdapter(crashing, PAYER, r.ledger).pay(fx.request())).rejects.toThrow("lost receipt");
    clock = (fx.mandate.expires + 3600) * 1000;
    const noReconcile: MetalClient = { ...r.client, reconcile: async () => null };
    await expect(createMetalUsdzAdapter(noReconcile, PAYER, r.ledger).pay(fx.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    const recovered = await createMetalUsdzAdapter(r.client, PAYER, r.ledger).pay(fx.request());
    expect(recovered.reference).toBe((await store.get(fx.intentId))!.txHash);
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(await r.payeeBalance()).toBe(ONE_DOLLAR_USDZ);
  });
});

describe("fees", () => {
  it("a network fee above the signed cap is refused before signing and releases the reservation", async () => {
    const fx = boundFixture({ intentId: "fee", quoteId: "chk_fee" });
    const store = createMemoryDispatchStore();
    const r = metalRig([fx], { store, fee: 1_000_001n });
    await expect(r.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "metal_fee_cap" });
    expect(await store.get(fx.intentId)).toBeNull();
    expect(await r.payeeBalance()).toBe(0n);
  });
  it("the Airi mock target carries a zero fee cap; a nonzero cap cannot even be signed", () => {
    expect(() => boundFixture({ intentId: "fee2", rail: "airwallex-airi", target: t => ({ ...t, fee: { ...t.fee, capBaseUnits: "1" } }) })).toThrow();
  });
});

describe("legacy pre-binding rows (memory and file stores)", () => {
  /** The pre-0003 column set: no checkoutFingerprint, paymentTargetHash or snapshot. */
  const legacyRow = (intentId: string): DispatchRecord => ({
    intentId, mandateHash: "a".repeat(64), checkoutId: "chk_legacy", rail: "metal-usdz", merchantId: "review-merchant", currency: "USD",
    amountBaseUnits: "100", payee: PAYEE, railAmount: ONE_DOLLAR_USDZ.toString(), status: "reserved", createdAtMs: 1, updatedAtMs: 1,
  });
  for (const kind of ["memory", "file"] as const) {
    it(`${kind}: never executed by run(); a sent row recovers read-only, labelled ${LEGACY_BINDING_LABEL}; a reserved row cannot execute`, async () => {
      const store = kind === "memory" ? createMemoryDispatchStore() : createFileDispatchStore(join(dir, "legacy.json"));
      const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
      const { txHash } = await client.transfer({ from: PAYER, to: PAYEE, amount: ONE_DOLLAR_USDZ, memo: "legacy", feeCap: 0n });
      await store.reserve(legacyRow("legacy-1"));
      expect(await store.markSent("legacy-1", txHash, 2)).toBe(true);
      await store.reserve(legacyRow("legacy-2"));
      const fx = boundFixture({ intentId: "legacy-1", quoteId: "chk_legacy" });
      const ledger = boundLedger([fx], store);
      const adapter = createMetalUsdzAdapter(client, PAYER, ledger);
      const transfer = vi.spyOn(client, "transfer");
      await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "legacy_dispatch_row" });
      await expect(adapter.recoverLegacy("legacy-2")).rejects.toMatchObject({ reason: "legacy_reservation_not_executable" });
      await expect(adapter.recoverLegacy("legacy-404")).rejects.toMatchObject({ reason: "dispatch_unknown" });
      await expect(ledger.recoverLegacy("airwallex-airi", "legacy-1")).rejects.toMatchObject({ reason: "rail_mismatch" });
      const recovered = await adapter.recoverLegacy("legacy-1");
      expect(recovered).toMatchObject({ reference: txHash, detail: { binding: LEGACY_BINDING_LABEL } });
      expect(await adapter.recoverLegacy("legacy-1")).toMatchObject({ reference: txHash });
      const row = await store.get("legacy-1");
      expect(row).toMatchObject({ status: "succeeded" });
      expect(row).not.toHaveProperty("snapshot");
      expect(row).not.toHaveProperty("checkoutFingerprint");
      expect(transfer).not.toHaveBeenCalled();
      expect(await client.balanceOf(PAYEE)).toBe(ONE_DOLLAR_USDZ);
      // A v3.1 row is never handled by the legacy path.
      const bound = boundFixture({ intentId: "bound-1", quoteId: "chk_b1" });
      const b = createMetalUsdzAdapter(client, PAYER, boundLedger([bound], store));
      await b.pay(bound.request());
      await expect(b.recoverLegacy("bound-1")).rejects.toMatchObject({ reason: "not_legacy" });
    });
  }
});

describe("one exact mock happy path with an auditable outcome", () => {
  it("Airi mock: TAP, v3.1 mandate, passkey, consume, one dispatch bound to both hashes, order, audit trail", async () => {
    const store = createMemoryDispatchStore();
    const rig = await createShopperRig({ metal: "mock", dispatchStore: store });
    try {
      const r = await rig.shop({ text: "Coffee brewing setup for the office: beans, filters, mugs", budgetCents: 12_000 });
      expect(r.outcome).toBe("PAID");
      const intent = await rig.service.readSignedIntent(rig.ctx, { intentId: r.intentId! });
      const m = intent!.mandate as Fixture["mandate"];
      expect(m.version).toBe("3.1");
      expect(m.quote.quoteId).toBe(r.quote!.checkoutId);
      expect(m.paymentTarget).toMatchObject({ rail: "airwallex-airi", payee: `awx-mock-fixture:${DEMO_AIRI_FIXTURES["harbor-supply"]}`, railAmount: r.quote!.totalBaseUnits, fee: { capBaseUnits: "0" } });
      const row = (await store.get(r.intentId!))!;
      expect(row).toMatchObject({ status: "succeeded", mandateHash: r.mandateHash, checkoutId: r.quote!.checkoutId, checkoutFingerprint: m.checkoutFingerprint, paymentTargetHash: m.paymentTargetHash,
        payee: m.paymentTarget.payee, railAmount: m.paymentTarget.railAmount, amountBaseUnits: r.quote!.totalBaseUnits });
      expect(row.txHash).toBe(r.payment!.reference);
      expect(r.payment!.detail).toMatchObject({ to: m.paymentTarget.payee, amountBaseUnits: r.quote!.totalBaseUnits, fee: "0" });
      const audit = (await rig.auditLog(r.intentId)).map(a => `${a.action}:${a.outcome}`).reverse();
      expect(audit).toEqual(expect.arrayContaining(["intent_created:approved", "authorized:approved", "consumed:approved"]));
      expect(audit.indexOf("intent_created:approved")).toBeLessThan(audit.indexOf("authorized:approved"));
      expect(audit.indexOf("authorized:approved")).toBeLessThan(audit.indexOf("consumed:approved"));
      expect((await rig.auditLog(r.intentId)).every(a => a.mandateHash === null || a.mandateHash === r.mandateHash)).toBe(true);
      // One-time: replaying the same payment returns the same settled result; nothing new is dispatched.
      const again = await rig.rails.airwallex.pay({ receipt: { consumed: true, intentId: r.intentId!, mandateHash: r.mandateHash! }, checkoutId: r.quote!.checkoutId, checkout: (({ checkoutId: _c, ...c }) => c)(r.quote!) as TpaCheckoutInput });
      expect(again.reference).toBe(r.payment!.reference);
    } finally { await rig.close(); }
  });
});
