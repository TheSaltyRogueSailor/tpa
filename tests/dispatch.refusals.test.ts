/**
 * Refusal tests for the four payment-dispatch gaps found in review of 55ca605 (plus result checks). Mock only:
 * local balances, temp-dir journals, spies instead of fetch. Each test here fails on 55ca605.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { createShopperRig } from "../shopper/flow.js";
import {
  createAirwallexSandboxAdapter, createDispatchLedger, createFileDispatchStore, createMemoryDispatchStore, createMetalUsdzAdapter, createMockMetalClient,
  type DispatchLedger, type MetalClient, type PaymentRequest, type PaymentResult,
} from "../shopper/payments.js";
import { boundLedger, consumedLookup } from "./support/dispatch.js";

const payer = "0x0000000000000000000000000000000000000001";
const payee = "0x0000000000000000000000000000000000000002";
const ONE_DOLLAR_USDZ = 10n ** 18n;
const request = (over: Partial<PaymentRequest> = {}): PaymentRequest => ({ receipt: { consumed: true, intentId: "review-intent", mandateHash: "a".repeat(64) }, merchant: { id: "review-merchant", name: "Review merchant" }, currency: "USD", amountBaseUnits: "100", checkoutId: "review-checkout", ...over });
const okay = (reference: string, rail = "metal-usdz"): PaymentResult => ({ rail, mode: "mock", status: "succeeded", reference, detail: {} });
const target = { payee, railAmount: ONE_DOLLAR_USDZ.toString() };
const dirs: string[] = [];
const tempJournal = () => { const d = mkdtempSync(join(tmpdir(), "tpa-refusal-")); dirs.push(d); return join(d, "dispatch.json"); };
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

describe("gap 1: every adapter needs a permission-bound ledger; live adapters need a durable one", () => {
  it("a Metal adapter without a ledger refuses a fabricated receipt and moves nothing", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const rail = (createMetalUsdzAdapter as (...a: unknown[]) => ReturnType<typeof createMetalUsdzAdapter>)(client, payer, { "review-merchant": payee });
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_unbound" });
    expect(await client.balanceOf(payee)).toBe(0n);
  });

  it("a ledger cannot be built without the intent reader", () => {
    expect(() => createDispatchLedger({ store: createMemoryDispatchStore() } as never)).toThrow(expect.objectContaining({ reason: "ledger_unbound" }));
  });

  it("a hand-made ledger object that skips the binding is refused", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const fake: DispatchLedger = { durable: true, run: (_rail, _req, _t, execute) => execute({ onSigned: async () => undefined } as never), settled: async () => null };
    const rail = createMetalUsdzAdapter(client, payer, { "review-merchant": payee }, fake);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_unbound" });
    expect(await client.balanceOf(payee)).toBe(0n);
  });

  it("a testnet Metal client refuses a ledger on process memory before signing", async () => {
    const transfer = vi.fn(async () => ({ txHash: "0x1", finalized: true }));
    const live: MetalClient = { chainId: 63825, mode: "testnet", balanceOf: async () => 0n, transfer };
    const rail = createMetalUsdzAdapter(live, payer, { "review-merchant": payee }, boundLedger([request()]));
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_not_durable" });
    expect(transfer).not.toHaveBeenCalled();
  });

  it("the Airwallex sandbox adapter verifies the consumed intent before any network call", async () => {
    const fetchSpy = vi.fn(async () => { throw new Error("network must not be reached"); });
    const env = { AWX_CLIENT_ID: "test-id", AWX_API_KEY: "test-key", AWX_TEST_CARD_NUMBER: "4000000000000000" };
    const rail = (createAirwallexSandboxAdapter as (...a: unknown[]) => ReturnType<typeof createAirwallexSandboxAdapter>)(boundLedger([], createFileDispatchStore(tempJournal())), env, fetchSpy);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("gap 2: the file journal is exclusive across store instances and processes", () => {
  it("two stores opened before the first payment execute one intent once", async () => {
    const path = tempJournal();
    const first = boundLedger([request()], createFileDispatchStore(path));
    const second = boundLedger([request()], createFileDispatchStore(path));
    let executions = 0;
    const execute = async () => okay(`mock-result-${++executions}`);
    await first.run("metal-usdz", request(), target, execute);
    const again = await second.run("metal-usdz", request(), target, execute);
    expect(executions).toBe(1);
    expect(again.reference).toBe("mock-result-1");
  });

  it("concurrent reservations through two store instances: exactly one wins", async () => {
    const path = tempJournal();
    const stores = Array.from({ length: 6 }, () => createFileDispatchStore(path));
    const rec = { intentId: "race", mandateHash: "a".repeat(64), checkoutId: "c", rail: "metal-usdz", merchantId: "m", currency: "USD", amountBaseUnits: "100", payee, railAmount: "1", status: "reserved" as const, createdAtMs: 1, updatedAtMs: 1 };
    const results = await Promise.all(stores.map(s => s.reserve(rec)));
    expect(results.filter(r => r.created)).toHaveLength(1);
  });

  it("a lock held by another process fails closed: no execution", async () => {
    const path = tempJournal();
    writeFileSync(`${path}.lock`, "99999\n");
    const ledger = boundLedger([request()], createFileDispatchStore(path, { lockTimeoutMs: 50 }));
    const execute = vi.fn(async () => okay("0xnever"));
    await expect(ledger.run("metal-usdz", request(), target, execute)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("gap 3: an in-flight call with different terms is refused, not handed the original result", () => {
  it("same intent, different checkout, rail, amount and payee while the first is in flight", async () => {
    const ledger = createDispatchLedger({ store: createMemoryDispatchStore(), lookupIntent: consumedLookup(request()) });
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const execute = vi.fn(async () => { await gate; return okay("original-reference"); });
    const first = ledger.run("metal-usdz", request(), target, execute);
    const changed = ledger.run("different-rail", request({ checkoutId: "swapped-checkout", amountBaseUnits: "101" }), { payee: "different-payee", railAmount: "1010000000000000000" }, async () => okay("wrong-reference", "different-rail"));
    release();
    expect((await first).reference).toBe("original-reference");
    await expect(changed).rejects.toMatchObject({ reason: "dispatch_conflict" });
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("only the checkout differs: still refused", async () => {
    const ledger = boundLedger([request()]);
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const first = ledger.run("metal-usdz", request(), target, async () => { await gate; return okay("original-reference"); });
    const swapped = ledger.run("metal-usdz", request({ checkoutId: "other-checkout" }), target, async () => okay("x"));
    release();
    await first;
    await expect(swapped).rejects.toMatchObject({ reason: "dispatch_conflict" });
  });
});

describe("gap 4: the request is frozen before the first await", () => {
  it("raising the amount from 100 to 101 cents after pay() still pays exactly 100 cents", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const req = request();
    const rail = createMetalUsdzAdapter(client, payer, { "review-merchant": payee }, boundLedger([request()]));
    const pending = rail.pay(req);
    queueMicrotask(() => { req.amountBaseUnits = "101"; });
    const result = await pending;
    expect(await client.balanceOf(payee)).toBe(ONE_DOLLAR_USDZ);
    expect(result.detail.amountBaseUnits).toBe(ONE_DOLLAR_USDZ.toString());
  });

  it("changing the checkout or merchant after run() does not change what is reserved", async () => {
    const ledger = boundLedger([request()]);
    const req = request();
    const pending = ledger.run("metal-usdz", req, target, async () => okay("0xfrozen"));
    queueMicrotask(() => { req.checkoutId = "attacker-checkout"; req.merchant.id = "attacker"; });
    await pending;
    expect(await ledger.settled("review-checkout", "0xfrozen")).toMatchObject({ checkoutId: "review-checkout", merchantId: "review-merchant" });
    expect(await ledger.settled("attacker-checkout", "0xfrozen")).toBeNull();
  });
});

describe("results are checked before a dispatch counts as paid", () => {
  it("a Metal transfer with finalized=false is never settled and is not resent", async () => {
    const transfer = vi.fn(async ({ onSigned }: { onSigned?: (h: string) => Promise<void> }) => { await onSigned?.("0xunfinal"); return { txHash: "0xunfinal", finalized: false }; });
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async ({ txHash }) => ({ txHash, finalized: false }) };
    const ledger = boundLedger([request()]);
    const rail = createMetalUsdzAdapter(client, payer, { "review-merchant": payee }, ledger);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "metal_not_final" });
    expect(await ledger.settled("review-checkout", "0xunfinal")).toBeNull();
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(transfer).toHaveBeenCalledTimes(1);
  });

  it("an execute result for another rail is not marked succeeded", async () => {
    const ledger = boundLedger([request()]);
    await expect(ledger.run("metal-usdz", request(), target, async () => okay("0xwrong", "airwallex-airi"))).rejects.toMatchObject({ reason: "dispatch_result_mismatch" });
    expect(await ledger.settled("review-checkout", "0xwrong")).toBeNull();
  });

  it("a merchant that refuses the order is reported separately from PAID", async () => {
    const memory = createMemoryDispatchStore();
    const rig = await createShopperRig({ metal: "mock", dispatchStore: { ...memory, findSettled: async () => null } });
    try {
      const r = await rig.shop({ text: "Coffee brewing setup for the office: beans, filters, mugs", budgetCents: 12_000 });
      expect(r.outcome).toBe("MERCHANT_FAILED");
      expect(r.payment?.status).toBe("succeeded");
      expect(r.orderNumber).toBeUndefined();
    } finally { await rig.close(); }
  });
});
