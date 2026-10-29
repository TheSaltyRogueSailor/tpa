/**
 * Refusal tests for the four payment-dispatch gaps found in review of 55ca605 (plus result checks), on the v3.1
 * ledger API (the target comes only from the signed mandate). Mock only: local balances, temp-dir journals, spies.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { createShopperRig } from "../shopper/flow.js";
import {
  createAirwallexSandboxAdapter, createDispatchLedger, createFileDispatchStore, createMemoryDispatchStore, createMetalUsdzAdapter, createMockMetalClient,
  type DispatchLedger, type MetalClient, type PaymentResult,
} from "../shopper/payments.js";
import { ONE_DOLLAR_USDZ, PAYEE as payee, PAYER as payer, boundFixture, boundLedger, consumedLookup } from "./support/dispatch.js";

const metalFx = boundFixture();
const airiFx = boundFixture({ rail: "airwallex-airi" });
const request = metalFx.request;
const okay = (reference: string, rail = "metal-usdz"): PaymentResult => ({ rail, mode: "mock", status: "succeeded", reference, detail: {} });
const tx = (byte: string) => `0x${byte.repeat(32)}`;
const dirs: string[] = [];
const tempJournal = () => { const d = mkdtempSync(join(tmpdir(), "tpa-refusal-")); dirs.push(d); return join(d, "dispatch.json"); };
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

describe("gap 1: every adapter needs a permission-bound ledger; live adapters need a durable one", () => {
  it("a Metal adapter without a ledger refuses a fabricated receipt and moves nothing", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const rail = (createMetalUsdzAdapter as (...a: unknown[]) => ReturnType<typeof createMetalUsdzAdapter>)(client, payer);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_unbound" });
    expect(await client.balanceOf(payee)).toBe(0n);
  });

  it("a ledger cannot be built without the intent reader", () => {
    expect(() => createDispatchLedger({ store: createMemoryDispatchStore() } as never)).toThrow(expect.objectContaining({ reason: "ledger_unbound" }));
  });

  it("a hand-made ledger object that skips the binding is refused", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const fake: DispatchLedger = { durable: true, run: (_rail, _req, execute) => execute({ onSigned: async () => undefined } as never), recoverLegacy: async () => okay("x"), settled: async () => null };
    const rail = createMetalUsdzAdapter(client, payer, fake);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_unbound" });
    expect(await client.balanceOf(payee)).toBe(0n);
  });

  it("a testnet Metal client refuses a ledger on process memory before signing", async () => {
    const transfer = vi.fn(async () => ({ txHash: "0x1", finalized: true }));
    const live: MetalClient = { chainId: 63825, mode: "testnet", balanceOf: async () => 0n, transfer };
    const rail = createMetalUsdzAdapter(live, payer, boundLedger([metalFx]));
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "ledger_not_durable" });
    expect(transfer).not.toHaveBeenCalled();
  });

  it("the Airwallex sandbox adapter is disabled: refuses destination_unverified before any network call", async () => {
    const fetchSpy = vi.fn(async () => { throw new Error("network must not be reached"); });
    const rail = (createAirwallexSandboxAdapter as (...a: unknown[]) => ReturnType<typeof createAirwallexSandboxAdapter>)(boundLedger([], createFileDispatchStore(tempJournal())), { AWX_CLIENT_ID: "x", AWX_API_KEY: "y" }, fetchSpy);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "destination_unverified" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("gap 2: the file journal is exclusive across store instances and processes", () => {
  it("two stores opened before the first payment execute one intent once", async () => {
    const path = tempJournal();
    const first = boundLedger([airiFx], createFileDispatchStore(path));
    const second = boundLedger([airiFx], createFileDispatchStore(path));
    let executions = 0;
    const execute = async () => okay(`mock-result-${++executions}`, "airwallex-airi");
    await first.run("airwallex-airi", airiFx.request(), execute);
    const again = await second.run("airwallex-airi", airiFx.request(), execute);
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
    const ledger = boundLedger([metalFx], createFileDispatchStore(path, { lockTimeoutMs: 50 }));
    const execute = vi.fn(async () => okay(tx("0e")));
    await expect(ledger.run("metal-usdz", request(), execute)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("gap 3: an in-flight call with different terms is refused, not handed the original result", () => {
  it("same intent, different checkout, quote and rail while the first is in flight", async () => {
    const ledger = createDispatchLedger({ store: createMemoryDispatchStore(), lookupIntent: consumedLookup(metalFx) });
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const execute = vi.fn(async () => { await gate; return okay("original-reference"); });
    const first = ledger.run("metal-usdz", request(), execute);
    const changed = ledger.run("airwallex-airi", request({ checkoutId: "swapped-checkout" }), async () => okay("wrong-reference", "airwallex-airi"));
    release();
    expect((await first).reference).toBe("original-reference");
    await expect(changed).rejects.toMatchObject({ reason: "dispatch_conflict" });
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("only the quote id differs: still refused", async () => {
    const ledger = boundLedger([metalFx]);
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const first = ledger.run("metal-usdz", request(), async () => { await gate; return okay("original-reference"); });
    const swapped = ledger.run("metal-usdz", request({ checkoutId: "other-checkout" }), async () => okay("x"));
    release();
    await first;
    await expect(swapped).rejects.toMatchObject({ reason: "dispatch_conflict" });
  });
});

describe("gap 4: the request is frozen before the first await", () => {
  it("raising a price after pay() still pays exactly the signed amount", async () => {
    const client = createMockMetalClient({ [payer]: 10n ** 22n });
    const req = request();
    const rail = createMetalUsdzAdapter(client, payer, boundLedger([metalFx]));
    const pending = rail.pay(req);
    queueMicrotask(() => { req.checkout.items[0]!.unitPriceBaseUnits = "101"; req.checkout.totalBaseUnits = "101"; });
    const result = await pending;
    expect(await client.balanceOf(payee)).toBe(ONE_DOLLAR_USDZ);
    expect(result.detail.amountBaseUnits).toBe(ONE_DOLLAR_USDZ.toString());
  });

  it("changing the checkout or merchant after run() does not change what is reserved", async () => {
    const ledger = boundLedger([metalFx]);
    const req = request();
    const pending = ledger.run("metal-usdz", req, async () => okay("0xfrozen"));
    queueMicrotask(() => { req.checkoutId = "attacker-checkout"; req.checkout.merchant.id = "attacker"; });
    await pending;
    expect(await ledger.settled("review-quote", "0xfrozen")).toMatchObject({ checkoutId: "review-quote", merchantId: "review-merchant" });
    expect(await ledger.settled("attacker-checkout", "0xfrozen")).toBeNull();
  });
});

describe("results are checked before a dispatch counts as paid", () => {
  it("a Metal transfer with finalized=false is never settled and is not resent", async () => {
    const transfer = vi.fn(async ({ onSigned }: { onSigned?: (h: string) => Promise<void> }) => { await onSigned?.(tx("aa")); return { txHash: tx("aa"), finalized: false }; });
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async ({ txHash }) => ({ txHash, finalized: false }) };
    const ledger = boundLedger([metalFx]);
    const rail = createMetalUsdzAdapter(client, payer, ledger);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "metal_not_final" });
    expect(await ledger.settled("review-quote", tx("aa"))).toBeNull();
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(transfer).toHaveBeenCalledTimes(1);
  });

  it("an execute result for another rail is not marked succeeded", async () => {
    const ledger = boundLedger([metalFx]);
    await expect(ledger.run("metal-usdz", request(), async () => okay("0xwrong", "airwallex-airi"))).rejects.toMatchObject({ reason: "dispatch_result_mismatch" });
    expect(await ledger.settled("review-quote", "0xwrong")).toBeNull();
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
