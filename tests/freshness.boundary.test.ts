/**
 * v3.1 freshness through signing and send, and read-only recovery separated from the fresh execution gate.
 * Adapted from Michael's 1461e69 review demonstrations (tests/v31.review-timing.test.ts, review-only). There they
 * passed by showing the defects; here the same scenarios are refusal and recovery tests.
 *   1. expiry or revocation crossing the durable markSent write: the payment is never sent, the row stays "sent"
 *      (read-only), and no retry re-signs or resends.
 *   2. expiry or revocation during preparation: refused at the signing boundary, the signer is never called.
 *   3. a recorded "sent" payment reconciles read-only even after its intent metadata is revoked.
 * Mock rails, an in-process fake RPC for the real Metal client, and memory / temp-file stores only: no network.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@metalntwx/metal-ts", async importOriginal => {
  const actual = await importOriginal<typeof import("@metalntwx/metal-ts")>();
  return { ...actual, signMip20Contract: vi.fn(actual.signMip20Contract) };
});
import { signMip20Contract } from "@metalntwx/metal-ts";
import { createMetalTestnetClient } from "../shopper/metal.js";
import {
  createDispatchLedger, createFileDispatchStore, createMemoryDispatchStore, createMetalUsdzAdapter, createMockAiriAdapter, createMockMetalClient,
  type BoundIntent, type MetalClient,
} from "../shopper/payments.js";
import type { TpaDispatchStore } from "../src/dispatch.js";
import { ONE_DOLLAR_USDZ, PAYEE, PAYER, boundFixture, consumedLookup, type Fixture } from "./support/dispatch.js";
import { offlineMetalRpc } from "./support/metal-rpc.js";

let dir: string;
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), "tpa-fresh-")); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });
beforeEach(() => { vi.mocked(signMip20Contract).mockClear(); });
let journals = 0;
const journal = () => join(dir, `dispatch-${++journals}.json`);

/** Intent reader whose revocation metadata a test can flip (models an authoritative host/reader change). */
function revocableLookup(f: Fixture) {
  const state = { revoked: false };
  const base = consumedLookup(f);
  const lookup = async (id: string): Promise<BoundIntent | null> => { const i = await base(id); return i && state.revoked ? { ...i, revokedAtMs: 1 } : i; };
  return { state, lookup };
}
/** Store whose markSent runs `during` right after the durable write (as if the write took that long). */
function slowMarkSent(inner: TpaDispatchStore, during: () => void): TpaDispatchStore {
  return { ...inner, markSent: async (id, hash, at) => { const ok = await inner.markSent(id, hash, at); during(); return ok; } };
}

describe("final fresh gate AFTER the durable markSent write (review demos 1 and 2, now refusals)", () => {
  it("expiry crossing the markSent write: never sent, row stays sent, a retry never re-signs or resends", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const f = boundFixture({ intentId: "write-delay-expiry", quoteId: "quote-delay-expiry", issuedAt });
    let clock = issuedAt * 1000;
    const inner = createMemoryDispatchStore();
    const ledger = createDispatchLedger({ store: slowMarkSent(inner, () => { clock = (f.mandate.expires + 1) * 1000; }), lookupIntent: consumedLookup(f), now: () => clock });
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const transfer = vi.spyOn(client, "transfer");
    const adapter = createMetalUsdzAdapter(client, PAYER, ledger);
    const error = await adapter.pay(f.request()).catch(e => e);
    expect(error).toMatchObject({ reason: "approval_expired" });
    expect(String(error.message)).toContain("recorded but not sent");
    expect(await client.balanceOf(PAYEE)).toBe(0n);
    expect(await client.balanceOf(PAYER)).toBe(10n * ONE_DOLLAR_USDZ);
    expect(client.signatures).toHaveLength(1);
    expect(await inner.get(f.intentId)).toMatchObject({ status: "sent", txHash: client.signatures[0] });
    await expect(adapter.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    clock = issuedAt * 1000; // even with a fresh clock again, the recorded row is read-only
    await expect(adapter.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(transfer).toHaveBeenCalledTimes(1);
    expect(client.signatures).toHaveLength(1);
    expect(await client.balanceOf(PAYEE)).toBe(0n);
  });

  it("revocation during the markSent write: never sent, row stays sent and read-only", async () => {
    const f = boundFixture({ intentId: "write-delay-revoke", quoteId: "quote-delay-revoke" });
    const { state, lookup } = revocableLookup(f);
    const inner = createMemoryDispatchStore();
    const ledger = createDispatchLedger({ store: slowMarkSent(inner, () => { state.revoked = true; }), lookupIntent: lookup });
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const adapter = createMetalUsdzAdapter(client, PAYER, ledger);
    await expect(adapter.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(await client.balanceOf(PAYEE)).toBe(0n);
    expect((await inner.get(f.intentId))?.status).toBe("sent");
    await expect(adapter.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(client.signatures).toHaveLength(1);
  });

  it("durable file journal: after a late refusal and a restart, the row is still read-only and nothing is resent", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const f = boundFixture({ intentId: "write-delay-file", quoteId: "quote-delay-file", issuedAt });
    const path = journal();
    let clock = issuedAt * 1000;
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const first = createDispatchLedger({ store: slowMarkSent(createFileDispatchStore(path), () => { clock = f.mandate.quote.expires * 1000; }), lookupIntent: consumedLookup(f), now: () => clock });
    await expect(createMetalUsdzAdapter(client, PAYER, first).pay(f.request())).rejects.toMatchObject({ reason: "approval_expired" });
    clock = issuedAt * 1000;
    const restarted = createDispatchLedger({ store: createFileDispatchStore(path), lookupIntent: consumedLookup(f), now: () => clock });
    await expect(createMetalUsdzAdapter(client, PAYER, restarted).pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(client.signatures).toHaveLength(1);
    expect(await client.balanceOf(PAYEE)).toBe(0n);
  });

  it("Airwallex mock: expiry crossing the provider-marker write means no provider call", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const f = boundFixture({ intentId: "airi-delay", quoteId: "quote-airi-delay", rail: "airwallex-airi", issuedAt });
    let clock = issuedAt * 1000;
    const inner = createMemoryDispatchStore();
    const airi = createMockAiriAdapter(createDispatchLedger({ store: slowMarkSent(inner, () => { clock = (f.mandate.expires + 1) * 1000; }), lookupIntent: consumedLookup(f), now: () => clock }));
    await expect(airi.pay(f.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(airi.attempts.size).toBe(0);
    expect((await inner.get(f.intentId))?.status).toBe("sent");
    await expect(airi.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(airi.attempts.size).toBe(0);
  });

  it("the final decision is made after the durable write and is the last read before the send", async () => {
    const f = boundFixture({ intentId: "order", quoteId: "quote-order" });
    const events: string[] = [];
    const inner = createMemoryDispatchStore();
    const store: TpaDispatchStore = { ...inner, markSent: async (id, hash, at) => { const ok = await inner.markSent(id, hash, at); events.push("markSent"); return ok; } };
    const base = consumedLookup(f);
    const ledger = createDispatchLedger({ store, lookupIntent: async id => { events.push("lookup"); return base(id); } });
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const set = client.balances.set.bind(client.balances);
    vi.spyOn(client.balances, "set").mockImplementation((k, v) => { events.push("send"); return set(k, v); });
    await createMetalUsdzAdapter(client, PAYER, ledger).pay(f.request());
    const marked = events.indexOf("markSent");
    const sent = events.indexOf("send");
    expect(marked).toBeGreaterThan(-1);
    expect(events.slice(marked + 1, sent)).toEqual(["lookup"]);
    expect(await client.balanceOf(PAYEE)).toBe(ONE_DOLLAR_USDZ);
  });
});

describe("pre-sign gate at the signing boundary: the signer is never called after expiry or revocation", () => {
  it("mock: expiry during preparation refuses before signing and releases the reservation", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const f = boundFixture({ intentId: "prep-expiry", quoteId: "quote-prep-expiry", issuedAt });
    let clock = issuedAt * 1000;
    const store = createMemoryDispatchStore();
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const ledger = createDispatchLedger({ store, lookupIntent: consumedLookup(f), now: () => clock });
    const slow: MetalClient = { ...client, transfer: input => { clock = f.mandate.expires * 1000; return client.transfer(input); } };
    await expect(createMetalUsdzAdapter(slow, PAYER, ledger).pay(f.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(client.signatures).toHaveLength(0);
    expect(await store.get(f.intentId)).toBeNull();
    expect(await client.balanceOf(PAYEE)).toBe(0n);
  });

  it("mock: revocation during preparation refuses before signing", async () => {
    const f = boundFixture({ intentId: "prep-revoke", quoteId: "quote-prep-revoke" });
    const { state, lookup } = revocableLookup(f);
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const slow: MetalClient = { ...client, transfer: input => { state.revoked = true; return client.transfer(input); } };
    await expect(createMetalUsdzAdapter(slow, PAYER, createDispatchLedger({ store: createMemoryDispatchStore(), lookupIntent: lookup })).pay(f.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(client.signatures).toHaveLength(0);
  });

  function liveRig(f: Fixture, onCall: (method: string, clock: { ms: number }) => void, lookup = consumedLookup(f)) {
    const payerKey = generatePrivateKey();
    const payer = privateKeyToAccount(payerKey).address;
    const clock = { ms: f.mandate.issuedAt * 1000 };
    const rpc = offlineMetalRpc({ onCall: method => onCall(method, clock) });
    const client = createMetalTestnetClient({ rpcUrl: "http://offline.invalid", payerKey, transport: rpc.transport, receiptTimeoutMs: 2_000, finalityTimeoutMs: 500 });
    const store = createFileDispatchStore(journal());
    const ledger = createDispatchLedger({ store, lookupIntent: lookup, now: () => clock.ms });
    return { rpc, store, clock, adapter: createMetalUsdzAdapter(client, payer, ledger) };
  }

  it("real Metal client (offline RPC): expiry during gas preparation means signMip20Contract is never called", async () => {
    const f = boundFixture({ intentId: "live-prep-expiry", quoteId: "quote-live-prep" });
    const r = liveRig(f, (method, clock) => { if (method === "eth_estimateGas") clock.ms = f.mandate.expires * 1000; });
    await expect(r.adapter.pay(f.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(r.rpc.calls).toContain("eth_estimateGas");
    expect(vi.mocked(signMip20Contract)).not.toHaveBeenCalled();
    expect(r.rpc.sends()).toBe(0);
    expect(await r.store.get(f.intentId)).toBeNull();
  });

  it("real Metal client (offline RPC): revocation during preparation means signMip20Contract is never called", async () => {
    const f = boundFixture({ intentId: "live-prep-revoke", quoteId: "quote-live-revoke" });
    const { state, lookup } = revocableLookup(f);
    const r = liveRig(f, method => { if (method === "eth_estimateGas") state.revoked = true; }, lookup);
    await expect(r.adapter.pay(f.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(vi.mocked(signMip20Contract)).not.toHaveBeenCalled();
    expect(r.rpc.sends()).toBe(0);
  });

  it("real Metal client (offline RPC): control case, a fresh approval reaches the signer once and sends once", async () => {
    const f = boundFixture({ intentId: "live-control", quoteId: "quote-live-control" });
    const r = liveRig(f, () => undefined);
    await expect(r.adapter.pay(f.request())).rejects.toMatchObject({ reason: "metal_transfer_not_found" }); // the fake receipt has no Transfer log
    expect(vi.mocked(signMip20Contract)).toHaveBeenCalledTimes(1);
    expect(r.rpc.sends()).toBe(1);
    expect((await r.store.get(f.intentId))?.status).toBe("sent");
  });

  it("real Metal client (offline RPC): expiry crossing the markSent write means signed but never broadcast", async () => {
    const f = boundFixture({ intentId: "live-mark", quoteId: "quote-live-mark" });
    const payerKey = generatePrivateKey();
    const rpc = offlineMetalRpc();
    const client = createMetalTestnetClient({ rpcUrl: "http://offline.invalid", payerKey, transport: rpc.transport });
    let clock = f.mandate.issuedAt * 1000;
    const inner = createFileDispatchStore(journal());
    const ledger = createDispatchLedger({ store: slowMarkSent(inner, () => { clock = (f.mandate.expires + 1) * 1000; }), lookupIntent: consumedLookup(f), now: () => clock });
    await expect(createMetalUsdzAdapter(client, privateKeyToAccount(payerKey).address, ledger).pay(f.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(vi.mocked(signMip20Contract)).toHaveBeenCalledTimes(1);
    expect(rpc.sends()).toBe(0);
    expect((await inner.get(f.intentId))?.status).toBe("sent");
  });

  it("real Metal client refuses (metal_unguarded) without both hooks, before any RPC call", async () => {
    const payerKey = generatePrivateKey();
    const rpc = offlineMetalRpc();
    const client = createMetalTestnetClient({ rpcUrl: "http://offline.invalid", payerKey, transport: rpc.transport });
    const from = privateKeyToAccount(payerKey).address;
    await expect(client.transfer({ from, to: PAYEE, amount: 1n, memo: "m", feeCap: 1_000_000n, onSigned: async () => undefined })).rejects.toMatchObject({ reason: "metal_unguarded" });
    await expect(client.transfer({ from, to: PAYEE, amount: 1n, memo: "m", feeCap: 1_000_000n, beforeSign: async () => undefined })).rejects.toMatchObject({ reason: "metal_unguarded" });
    expect(rpc.calls).toHaveLength(0);
    expect(vi.mocked(signMip20Contract)).not.toHaveBeenCalled();
  });
});

describe("read-only recovery uses the signed proof only, not the fresh gate (review demo 3, now a recovery)", () => {
  async function lostReceipt(f: Fixture, now?: () => number) {
    const { state, lookup } = revocableLookup(f);
    const store = createMemoryDispatchStore();
    const ledger = createDispatchLedger({ store, lookupIntent: lookup, ...(now ? { now } : {}) });
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const transfer = vi.spyOn(client, "transfer");
    const crashing: MetalClient = { ...client, transfer: async input => { await client.transfer(input); throw new Error("synthetic lost receipt"); } };
    await expect(createMetalUsdzAdapter(crashing, PAYER, ledger).pay(f.request())).rejects.toThrow("synthetic lost receipt");
    expect((await store.get(f.intentId))?.status).toBe("sent");
    return { state, store, ledger, client, transfer };
  }

  it("a recorded sent payment still reconciles after its intent metadata is revoked; nothing is re-signed or resent", async () => {
    const f = boundFixture({ intentId: "sent-revoked-recovery", quoteId: "quote-sent-recovery" });
    const r = await lostReceipt(f);
    r.state.revoked = true;
    const reconcile = vi.fn(r.client.reconcile!);
    const result = await createMetalUsdzAdapter({ ...r.client, reconcile }, PAYER, r.ledger).pay(f.request());
    expect(result).toMatchObject({ status: "succeeded", reference: (await r.store.get(f.intentId))!.txHash });
    expect(reconcile).toHaveBeenCalledTimes(1);
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(r.client.signatures).toHaveLength(1);
    expect(await r.client.balanceOf(PAYEE)).toBe(ONE_DOLLAR_USDZ);
    expect((await r.store.get(f.intentId))?.status).toBe("succeeded");
  });

  it("revoked and expired: still reconciles read-only", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const f = boundFixture({ intentId: "sent-revoked-expired", quoteId: "quote-sent-rx", issuedAt });
    let clock = issuedAt * 1000;
    const r = await lostReceipt(f, () => clock);
    r.state.revoked = true;
    clock = (f.mandate.expires + 3600) * 1000;
    await expect(createMetalUsdzAdapter(r.client, PAYER, r.ledger).pay(f.request())).resolves.toMatchObject({ status: "succeeded" });
    expect(r.transfer).toHaveBeenCalledTimes(1);
  });

  it("revoked, transaction not found: stays pending, nothing signed or sent", async () => {
    const f = boundFixture({ intentId: "sent-revoked-pending", quoteId: "quote-sent-rp" });
    const r = await lostReceipt(f);
    r.state.revoked = true;
    await expect(createMetalUsdzAdapter({ ...r.client, reconcile: async () => null }, PAYER, r.ledger).pay(f.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(r.transfer).toHaveBeenCalledTimes(1);
    expect(r.client.signatures).toHaveLength(1);
  });

  it("revoked with no recorded row: the fresh gate refuses and nothing is reserved or signed", async () => {
    const f = boundFixture({ intentId: "revoked-fresh", quoteId: "quote-revoked-fresh" });
    const { state, lookup } = revocableLookup(f);
    state.revoked = true;
    const store = createMemoryDispatchStore();
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const transfer = vi.spyOn(client, "transfer");
    await expect(createMetalUsdzAdapter(client, PAYER, createDispatchLedger({ store, lookupIntent: lookup })).pay(f.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(transfer).not.toHaveBeenCalled();
    expect(await store.get(f.intentId)).toBeNull();
  });

  it("recovery still requires the signed proof: wrong mandate hash, unconsumed intent or changed checkout never reach reconcile", async () => {
    const f = boundFixture({ intentId: "sent-proof", quoteId: "quote-sent-proof" });
    const r = await lostReceipt(f);
    r.state.revoked = true;
    const reconcile = vi.fn(r.client.reconcile!);
    const adapter = createMetalUsdzAdapter({ ...r.client, reconcile }, PAYER, r.ledger);
    await expect(adapter.pay({ ...f.request(), receipt: { consumed: true, intentId: f.intentId, mandateHash: "0".repeat(64) } })).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    await expect(adapter.pay({ ...f.request(), checkout: { ...f.checkout, items: [{ ...f.checkout.items[0]!, sku: "SWAPPED" }] } })).rejects.toMatchObject({ reason: "items_mismatch" });
    const unconsumed = createDispatchLedger({ store: r.store, lookupIntent: async id => { const i = await consumedLookup(f)(id); return i && { ...i, state: "authorized" }; } });
    await expect(createMetalUsdzAdapter({ ...r.client, reconcile }, PAYER, unconsumed).pay(f.request())).rejects.toMatchObject({ reason: "dispatch_not_bound" });
    expect(reconcile).not.toHaveBeenCalled();
    expect(r.transfer).toHaveBeenCalledTimes(1);
  });
});
