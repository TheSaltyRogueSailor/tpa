/**
 * MySQL dispatch store (tpa_payment_dispatches). Opt-in: set TPA_DISPATCH_TEST_DATABASE_URL to a DISPOSABLE
 * schema. This suite drops and recreates ONLY tpa_payment_dispatches; it never touches the other TPA tables.
 * Setup is the real upgrade path: migration 0002, then legacy (pre-3.1) rows written in the 0002 shape, then
 * migration 0003 applied on top. No backfill: legacy rows keep NULL binding columns.
 */
import { readFileSync } from "node:fs";
import mysql from "mysql2/promise";
import { drizzle } from "drizzle-orm/mysql2";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createTpaDispatchStore, isBoundDispatchRecord, TpaDispatchStoreError, type TpaDispatchRecord } from "../src/dispatch.js";
import { createDispatchLedger, createMetalUsdzAdapter, createMockMetalClient, LEGACY_BINDING_LABEL, type MetalClient } from "../shopper/payments.js";
import { boundFixture, consumedLookup, PAYER } from "./support/dispatch.js";

const URL = process.env.TPA_DISPATCH_TEST_DATABASE_URL;
let pool: mysql.Pool;
const host = () => ({ getDb: async () => drizzle(pool) as never, assertOwnerForUpdate: async () => undefined });
const rec = (intentId: string, over: Partial<TpaDispatchRecord> = {}): TpaDispatchRecord => ({ intentId, mandateHash: "a".repeat(64), checkoutId: "chk_1", rail: "metal-usdz", merchantId: "m", currency: "USD",
  amountBaseUnits: "100", payee: PAYEE, railAmount: "1000000000000000000", status: "reserved", createdAtMs: 1, updatedAtMs: 1, ...over });
// Schema-valid Metal values: payee is an address, tx hashes are 0x + 64 hex (src/dispatch.ts parseDispatchRecord).
const PAYEE = "0x0000000000000000000000000000000000000002";
const tx = (byte: string) => `0x${byte.repeat(32)}`;
const LEGACY_SENT = "o".repeat(64), LEGACY_RESERVED = "p".repeat(64), LEGACY_DONE = "q".repeat(64);
const ok = (reference: string) => ({ rail: "metal-usdz", mode: "testnet" as const, status: "succeeded" as const, reference, detail: {} });

describe.skipIf(!URL)("MySQL dispatch store (tpa_payment_dispatches)", () => {
  beforeAll(async () => {
    pool = mysql.createPool({ uri: URL!, connectionLimit: 8 });
    await pool.query("DROP TABLE IF EXISTS tpa_payment_dispatches");
    await pool.query(readFileSync("migrations/0002_tpa_payment_dispatches.sql", "utf8").replace(/^--.*$/gm, ""));
    // Old-row fixtures written with the 0002 column set only (exactly what a pre-3.1 deployment holds).
    const legacy = "INSERT INTO tpa_payment_dispatches (intentId, mandateHash, checkoutId, rail, merchantId, currency, amountBaseUnits, payee, railAmount, status, txHash, reference, resultJson, createdAtMs, updatedAtMs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    await pool.query(legacy, [LEGACY_SENT, "a".repeat(64), "chk_old", "metal-usdz", "m", "USD", "100", PAYEE, "1000000000000000000", "sent", tx("71"), null, null, 1, 2]);
    await pool.query(legacy, [LEGACY_RESERVED, "a".repeat(64), "chk_old2", "metal-usdz", "m", "USD", "100", PAYEE, "1000000000000000000", "reserved", null, null, null, 1, 1]);
    await pool.query(legacy, [LEGACY_DONE, "a".repeat(64), "chk_old3", "metal-usdz", "m", "USD", "100", PAYEE, "1000000000000000000", "succeeded", tx("73"), tx("73"), JSON.stringify(ok(tx("73"))), 1, 3]);
    await pool.query(readFileSync("migrations/0003_tpa_checkout_binding.sql", "utf8").replace(/^--.*$/gm, ""));
  });
  afterAll(async () => { await pool?.end(); });

  it("reserves atomically: of 8 concurrent inserts exactly one wins, the rest see the winner", async () => {
    const store = createTpaDispatchStore(host());
    const results = await Promise.all(Array.from({ length: 8 }, () => store.reserve(rec("i".repeat(64)))));
    expect(results.filter(r => r.created)).toHaveLength(1);
    for (const r of results) if (!r.created) expect(r.existing).toMatchObject({ intentId: "i".repeat(64), status: "reserved" });
  });

  it("walks reserved -> sent -> succeeded with conditional transitions and finds the settled row by checkout + reference", async () => {
    const store = createTpaDispatchStore(host());
    const id = "s".repeat(64);
    await store.reserve(rec(id));
    expect(await store.markSent(id, tx("a1"), 2)).toBe(true);
    expect(await store.markSent(id, tx("b2"), 3)).toBe(false);
    expect(await store.release(id)).toBe(false); // signed: must be reconciled, never released
    expect(await store.markSucceeded(id, ok(tx("a1")), 4)).toBe(true);
    expect(await store.markSucceeded(id, ok(tx("a1")), 5)).toBe(false);
    expect(await store.findSettled("chk_1", tx("a1"))).toMatchObject({ intentId: id, status: "succeeded", txHash: tx("a1"), result: { reference: tx("a1") } });
    expect(await store.findSettled("chk_other", tx("a1"))).toBeNull();
  });

  it("releases an unsigned reservation so a retry can pay", async () => {
    const store = createTpaDispatchStore(host());
    const id = "r".repeat(64);
    await store.reserve(rec(id));
    expect(await store.release(id)).toBe(true);
    expect(await store.get(id)).toBeNull();
  });

  it("through the ledger: a sent v3.1 dispatch survives a new process and is reconciled, not re-signed", async () => {
    const fx = boundFixture({ intentId: "l".repeat(64), quoteId: "chk_l", payee: PAYEE });
    await expect(createDispatchLedger({ store: createTpaDispatchStore(host()), lookupIntent: consumedLookup(fx) }).run("metal-usdz", fx.request(), async ({ onSigned }) => { await onSigned(tx("c3")); throw new Error("receipt timeout"); })).rejects.toThrow();
    const row = await createTpaDispatchStore(host()).get(fx.intentId);
    expect(row && isBoundDispatchRecord(row) && row.checkoutFingerprint).toBe(fx.mandate.checkoutFingerprint);
    expect(row?.paymentTargetHash).toBe(fx.mandate.paymentTargetHash);
    const again = createDispatchLedger({ store: createTpaDispatchStore(host()), lookupIntent: consumedLookup(fx) });
    let signed = 0;
    await expect(again.run("metal-usdz", fx.request(), async () => { signed += 1; return ok(tx("d4")); })).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(await again.run("metal-usdz", fx.request(), async () => { signed += 1; return ok(tx("d4")); }, async r => ok(r.txHash!))).toMatchObject({ reference: tx("c3") });
    expect(signed).toBe(0);
  });

  it("0003 migration: legacy rows read back as legacy (no fabricated hashes); no backfill happened", async () => {
    const store = createTpaDispatchStore(host());
    const [rows] = await pool.query("SELECT intentId, checkoutFingerprint, paymentTargetHash, snapshotJson FROM tpa_payment_dispatches WHERE intentId IN (?,?,?)", [LEGACY_SENT, LEGACY_RESERVED, LEGACY_DONE]) as [Array<Record<string, unknown>>, unknown];
    expect(rows).toHaveLength(3);
    for (const r of rows) expect([r.checkoutFingerprint, r.paymentTargetHash, r.snapshotJson]).toEqual([null, null, null]);
    for (const id of [LEGACY_SENT, LEGACY_RESERVED, LEGACY_DONE]) {
      const rec = await store.get(id);
      expect(rec && isBoundDispatchRecord(rec)).toBe(false);
      expect(rec?.checkoutFingerprint).toBeUndefined();
    }
  });

  it("legacy rows: never executed by the v3.1 path; sent is recoverable read-only (labelled); reserved can never execute", async () => {
    const store = createTpaDispatchStore(host());
    const transfer = vi.fn(async () => ({ txHash: tx("ff"), finalized: true }));
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async ({ txHash }) => ({ txHash, finalized: true }) };
    // A v3.1 mandate for the same intent id cannot ride on the legacy row.
    const fx = boundFixture({ intentId: LEGACY_SENT, quoteId: "chk_old", payee: PAYEE });
    const ledger = createDispatchLedger({ store, lookupIntent: consumedLookup(fx) });
    const rail = createMetalUsdzAdapter(client, PAYER, ledger);
    await expect(rail.pay(fx.request())).rejects.toMatchObject({ reason: "legacy_dispatch_row" });
    await expect(rail.recoverLegacy(LEGACY_RESERVED)).rejects.toMatchObject({ reason: "legacy_reservation_not_executable" });
    const recovered = await rail.recoverLegacy(LEGACY_SENT);
    expect(recovered).toMatchObject({ reference: tx("71"), detail: { binding: LEGACY_BINDING_LABEL } });
    expect(await rail.recoverLegacy(LEGACY_DONE)).toMatchObject({ reference: tx("73") });
    expect(transfer).not.toHaveBeenCalled();
    const after = await store.get(LEGACY_SENT);
    expect(after?.status).toBe("succeeded");
    expect(after?.snapshot).toBeUndefined();
  });

  it("0003 strict parsing: partial binding, tampered snapshot or a column that disagrees with the snapshot is refused", async () => {
    const store = createTpaDispatchStore(host());
    const fx = boundFixture({ intentId: "t".repeat(64), quoteId: "chk_t", payee: PAYEE });
    const ledger = createDispatchLedger({ store, lookupIntent: consumedLookup(fx) });
    await createMetalUsdzAdapter(createMockMetalClient({ [PAYER]: 10n ** 22n }), PAYER, ledger).pay(fx.request());
    const good = await store.get(fx.intentId);
    expect(good && isBoundDispatchRecord(good)).toBe(true);
    const [[raw]] = await pool.query("SELECT snapshotJson, checkoutFingerprint, paymentTargetHash FROM tpa_payment_dispatches WHERE intentId = ?", [fx.intentId]) as [Array<{ snapshotJson: string; checkoutFingerprint: string; paymentTargetHash: string }>, unknown];
    const restore = () => pool.query("UPDATE tpa_payment_dispatches SET snapshotJson = ?, checkoutFingerprint = ?, paymentTargetHash = ? WHERE intentId = ?", [raw!.snapshotJson, raw!.checkoutFingerprint, raw!.paymentTargetHash, fx.intentId]);
    const snap = JSON.parse(raw!.snapshotJson);
    const cases: Array<[string, unknown[]]> = [
      ["partial binding", ["UPDATE tpa_payment_dispatches SET snapshotJson = NULL WHERE intentId = ?", [fx.intentId]]],
      ["fingerprint column", ["UPDATE tpa_payment_dispatches SET checkoutFingerprint = ? WHERE intentId = ?", ["0".repeat(64), fx.intentId]]],
      ["snapshot price", ["UPDATE tpa_payment_dispatches SET snapshotJson = ? WHERE intentId = ?", [JSON.stringify({ ...snap, checkout: { ...snap.checkout, items: [{ ...snap.checkout.items[0], unitPriceBaseUnits: "101" }] } }), fx.intentId]]],
      ["snapshot payee", ["UPDATE tpa_payment_dispatches SET snapshotJson = ? WHERE intentId = ?", [JSON.stringify({ ...snap, target: { ...snap.target, payee: `evm:0x${"9".repeat(40)}` } }), fx.intentId]]],
      ["payee column", ["UPDATE tpa_payment_dispatches SET payee = ? WHERE intentId = ?", [`0x${"9".repeat(40)}`, fx.intentId]]],
      ["unknown snapshot key", ["UPDATE tpa_payment_dispatches SET snapshotJson = ? WHERE intentId = ?", [JSON.stringify({ ...snap, extra: 1 }), fx.intentId]]],
    ];
    for (const [name, [sql, params]] of cases) {
      await pool.query(sql as string, params as unknown[]);
      await expect(store.get(fx.intentId), name).rejects.toBeInstanceOf(TpaDispatchStoreError);
      await restore();
      await pool.query("UPDATE tpa_payment_dispatches SET payee = ? WHERE intentId = ?", [PAYEE, fx.intentId]);
    }
    expect(await store.get(fx.intentId)).toMatchObject({ status: "succeeded" });
  });

  it("refuses a stored row that fails the closed schema instead of trusting it", async () => {
    const store = createTpaDispatchStore(host());
    const id = "x".repeat(64);
    await store.reserve(rec(id));
    expect(await store.markSent(id, tx("e5"), 2)).toBe(true);
    await pool.query("UPDATE tpa_payment_dispatches SET status = 'succeeded', resultJson = ? WHERE intentId = ?", [JSON.stringify({ ...ok(tx("e5")), mode: "live" }), id]);
    await expect(store.get(id)).rejects.toBeInstanceOf(TpaDispatchStoreError);
    await pool.query("UPDATE tpa_payment_dispatches SET resultJson = ? WHERE intentId = ?", ["{not json", id]);
    await expect(store.get(id)).rejects.toBeInstanceOf(TpaDispatchStoreError);
    await expect(store.markSucceeded("y".repeat(64), { ...ok(tx("f6")), rail: "wire" }, 3)).rejects.toBeInstanceOf(TpaDispatchStoreError);
    await expect(store.reserve(rec("z".repeat(64), { currency: "EUR" }))).rejects.toBeInstanceOf(TpaDispatchStoreError);
  });
});
