/**
 * MySQL dispatch store (tpa_payment_dispatches). Opt-in: set TPA_DISPATCH_TEST_DATABASE_URL to a DISPOSABLE
 * schema. This suite drops and recreates ONLY tpa_payment_dispatches (migration 0002); it never touches the
 * other TPA tables, so it is separate from the TPA_TEST_DATABASE_URL suites.
 */
import { readFileSync } from "node:fs";
import mysql from "mysql2/promise";
import { drizzle } from "drizzle-orm/mysql2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTpaDispatchStore, TpaDispatchStoreError, type TpaDispatchRecord } from "../src/dispatch.js";
import { createDispatchLedger, type PaymentRequest } from "../shopper/payments.js";
import { consumedLookup } from "./support/dispatch.js";

const URL = process.env.TPA_DISPATCH_TEST_DATABASE_URL;
let pool: mysql.Pool;
const host = () => ({ getDb: async () => drizzle(pool) as never, assertOwnerForUpdate: async () => undefined });
const rec = (intentId: string, over: Partial<TpaDispatchRecord> = {}): TpaDispatchRecord => ({ intentId, mandateHash: "a".repeat(64), checkoutId: "chk_1", rail: "metal-usdz", merchantId: "m", currency: "USD",
  amountBaseUnits: "100", payee: PAYEE, railAmount: "1000000000000000000", status: "reserved", createdAtMs: 1, updatedAtMs: 1, ...over });
// Schema-valid Metal values: payee is an address, tx hashes are 0x + 64 hex (src/dispatch.ts parseDispatchRecord).
const PAYEE = "0x0000000000000000000000000000000000000002";
const tx = (byte: string) => `0x${byte.repeat(32)}`;
const ok = (reference: string) => ({ rail: "metal-usdz", mode: "testnet" as const, status: "succeeded" as const, reference, detail: {} });

describe.skipIf(!URL)("MySQL dispatch store (tpa_payment_dispatches)", () => {
  beforeAll(async () => {
    pool = mysql.createPool({ uri: URL!, connectionLimit: 8 });
    await pool.query("DROP TABLE IF EXISTS tpa_payment_dispatches");
    await pool.query(readFileSync("migrations/0002_tpa_payment_dispatches.sql", "utf8").replace(/^--.*$/gm, ""));
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

  it("through the ledger: a sent dispatch survives a new process and is reconciled, not re-signed", async () => {
    const id = "l".repeat(64);
    const req: PaymentRequest = { receipt: { consumed: true, intentId: id, mandateHash: "a".repeat(64) }, merchant: { id: "m", name: "M" }, currency: "USD", amountBaseUnits: "100", checkoutId: "chk_l" };
    const T = { payee: PAYEE, railAmount: "1" };
    await expect(createDispatchLedger({ store: createTpaDispatchStore(host()), lookupIntent: consumedLookup(req) }).run("metal-usdz", req, T, async ({ onSigned }) => { await onSigned(tx("c3")); throw new Error("receipt timeout"); })).rejects.toThrow();
    const again = createDispatchLedger({ store: createTpaDispatchStore(host()), lookupIntent: consumedLookup(req) });
    let signed = 0;
    await expect(again.run("metal-usdz", req, T, async () => { signed += 1; return ok(tx("d4")); })).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(await again.run("metal-usdz", req, T, async () => { signed += 1; return ok(tx("d4")); }, async r => ok(r.txHash!))).toMatchObject({ reference: tx("c3") });
    expect(signed).toBe(0);
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
