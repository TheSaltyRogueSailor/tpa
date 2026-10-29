import { and, eq, inArray, isNull } from "drizzle-orm";
import { bigint, mysqlEnum, mysqlTable, text, uniqueIndex, varchar } from "drizzle-orm/mysql-core";
import type { TpaHostAdapter } from "./host/contracts.js";

/**
 * Payment dispatch records: one row per consumed TPA intent, reserved before anything is signed.
 * Lives beside the authorization evidence in the same MySQL database (migration 0002). The row is the
 * only thing that lets a rail move money for an intent, and it keeps the signed transaction id so a
 * retry reconciles instead of resending.
 *
 *   reserved -> sent (txHash recorded BEFORE broadcast) -> succeeded
 *   reserved -> (deleted) when the rail failed before signing, so a retry may pay
 *   sent stays sent on any unknown outcome; only reconcile by txHash may move it to succeeded
 */
export const tpaPaymentDispatches = mysqlTable("tpa_payment_dispatches", {
  intentId: varchar("intentId", { length: 64 }).primaryKey(),
  mandateHash: varchar("mandateHash", { length: 64 }).notNull(),
  checkoutId: varchar("checkoutId", { length: 128 }).notNull(),
  rail: varchar("rail", { length: 32 }).notNull(),
  merchantId: varchar("merchantId", { length: 128 }).notNull(),
  currency: varchar("currency", { length: 8 }).notNull(),
  amountBaseUnits: varchar("amountBaseUnits", { length: 40 }).notNull(),
  payee: varchar("payee", { length: 128 }).notNull(),
  railAmount: varchar("railAmount", { length: 80 }).notNull(),
  status: mysqlEnum("status", ["reserved", "sent", "succeeded"]).notNull(),
  txHash: varchar("txHash", { length: 128 }),
  reference: varchar("reference", { length: 128 }),
  resultJson: text("resultJson"),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
  updatedAtMs: bigint("updatedAtMs", { mode: "number" }).notNull(),
}, table => ({
  referenceIndex: uniqueIndex("tpa_dispatch_reference_idx").on(table.reference),
}));

export type TpaDispatchStatus = "reserved" | "sent" | "succeeded";
export type TpaDispatchResult = { rail: string; mode: string; status: "succeeded"; reference: string; detail: Record<string, string> };
export type TpaDispatchRecord = {
  intentId: string; mandateHash: string; checkoutId: string; rail: string; merchantId: string; currency: string; amountBaseUnits: string;
  /** Rail-level payee (allowlisted Metal address, or merchant id for card rails) and rail amount (e.g. USDZ base units). */
  payee: string; railAmount: string;
  status: TpaDispatchStatus; txHash?: string; result?: TpaDispatchResult; createdAtMs: number; updatedAtMs: number;
};

/** Durable dispatch persistence. Every transition is conditional on the current status, so two workers cannot both advance one row. */
export interface TpaDispatchStore {
  /** Atomic reservation: inserts the row, or returns the existing one untouched. */
  reserve(record: TpaDispatchRecord): Promise<{ created: true } | { created: false; existing: TpaDispatchRecord }>;
  get(intentId: string): Promise<TpaDispatchRecord | null>;
  /** reserved -> sent. False when the row was not in "reserved" (someone else advanced it). */
  markSent(intentId: string, txHash: string, atMs: number): Promise<boolean>;
  /** reserved|sent -> succeeded. */
  markSucceeded(intentId: string, result: TpaDispatchResult, atMs: number): Promise<boolean>;
  /** Deletes a reservation that never got a signed transaction. False when it had (it must then be reconciled). */
  release(intentId: string): Promise<boolean>;
  findSettled(checkoutId: string, reference: string): Promise<TpaDispatchRecord | null>;
}

export class TpaDispatchStoreError extends Error { constructor() { super("unavailable"); this.name = "TpaDispatchStoreError"; } }

type Row = typeof tpaPaymentDispatches.$inferSelect;
const fromRow = (row: Row): TpaDispatchRecord => ({
  intentId: row.intentId, mandateHash: row.mandateHash, checkoutId: row.checkoutId, rail: row.rail, merchantId: row.merchantId, currency: row.currency,
  amountBaseUnits: row.amountBaseUnits, payee: row.payee, railAmount: row.railAmount, status: row.status,
  ...(row.txHash ? { txHash: row.txHash } : {}), ...(row.resultJson ? { result: JSON.parse(row.resultJson) as TpaDispatchResult } : {}),
  createdAtMs: Number(row.createdAtMs), updatedAtMs: Number(row.updatedAtMs),
});
const affected = (result: unknown): number => {
  const header = Array.isArray(result) ? result[0] : result;
  return Number((header as { affectedRows?: number } | undefined)?.affectedRows ?? 0);
};
const isDuplicate = (error: unknown): boolean => {
  for (let e: any = error, i = 0; e && i < 4; e = e.cause, i += 1) if (e.code === "ER_DUP_ENTRY" || e.errno === 1062) return true;
  return false;
};

/** MySQL implementation on the host's TPA database (same adapter as createTpaStore / createTpaEvidenceStore). */
export function createTpaDispatchStore(host: TpaHostAdapter): TpaDispatchStore {
  async function db(): Promise<any> {
    const database = await host.getDb();
    if (!database) throw new TpaDispatchStoreError();
    return database;
  }
  async function run<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); } catch (error) { if (error instanceof TpaDispatchStoreError) throw error; throw Object.assign(new TpaDispatchStoreError(), { cause: error }); }
  }
  async function get(intentId: string) {
    const [row] = await (await db()).select().from(tpaPaymentDispatches).where(eq(tpaPaymentDispatches.intentId, intentId)).limit(1);
    return row ? fromRow(row) : null;
  }
  const t = tpaPaymentDispatches;
  return {
    reserve: record => run(async () => {
      try {
        await (await db()).insert(t).values({
          intentId: record.intentId, mandateHash: record.mandateHash, checkoutId: record.checkoutId, rail: record.rail, merchantId: record.merchantId,
          currency: record.currency, amountBaseUnits: record.amountBaseUnits, payee: record.payee, railAmount: record.railAmount,
          status: "reserved", txHash: null, reference: null, resultJson: null, createdAtMs: record.createdAtMs, updatedAtMs: record.updatedAtMs,
        });
        return { created: true as const };
      } catch (error) {
        if (!isDuplicate(error)) throw error;
        const existing = await get(record.intentId);
        if (!existing) throw error;
        return { created: false as const, existing };
      }
    }),
    get: intentId => run(() => get(intentId)),
    markSent: (intentId, txHash, atMs) => run(async () => affected(await (await db()).update(t).set({ status: "sent", txHash, updatedAtMs: atMs })
      .where(and(eq(t.intentId, intentId), eq(t.status, "reserved")))) === 1),
    markSucceeded: (intentId, result, atMs) => run(async () => affected(await (await db()).update(t).set({ status: "succeeded", reference: result.reference, resultJson: JSON.stringify(result), updatedAtMs: atMs })
      .where(and(eq(t.intentId, intentId), inArray(t.status, ["reserved", "sent"])))) === 1),
    release: intentId => run(async () => affected(await (await db()).delete(t).where(and(eq(t.intentId, intentId), eq(t.status, "reserved"), isNull(t.txHash)))) === 1),
    findSettled: (checkoutId, reference) => run(async () => {
      const [row] = await (await db()).select().from(t).where(and(eq(t.reference, reference), eq(t.checkoutId, checkoutId), eq(t.status, "succeeded"))).limit(1);
      return row ? fromRow(row) : null;
    }),
  };
}
