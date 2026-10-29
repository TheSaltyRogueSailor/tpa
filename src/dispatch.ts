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

/**
 * Closed-schema validation for a persisted dispatch row and its stored result. Used on every read and write of the
 * JSON journal and on MySQL rows, so a hand-edited, truncated or foreign row is refused instead of trusted.
 * Unknown keys, wrong types, unknown enums and impossible status combinations all fail. Throws TpaDispatchRecordError.
 */
export const TPA_DISPATCH_RAILS = ["airwallex-airi", "airwallex-sandbox", "metal-usdz"] as const;
export const TPA_DISPATCH_MODES = ["mock", "sandbox", "testnet"] as const;
export class TpaDispatchRecordError extends Error { constructor(readonly field: string) { super(`invalid dispatch record (${field})`); this.name = "TpaDispatchRecordError"; } }
const RECORD_KEYS = new Set(["intentId", "mandateHash", "checkoutId", "rail", "merchantId", "currency", "amountBaseUnits", "payee", "railAmount", "status", "txHash", "result", "createdAtMs", "updatedAtMs"]);
const RESULT_KEYS = new Set(["rail", "mode", "status", "reference", "detail"]);
const TOKEN = /^[\x21-\x7e]{1,128}$/; // printable ASCII, no spaces or control characters
const isPlain = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
function closed(v: unknown, keys: Set<string>, field: string): Record<string, unknown> {
  if (!isPlain(v)) throw new TpaDispatchRecordError(field);
  for (const k of Object.keys(v)) if (!keys.has(k)) throw new TpaDispatchRecordError(`${field}.${k}`);
  return v;
}
function str(v: unknown, re: RegExp, field: string): string { if (typeof v !== "string" || !re.test(v)) throw new TpaDispatchRecordError(field); return v; }
function oneOf<T extends string>(v: unknown, values: readonly T[], field: string): T { if (typeof v !== "string" || !(values as readonly string[]).includes(v)) throw new TpaDispatchRecordError(field); return v as T; }
function ms(v: unknown, field: string): number { if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new TpaDispatchRecordError(field); return v; }

export function parseDispatchResult(value: unknown, rail?: string): TpaDispatchResult {
  const r = closed(value, RESULT_KEYS, "result");
  const detail = closed(r.detail, new Set(Object.keys(isPlain(r.detail) ? r.detail : {})), "result.detail");
  const keys = Object.keys(detail);
  if (keys.length > 16) throw new TpaDispatchRecordError("result.detail");
  const out: Record<string, string> = {};
  for (const k of keys) { if (!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(k)) throw new TpaDispatchRecordError("result.detail"); out[k] = str(detail[k], /^[^\u0000-\u001f]{0,256}$/, `result.detail.${k}`); }
  const parsed: TpaDispatchResult = {
    rail: oneOf(r.rail, TPA_DISPATCH_RAILS, "result.rail"), mode: oneOf(r.mode, TPA_DISPATCH_MODES, "result.mode"),
    status: oneOf(r.status, ["succeeded"] as const, "result.status"), reference: str(r.reference, TOKEN, "result.reference"), detail: out,
  };
  if (rail !== undefined && parsed.rail !== rail) throw new TpaDispatchRecordError("result.rail");
  return parsed;
}

export function parseDispatchRecord(value: unknown): TpaDispatchRecord {
  const v = closed(value, RECORD_KEYS, "record");
  const rail = oneOf(v.rail, TPA_DISPATCH_RAILS, "rail");
  const metal = rail === "metal-usdz";
  const record: TpaDispatchRecord = {
    intentId: str(v.intentId, /^[A-Za-z0-9_.:-]{1,64}$/, "intentId"),
    mandateHash: str(v.mandateHash, /^[a-f0-9]{64}$/, "mandateHash"),
    checkoutId: str(v.checkoutId, TOKEN, "checkoutId"),
    rail,
    merchantId: str(v.merchantId, TOKEN, "merchantId"),
    currency: oneOf(v.currency, ["USD"] as const, "currency"),
    amountBaseUnits: str(v.amountBaseUnits, /^[1-9][0-9]{0,15}$/, "amountBaseUnits"),
    payee: str(v.payee, metal ? /^0x[0-9a-fA-F]{40}$/ : TOKEN, "payee"),
    railAmount: str(v.railAmount, /^[1-9][0-9]{0,79}$/, "railAmount"),
    status: oneOf(v.status, ["reserved", "sent", "succeeded"] as const, "status"),
    createdAtMs: ms(v.createdAtMs, "createdAtMs"),
    updatedAtMs: ms(v.updatedAtMs, "updatedAtMs"),
  };
  if (record.updatedAtMs < record.createdAtMs) throw new TpaDispatchRecordError("updatedAtMs");
  if (v.txHash !== undefined) record.txHash = str(v.txHash, metal ? /^0x[0-9a-fA-F]{64}$/ : TOKEN, "txHash");
  if (v.result !== undefined) record.result = parseDispatchResult(v.result, rail);
  // Status invariants: reserved has neither; sent has a tx id and no result; succeeded has a result.
  if (record.status === "reserved" && (record.txHash !== undefined || record.result !== undefined)) throw new TpaDispatchRecordError("status");
  if (record.status === "sent" && (record.txHash === undefined || record.result !== undefined)) throw new TpaDispatchRecordError("status");
  if (record.status === "succeeded" && record.result === undefined) throw new TpaDispatchRecordError("status");
  // A settled Metal row must name the transaction it recorded before broadcast.
  if (metal && record.status === "succeeded" && (record.txHash === undefined || record.result!.reference.toLowerCase() !== record.txHash.toLowerCase())) throw new TpaDispatchRecordError("result.reference");
  return record;
}

/** Durable dispatch persistence. Every transition is conditional on the current status, so two workers cannot both advance one row. */
export interface TpaDispatchStore {
  /** True for stores that survive restarts and are shared across processes. Live payment adapters refuse anything else. */
  readonly durable?: boolean;
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
const fromRow = (row: Row): TpaDispatchRecord => {
  let result: unknown;
  if (row.resultJson != null) { try { result = JSON.parse(row.resultJson); } catch { throw new TpaDispatchRecordError("resultJson"); } }
  const record = parseDispatchRecord({
    intentId: row.intentId, mandateHash: row.mandateHash, checkoutId: row.checkoutId, rail: row.rail, merchantId: row.merchantId, currency: row.currency,
    amountBaseUnits: row.amountBaseUnits, payee: row.payee, railAmount: row.railAmount, status: row.status,
    ...(row.txHash != null ? { txHash: row.txHash } : {}), ...(result !== undefined ? { result } : {}),
    createdAtMs: Number(row.createdAtMs), updatedAtMs: Number(row.updatedAtMs),
  });
  // The indexed reference column must agree with the stored result.
  if ((row.reference ?? null) !== (record.result?.reference ?? null)) throw new TpaDispatchRecordError("reference");
  return record;
};
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
    durable: true,
    reserve: record => run(async () => {
      parseDispatchRecord({ ...record, status: "reserved", txHash: undefined, result: undefined });
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
    markSucceeded: (intentId, result, atMs) => run(async () => { parseDispatchResult(result); return affected(await (await db()).update(t).set({ status: "succeeded", reference: result.reference, resultJson: JSON.stringify(result), updatedAtMs: atMs })
      .where(and(eq(t.intentId, intentId), inArray(t.status, ["reserved", "sent"])))) === 1; }),
    release: intentId => run(async () => affected(await (await db()).delete(t).where(and(eq(t.intentId, intentId), eq(t.status, "reserved"), isNull(t.txHash)))) === 1),
    findSettled: (checkoutId, reference) => run(async () => {
      const [row] = await (await db()).select().from(t).where(and(eq(t.reference, reference), eq(t.checkoutId, checkoutId), eq(t.status, "succeeded"))).limit(1);
      return row ? fromRow(row) : null;
    }),
  };
}
