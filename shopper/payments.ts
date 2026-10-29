/**
 * Payment rails behind one interface. Every adapter dispatches through a DispatchLedger: one payment per consumed
 * TPA v3.1 intent, bound to the server-signed mandate (checkout fingerprint, trusted quote id and frozen payment
 * target, all inside the signed tuple). The payee, rail amount, network, asset, conversion and fee cap come ONLY from
 * the signed mandate's paymentTarget; callers cannot supply them. A bare ConsumeReceipt object is only a shape check.
 *
 *   Airwallex (Kit 09): MockAiriAdapter now. Kit 09 pays through Airi CLI (allowlisted public beta):
 *     select payment method -> create payment mandate -> fetch one-time card credentials -> checkout
 *     -> report result. We have no Airi access yet, so the mock reproduces that sequence and its
 *     idempotency rule ("check the prior attempt before any retry").
 *   Airwallex sandbox REST: DISABLED under v3.1. The rail-specific Airwallex destination (beneficiary vs merchant
 *     account) is not documented yet, so the adapter refuses (destination_unverified) before any network call.
 *   Metal (USDZ on Metal alta-testnet): MetalUsdzAdapter over a MetalClient. MockMetalClient by default; the
 *     real client (viem + @metalntwx/metal-ts, chain 63825, USDZ at 0x...b5d5, 18 decimals) lives in
 *     shopper/metal.ts and is selected only with METAL_LIVE=1 plus METAL_RPC_URL and METAL_PAYER_KEY.
 */
import { createHash } from "node:crypto";
import { closeSync, constants as fsConstants, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { isBoundDispatchRecord, parseDispatchRecord, type TpaBoundDispatchRecord, type TpaDispatchRecord, type TpaDispatchStore } from "../src/dispatch.js";
import {
  canonicalTpaMandate, compareCheckoutToMandate, boundFingerprintInput, normalizeTpaCheckout, tpaBoundCheckoutMandateSchema,
  type TpaBoundCheckoutMandate, type TpaCheckoutInput, type TpaNormalizedCheckout,
} from "../src/domain.js";
import { METAL_USDZ_ASSET, TPA_DISPATCH_SNAPSHOT_VERSION, checkoutFingerprint, railPayee, type TpaDispatchSnapshot, type TpaPaymentTarget } from "../src/binding.js";

export type ConsumeReceipt = { consumed: true; intentId: string; mandateHash: string };
/**
 * What a caller hands a rail: the consume receipt, the trusted quote id (today the TAP checkoutId) and the actual
 * checkout being paid. Nothing about where the money goes or how much the rail moves: that is the signed target.
 */
export type PaymentRequest = { receipt: ConsumeReceipt; checkoutId: string; checkout: TpaCheckoutInput };
export type PaymentResult = { rail: string; mode: "mock" | "sandbox" | "testnet"; status: "succeeded"; reference: string; detail: Record<string, string> };
export interface PaymentAdapter { readonly rail: string; readonly mode: PaymentResult["mode"]; pay(request: PaymentRequest): Promise<PaymentResult> }

export class PaymentRefused extends Error { constructor(readonly reason: string, message: string) { super(message); this.name = "PaymentRefused"; } }
function requireReceipt(request: PaymentRequest) {
  const r = request?.receipt;
  if (!r || r.consumed !== true || typeof r.mandateHash !== "string" || !/^[a-f0-9]{64}$/.test(r.mandateHash) || typeof r.intentId !== "string" || !r.intentId) throw new PaymentRefused("no_tpa_receipt", "No TPA consume receipt: payment rails only run after the mandate exact-match check.");
}
const digest = (...parts: string[]) => createHash("sha256").update(parts.join("|")).digest("hex");
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") { for (const v of Object.values(value)) deepFreeze(v); Object.freeze(value); }
  return value;
}

/**
 * Immutable copy of a payment request, taken synchronously at the adapter / ledger boundary before any await. The
 * checkout is normalized (the same normalization the mandate was built with) and deep-frozen, so a caller that keeps
 * the original object cannot change items, prices, merchant or recipient after the permission check.
 */
export type FrozenPaymentRequest = Readonly<{
  receipt: Readonly<ConsumeReceipt>; checkoutId: string;
  /** The presented checkout exactly as given (deep-frozen copy), and its normalized form. */
  checkout: Readonly<TpaCheckoutInput>; normalized: Readonly<TpaNormalizedCheckout>;
  merchant: Readonly<{ id: string; name: string }>; currency: "USD"; amountBaseUnits: string;
}>;
export function snapshotRequest(request: PaymentRequest): FrozenPaymentRequest {
  requireReceipt(request);
  if (typeof request.checkoutId !== "string" || !request.checkoutId) throw new PaymentRefused("invalid_checkout", "Payment request has no quote / checkout id.");
  let checkout: TpaCheckoutInput, normalized: TpaNormalizedCheckout;
  try { checkout = structuredClone(request.checkout); normalized = normalizeTpaCheckout(structuredClone(checkout)); } catch { throw new PaymentRefused("invalid_checkout", "Payment request checkout is missing or invalid."); }
  if (normalized.currency !== "USD") throw new PaymentRefused("invalid_currency", "Only USD payments are supported.");
  return deepFreeze({
    receipt: { consumed: true as const, intentId: request.receipt.intentId, mandateHash: request.receipt.mandateHash },
    checkoutId: request.checkoutId, checkout, normalized,
    merchant: { id: normalized.merchant.id, name: normalized.merchant.name }, currency: "USD" as const, amountBaseUnits: normalized.totalBaseUnits,
  });
}

/* ------------------------------ dispatch ledger ------------------------------ */
/**
 * One payment dispatch per consumed TPA v3.1 intent. The ledger, not the caller, decides whether money may move:
 *   - binding: `lookupIntent` (owner-scoped, signature-verified: TpaService.readSignedIntent in shopper/flow.ts) must
 *     show the intent "consumed" under the receipt's mandate hash; the ledger recomputes that hash and both binding
 *     hashes from the signed v3.1 mandate, compares the presented checkout field by field (and by fingerprint), and
 *     requires the presented quote id and the rail to equal the signed ones. v3.0 and v2.0 mandates are refused
 *     (checkout_binding_missing / dispatch_not_bound): legacy modes never authorize new external payments.
 *   - target: the payee, rail amount, network, asset, conversion and fee cap come only from the signed paymentTarget.
 *   - freshness: before reserving, after reserving, and again at onSigned (immediately before anything is signed or
 *     sent) the intent is re-read and the mandate, quote and conversion expiry and the consumed state are rechecked.
 *     Expiry during preparation therefore refuses before signing and releases the reservation.
 *   - immutable row: the reservation stores the v3.1 snapshot (signed checkout + target + both hashes). Every read
 *     recomputes both hashes from it and requires them to equal the signed mandate.
 *   - unknown outcome: the tx/provider id is recorded ("sent") before broadcast. A "sent" row is only ever reconciled,
 *     read-only, by that id (this is allowed after expiry); it is never re-signed or resent.
 *   - legacy rows (no snapshot): never executed by run(). recoverLegacy() is a separately labelled historical,
 *     read-only path for pre-binding "sent" rows; legacy "reserved" rows cannot execute.
 * Live adapters additionally require a durable store.
 */
export type DispatchRecord = TpaDispatchRecord;
export type BoundIntent = { id: string; mandateHash: string; state: string; revokedAtMs?: number | null; mandate: unknown };
/** The frozen execution target: the untagged rail payee and rail amount, plus the full signed target. */
export type DispatchTarget = Readonly<{ payee: string; railAmount: string; signed: TpaPaymentTarget }>;
export type DispatchHooks = {
  request: FrozenPaymentRequest;
  target: DispatchTarget;
  /** Records the tx / provider id ("sent") after a final freshness check. Must be awaited BEFORE broadcast. */
  onSigned(txHash: string): Promise<void>;
  /** Re-reads the intent and rechecks state and every expiry; throws when the approval is no longer fresh. */
  confirmFresh(): Promise<void>;
};
export type LedgerReconcile = (record: DispatchRecord) => Promise<PaymentResult | null>;
export interface DispatchLedger {
  /** True when the backing store survives restarts and is shared across processes (MySQL, locked file journal). */
  readonly durable: boolean;
  run(rail: string, request: PaymentRequest, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: LedgerReconcile): Promise<PaymentResult>;
  /** Historical, read-only recovery for a legacy (pre-3.1) row. Never reserves, signs or sends. */
  recoverLegacy(rail: string, intentId: string, reconcile?: LedgerReconcile): Promise<PaymentResult>;
  /** The settled dispatch for a checkout and rail reference, if any (what a merchant may trust). */
  settled(checkoutId: string, reference: string): Promise<DispatchRecord | null>;
}
export type DispatchLedgerOptions = { store: TpaDispatchStore; lookupIntent: (intentId: string) => Promise<BoundIntent | null>; now?: () => number };

/** Ledgers built by createDispatchLedger (always permission-bound). Adapters refuse anything else. */
const boundLedgers = new WeakSet<object>();
function requireBoundLedger(ledger: DispatchLedger | undefined, live: boolean, rail: string): DispatchLedger {
  if (!ledger || !boundLedgers.has(ledger)) throw new PaymentRefused("ledger_unbound", `${rail}: a permission-bound dispatch ledger (createDispatchLedger with lookupIntent) is required.`);
  if (live && !ledger.durable) throw new PaymentRefused("ledger_not_durable", `${rail}: live payments need a durable dispatch store (MySQL or the locked file journal), not process memory.`);
  return ledger;
}

/** Process-local store for unit tests and mock rails. Not durable: live adapters refuse a ledger built on it. */
export function createMemoryDispatchStore(): TpaDispatchStore {
  const rows = new Map<string, DispatchRecord>();
  const copy = (r: DispatchRecord | undefined) => (r ? structuredClone(r) : null);
  return {
    durable: false,
    async reserve(record) { const existing = rows.get(record.intentId); if (existing) return { created: false, existing: copy(existing)! }; rows.set(record.intentId, structuredClone({ ...record, status: "reserved" })); return { created: true }; },
    async get(intentId) { return copy(rows.get(intentId)); },
    async markSent(intentId, txHash, atMs) { const r = rows.get(intentId); if (!r || r.status !== "reserved") return false; Object.assign(r, { status: "sent", txHash, updatedAtMs: atMs }); return true; },
    async markSucceeded(intentId, result, atMs) { const r = rows.get(intentId); if (!r || r.status === "succeeded") return false; Object.assign(r, { status: "succeeded", result: structuredClone(result), updatedAtMs: atMs }); return true; },
    async release(intentId) { const r = rows.get(intentId); if (!r || r.status !== "reserved" || r.txHash) return false; rows.delete(intentId); return true; },
    async findSettled(checkoutId, reference) { for (const r of rows.values()) if (r.status === "succeeded" && r.checkoutId === checkoutId && r.result?.reference === reference) return copy(r); return null; },
  };
}

/**
 * Same contract persisted to a local JSON file, safe across processes and across store instances: every operation
 * takes an exclusive lockfile (`<path>.lock`, created with O_EXCL), re-reads the journal from disk under the lock,
 * applies the transition, writes a temp file, fsyncs it and renames it over the journal, then drops the lock. Nothing
 * is cached between operations. Uncertain state fails closed: an unreadable or malformed journal, or a lock that
 * cannot be taken within `lockTimeoutMs` (for example one left behind by a crashed process), refuses with
 * dispatch_store_unavailable and never guesses. Used by the standalone shopper demo (no MySQL); hosts use
 * createTpaDispatchStore.
 */
export function createFileDispatchStore(path: string, options: { lockTimeoutMs?: number } = {}): TpaDispatchStore {
  const lockPath = `${path}.lock`;
  const timeoutMs = options.lockTimeoutMs ?? 5_000;
  const unavailable = (why: string) => new PaymentRefused("dispatch_store_unavailable", `Dispatch journal ${why}; refusing to pay until it is resolved.`);
  /** Every row must pass the closed schema (types, enums, status invariants) and intent ids must be unique. */
  function validRows(rows: unknown, why: string): DispatchRecord[] {
    if (!Array.isArray(rows)) throw unavailable(why);
    const out: DispatchRecord[] = [];
    const seen = new Set<string>();
    for (const row of rows) {
      let r: DispatchRecord;
      try { r = parseDispatchRecord(row); } catch { throw unavailable(why); }
      if (seen.has(r.intentId)) throw unavailable(why);
      seen.add(r.intentId);
      out.push(r);
    }
    return out;
  }
  function load(): DispatchRecord[] {
    if (!existsSync(path)) return [];
    let rows: unknown;
    try { rows = JSON.parse(readFileSync(path, "utf8")); } catch { throw unavailable("is unreadable or malformed"); }
    return validRows(rows, "is malformed");
  }
  function save(rows: DispatchRecord[]) {
    const checked = validRows(rows, "write would store an invalid row");
    const tmp = `${path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try { writeSync(fd, JSON.stringify(checked, null, 2)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, path);
    // The rename is only durable once the directory entry is: fsync the parent directory too (power-loss safety).
    let dirFd: number | undefined;
    try { dirFd = openSync(dirname(path), fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0)); fsyncSync(dirFd); }
    catch { throw unavailable("directory could not be synced after the write"); }
    finally { if (dirFd !== undefined) closeSync(dirFd); }
  }
  async function locked<T>(fn: (rows: DispatchRecord[]) => { out: T; rows?: DispatchRecord[] }): Promise<T> {
    mkdirSync(dirname(path), { recursive: true });
    const deadline = Date.now() + timeoutMs;
    let fd: number | undefined;
    for (let wait = 5; fd === undefined; wait = Math.min(wait * 2, 100)) {
      try { fd = openSync(lockPath, "wx", 0o600); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw unavailable("lock could not be created");
        if (Date.now() >= deadline) throw unavailable(`lock ${lockPath} is held (remove it only after checking no payment is running)`);
        await new Promise(r => setTimeout(r, wait));
      }
    }
    try {
      try { writeSync(fd, `${process.pid}\n`); } finally { closeSync(fd); }
      const rows = load();
      const { out, rows: next } = fn(rows);
      if (next) save(next);
      return out;
    } finally { try { unlinkSync(lockPath); } catch { /* already gone; nothing else to release */ } }
  }
  const copy = (r: DispatchRecord | undefined) => (r ? structuredClone(r) : null);
  const find = (rows: DispatchRecord[], intentId: string) => rows.find(r => r.intentId === intentId);
  return {
    durable: true,
    reserve: record => locked<{ created: true } | { created: false; existing: DispatchRecord }>(rows => {
      const existing = find(rows, record.intentId);
      if (existing) return { out: { created: false as const, existing: copy(existing)! } };
      return { out: { created: true as const }, rows: [...rows, { ...structuredClone(record), status: "reserved" }] };
    }),
    get: intentId => locked(rows => ({ out: copy(find(rows, intentId)) })),
    markSent: (intentId, txHash, atMs) => locked(rows => {
      const r = find(rows, intentId);
      if (!r || r.status !== "reserved") return { out: false };
      Object.assign(r, { status: "sent", txHash, updatedAtMs: atMs });
      return { out: true, rows };
    }),
    markSucceeded: (intentId, result, atMs) => locked(rows => {
      const r = find(rows, intentId);
      if (!r || r.status === "succeeded") return { out: false };
      Object.assign(r, { status: "succeeded", result: structuredClone(result), updatedAtMs: atMs });
      return { out: true, rows };
    }),
    release: intentId => locked(rows => {
      const r = find(rows, intentId);
      if (!r || r.status !== "reserved" || r.txHash) return { out: false };
      return { out: true, rows: rows.filter(x => x !== r) };
    }),
    findSettled: (checkoutId, reference) => locked(rows => ({ out: copy(rows.find(r => r.status === "succeeded" && r.checkoutId === checkoutId && r.result?.reference === reference)) })),
  };
}

/** Label written on results recovered through the historical legacy path. */
export const LEGACY_BINDING_LABEL = "legacy-pre-3.1" as const;

export function createDispatchLedger(options: DispatchLedgerOptions): DispatchLedger {
  if (!options || typeof options.lookupIntent !== "function") throw new PaymentRefused("ledger_unbound", "createDispatchLedger needs lookupIntent (the owner-scoped TPA intent reader); refusing to build an unbound ledger.");
  if (!options.store) throw new PaymentRefused("ledger_unbound", "createDispatchLedger needs a dispatch store.");
  const { store, lookupIntent } = options;
  const now = options.now ?? Date.now;
  const inflight = new Map<string, { fingerprint: string; promise: Promise<PaymentResult> }>();
  const notBound = (why = "Payment does not match a consumed, server-signed TPA mandate.") => new PaymentRefused("dispatch_not_bound", why);

  /** Reads the intent and returns its signed, consumed v3.1 mandate (hashes recomputed). Never checks expiry. */
  async function signedMandate(request: FrozenPaymentRequest): Promise<TpaBoundCheckoutMandate> {
    let intent: BoundIntent | null;
    try { intent = await lookupIntent(request.receipt.intentId); } catch { throw notBound("The TPA intent could not be read and verified (signature, owner or integrity)."); }
    if (!intent || intent.id !== request.receipt.intentId || intent.mandateHash !== request.receipt.mandateHash) throw notBound();
    if (intent.state !== "consumed" || (intent.revokedAtMs ?? null) !== null) throw notBound("The TPA intent is not consumed or was revoked.");
    const version = (intent.mandate as { version?: unknown } | null)?.version;
    if (version === "3.0") throw new PaymentRefused("checkout_binding_missing", "This mandate predates the v3.1 checkout binding; it cannot authorize a new external payment.");
    if (version !== "3.1") throw notBound("Only v3.1 bound checkout mandates authorize payments.");
    const parsed = tpaBoundCheckoutMandateSchema.safeParse(intent.mandate); // recomputes checkoutFingerprint and paymentTargetHash
    if (!parsed.success) throw new PaymentRefused("binding_invalid", "The signed mandate's binding hashes do not verify.");
    let canonical: string;
    try { canonical = canonicalTpaMandate(parsed.data); } catch { throw new PaymentRefused("binding_invalid", "The signed mandate could not be canonicalized."); }
    if (sha256(canonical) !== intent.mandateHash) throw new PaymentRefused("binding_invalid", "The mandate hash does not match the signed mandate.");
    return parsed.data;
  }
  /** The presented checkout, quote and rail must be exactly what was signed. */
  function bindRequest(mandate: TpaBoundCheckoutMandate, request: FrozenPaymentRequest, rail: string) {
    const difference = compareCheckoutToMandate(mandate, request.checkout);
    if (difference) throw new PaymentRefused(difference, `The checkout does not match the signed mandate (${difference}).`);
    if (request.checkoutId !== mandate.quote.quoteId) throw new PaymentRefused("quote_mismatch", "The quote id does not match the signed mandate.");
    const presented = checkoutFingerprint(boundFingerprintInput({ ...request.normalized, currency: "USD", amountBaseUnits: request.normalized.totalBaseUnits, quote: mandate.quote }));
    if (presented !== mandate.checkoutFingerprint) throw new PaymentRefused("fingerprint_mismatch", "The checkout fingerprint does not match the signed mandate.");
    if (mandate.paymentTarget.rail !== rail) throw new PaymentRefused("rail_mismatch", `The signed payment target is for ${mandate.paymentTarget.rail}, not ${rail}.`);
  }
  function assertFresh(mandate: TpaBoundCheckoutMandate) {
    const at = now();
    if (at >= mandate.expires * 1_000) throw new PaymentRefused("approval_expired", "The approval has expired; a new approval is required.");
    if (at >= mandate.quote.expires * 1_000) throw new PaymentRefused("quote_expired", "The quote has expired; a new approval is required.");
    if (at >= mandate.paymentTarget.conversion.expires * 1_000) throw new PaymentRefused("conversion_expired", "The locked conversion has expired; a new approval is required.");
  }
  /** Fresh re-read of the intent (state, revocation, signature via lookupIntent) plus every expiry. */
  async function confirmFresh(request: FrozenPaymentRequest, mandateHash: string) {
    const again = await signedMandate(request);
    if (sha256(canonicalTpaMandate(again)) !== mandateHash) throw new PaymentRefused("dispatch_conflict", "The signed mandate changed while preparing the payment.");
    assertFresh(again);
  }
  const targetOf = (t: TpaPaymentTarget): DispatchTarget => deepFreeze({ payee: railPayee(t), railAmount: t.railAmount, signed: structuredClone(t) });
  function snapshotOf(mandate: TpaBoundCheckoutMandate): TpaDispatchSnapshot {
    return { v: TPA_DISPATCH_SNAPSHOT_VERSION, mandateVersion: "3.1", checkout: structuredClone(boundFingerprintInput(mandate)) as TpaDispatchSnapshot["checkout"],
      target: structuredClone(mandate.paymentTarget), checkoutFingerprint: mandate.checkoutFingerprint, paymentTargetHash: mandate.paymentTargetHash };
  }
  /** A v3.1 row may only be used for the exact signed terms it was reserved under (hashes recomputed on read). */
  function sameBinding(row: TpaBoundDispatchRecord, mandate: TpaBoundCheckoutMandate, mandateHash: string, rail: string): boolean {
    let checkout: string;
    try { checkout = checkoutFingerprint(row.snapshot.checkout); } catch { return false; }
    return row.mandateHash === mandateHash && row.rail === rail && checkout === mandate.checkoutFingerprint
      && row.checkoutFingerprint === mandate.checkoutFingerprint && row.paymentTargetHash === mandate.paymentTargetHash
      && row.snapshot.paymentTargetHash === mandate.paymentTargetHash && row.checkoutId === mandate.quote.quoteId;
  }
  /** A rail result may only settle the row it was produced for. */
  function checkResult(result: PaymentResult | null | undefined, rail: string, target: { payee: string; railAmount: string }, reference?: string): PaymentResult {
    const d = result?.detail ?? {};
    if (!result || result.status !== "succeeded" || result.rail !== rail || typeof result.reference !== "string" || !result.reference
      || (reference !== undefined && result.reference.toLowerCase() !== reference.toLowerCase())
      || ("finalized" in d && d.finalized !== "true") || ("to" in d && d.to !== target.payee) || ("amountBaseUnits" in d && d.amountBaseUnits !== target.railAmount)) {
      throw new PaymentRefused("dispatch_result_mismatch", "Rail result does not match the reserved dispatch (rail, reference, payee, amount or finality); not marking it paid.");
    }
    return result;
  }
  async function settle(intentId: string, result: PaymentResult): Promise<PaymentResult> {
    if (await store.markSucceeded(intentId, result, now())) return result;
    const current = await store.get(intentId);
    if (current?.status === "succeeded" && current.result?.reference === result.reference) return current.result as PaymentResult;
    throw new PaymentRefused("dispatch_conflict", "Dispatch record changed while paying.");
  }
  /**
   * Every row read is re-parsed strictly, whatever the store: for a v3.1 row this recomputes both hashes from the
   * snapshot and checks every column (rail, quote, merchant, amount, payee, rail amount) against it.
   */
  function verifiedRow(row: DispatchRecord): DispatchRecord {
    try { return parseDispatchRecord(structuredClone(row)); } catch { throw new PaymentRefused("binding_invalid", "The stored dispatch row does not verify (snapshot, hashes or columns); refusing to use it."); }
  }
  async function existingRow(stored: DispatchRecord, mandate: TpaBoundCheckoutMandate, mandateHash: string, rail: string, reconcile?: LedgerReconcile): Promise<PaymentResult> {
    const existing = verifiedRow(stored);
    if (!isBoundDispatchRecord(existing)) throw new PaymentRefused("legacy_dispatch_row", "A pre-binding dispatch row exists for this intent; it can only be read through the historical legacy recovery path.");
    if (!sameBinding(existing, mandate, mandateHash, rail)) throw new PaymentRefused("dispatch_conflict", "This TPA intent was already dispatched under different signed terms, rail or target.");
    const target = targetOf(existing.snapshot.target);
    if (existing.status === "succeeded" && existing.result) return checkResult(existing.result as PaymentResult, rail, target);
    if (existing.status === "reserved") throw new PaymentRefused("dispatch_in_progress", "Another worker holds the dispatch reservation for this intent.");
    // "sent": read-only reconcile by the recorded id. Allowed after expiry; never re-signs or resends.
    const settled = reconcile ? await reconcile(existing) : null;
    if (!settled) throw new PaymentRefused("dispatch_pending_reconcile", `A transaction for this intent was already signed (${existing.txHash ?? "unknown"}); not resending until it is reconciled.`);
    return settle(existing.intentId, checkResult(settled, rail, target, existing.txHash));
  }

  async function dispatch(rail: string, request: FrozenPaymentRequest, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: LedgerReconcile) {
    const mandate = await signedMandate(request);
    bindRequest(mandate, request, rail);
    const mandateHash = request.receipt.mandateHash;
    const current = await store.get(request.receipt.intentId);
    if (current) return existingRow(current, mandate, mandateHash, rail, reconcile);
    assertFresh(mandate); // a fresh reservation needs a fresh approval
    const target = targetOf(mandate.paymentTarget);
    const at = now();
    const snapshot = snapshotOf(mandate);
    const record: DispatchRecord = { intentId: request.receipt.intentId, mandateHash, checkoutId: mandate.quote.quoteId, rail, merchantId: mandate.merchant.id,
      currency: mandate.currency, amountBaseUnits: mandate.amountBaseUnits, payee: target.payee, railAmount: target.railAmount, status: "reserved", createdAtMs: at, updatedAtMs: at,
      checkoutFingerprint: snapshot.checkoutFingerprint, paymentTargetHash: snapshot.paymentTargetHash, snapshot };
    try { parseDispatchRecord(record); } catch { throw new PaymentRefused("binding_invalid", "The dispatch snapshot does not verify against the signed mandate."); }
    const reserved = await store.reserve(record);
    if (!reserved.created) return existingRow(reserved.existing, mandate, mandateHash, rail, reconcile);
    let signedTx: string | undefined;
    try {
      await confirmFresh(request, mandateHash); // after the reservation (lock) wait
      const result = await execute({
        request, target,
        confirmFresh: () => confirmFresh(request, mandateHash),
        onSigned: async txHash => {
          await confirmFresh(request, mandateHash); // after async preparation, immediately before broadcast
          if (!(await store.markSent(request.receipt.intentId, txHash, now()))) throw new PaymentRefused("dispatch_conflict", "Dispatch reservation changed before broadcast; not sending.");
          signedTx = txHash;
        },
      });
      return await settle(request.receipt.intentId, checkResult(result, rail, target, signedTx));
    } catch (error) {
      // Nothing signed: release so a fresh approval may pay. Signed: keep "sent" so a retry reconciles, never resends.
      if (!signedTx) await store.release(request.receipt.intentId).catch(() => undefined);
      throw error;
    }
  }

  const ledger: DispatchLedger = {
    durable: store.durable === true,
    run(rail, request, execute, reconcile) {
      // Snapshot synchronously, before any await: nothing the caller does to its objects afterwards is seen here.
      let snap: FrozenPaymentRequest;
      try {
        if (typeof rail !== "string" || !rail) throw new PaymentRefused("invalid_target", "Rail is required.");
        snap = snapshotRequest(request);
      } catch (error) { return Promise.reject(error); }
      const fingerprint = digest(rail, snap.receipt.intentId, snap.receipt.mandateHash, snap.checkoutId, JSON.stringify(snap.normalized));
      const key = snap.receipt.intentId;
      const running = inflight.get(key);
      if (running) {
        if (running.fingerprint !== fingerprint) return Promise.reject(new PaymentRefused("dispatch_conflict", "A different payment for this TPA intent is already in flight (checkout, quote or rail differ)."));
        return running.promise;
      }
      const promise = dispatch(rail, snap, execute, reconcile).finally(() => inflight.delete(key));
      inflight.set(key, { fingerprint, promise });
      return promise;
    },
    async recoverLegacy(rail, intentId, reconcile) {
      const stored = await store.get(intentId);
      if (!stored) throw new PaymentRefused("dispatch_unknown", "No dispatch row for this intent.");
      const row = verifiedRow(stored);
      if (isBoundDispatchRecord(row)) throw new PaymentRefused("not_legacy", "This is a v3.1 row; use the bound dispatch path.");
      if (row.rail !== rail) throw new PaymentRefused("rail_mismatch", "The legacy row belongs to a different rail.");
      const target = { payee: row.payee, railAmount: row.railAmount };
      if (row.status === "succeeded" && row.result) return checkResult(row.result as PaymentResult, rail, target);
      if (row.status === "reserved") throw new PaymentRefused("legacy_reservation_not_executable", "A legacy pre-binding reservation can never execute; it needs a new v3.1 approval.");
      const found = reconcile ? await reconcile(row) : null;
      if (!found) throw new PaymentRefused("dispatch_pending_reconcile", `Legacy transaction ${row.txHash ?? "unknown"} is not settled yet; still pending, nothing resent.`);
      const checked = checkResult(found, rail, target, row.txHash);
      return settle(row.intentId, { ...checked, detail: { ...checked.detail, binding: LEGACY_BINDING_LABEL } });
    },
    async settled(checkoutId, reference) { return store.findSettled(checkoutId, reference); },
  };
  boundLedgers.add(ledger);
  return Object.freeze(ledger);
}

/* --------------------------- Airwallex / Airi (Kit 09) --------------------------- */
/**
 * Mock rail: needs a permission-bound ledger (memory store is fine, nothing real moves). The destination is the
 * signed, tagged mock fixture ("awx-mock-fixture:<id>"); a provider reference marker is recorded ("sent") before the
 * mock "provider call", and a retry reconciles against the recorded attempt instead of paying again.
 */
export function createMockAiriAdapter(ledger: DispatchLedger): PaymentAdapter & { attempts: Map<string, PaymentResult>; recoverLegacy(intentId: string): Promise<PaymentResult> } {
  const attempts = new Map<string, PaymentResult>();
  const reconcile: LedgerReconcile = async record => {
    const prior = attempts.get(record.intentId);
    return prior && record.txHash && prior.reference === record.txHash ? prior : null;
  };
  return {
    rail: "airwallex-airi", mode: "mock", attempts,
    recoverLegacy(intentId) {
      try { return requireBoundLedger(ledger, false, "airwallex-airi").recoverLegacy("airwallex-airi", intentId, reconcile); } catch (error) { return Promise.reject(error); }
    },
    pay(request) {
      let bound: DispatchLedger;
      try { bound = requireBoundLedger(ledger, false, "airwallex-airi"); } catch (error) { return Promise.reject(error); }
      // Kit 09 rule: before any retry, check the prior attempt. One mandate, one payment (enforced by the ledger).
      return bound.run("airwallex-airi", request, async ({ request: r, target, onSigned }) => {
        const signed = target.signed;
        if (signed.network !== "airwallex:mock-fixture" || !signed.payee.startsWith("awx-mock-fixture:") || signed.fee.capBaseUnits !== "0") {
          throw new PaymentRefused("destination_unverified", "Airwallex: only the documented mock fixture destination is supported.");
        }
        // TODO(airi): `airi` CLI calls once allowlisted and the destination contract is documented.
        const reference = `awx_mock_${digest(r.receipt.intentId, r.checkoutId).slice(0, 20)}`;
        await onSigned(reference); // durable provider marker, after the final freshness check, before the "provider call"
        const result: PaymentResult = {
          rail: "airwallex-airi", mode: "mock", status: "succeeded", reference,
          detail: { paymentMandateId: `pm_mock_${digest(r.receipt.mandateHash).slice(0, 16)}`, oneTimeCard: "**** **** **** 0000 (mock, never exposed to the agent)",
            to: target.payee, amountBaseUnits: target.railAmount, amount: (Number(target.railAmount) / 100).toFixed(2), currency: "USD", fee: "0" },
        };
        attempts.set(r.receipt.intentId, result);
        return result;
      }, reconcile);
    },
  };
}

/**
 * Airwallex sandbox REST: DISABLED for v3.1. Airwallex beneficiary ids and merchant account ids are not
 * interchangeable and the rail-specific destination mapping is not documented, so this adapter never guesses a payee:
 * every call refuses with destination_unverified before any network call, credentials are never read.
 */
export function createAirwallexSandboxAdapter(_ledger?: DispatchLedger): PaymentAdapter {
  return {
    rail: "airwallex-sandbox", mode: "sandbox",
    pay() { return Promise.reject(new PaymentRefused("destination_unverified", "Airwallex sandbox is disabled until the rail-specific destination mapping is documented; no payee is guessed.")); },
  };
}

/* ------------------------------- Metal (USDZ) ------------------------------- */
export const METAL_TESTNET = { chainId: 63825, usdz: "0x000000000000000000000000000000000000b5d5", decimals: 18 } as const;
/** Minimal chain surface the adapter needs. Real implementation: viem public/wallet client on METAL_RPC_URL. */
export interface MetalClient {
  readonly chainId: number;
  readonly mode: "mock" | "testnet";
  balanceOf(address: string): Promise<bigint>;
  /**
   * MIP20 transfer of USDZ base units; resolves once the transfer is final. `feeCap` (USDZ base units) is the signed
   * maximum network fee: a client must refuse (metal_fee_cap) before signing when gasLimit * maxFeePerGas exceeds it.
   */
  transfer(input: { from: string; to: string; amount: bigint; memo: string; feeCap?: bigint; onSigned?: (txHash: string) => Promise<void> }): Promise<{ txHash: string; finalized: boolean }>;
  /** Look up an already signed transfer by hash; null when it is not (yet) a settled matching transfer. Never resends. */
  reconcile?(input: { txHash: string; from: string; to: string; amount: bigint }): Promise<{ txHash: string; finalized: boolean } | null>;
}
/** Mock client. `mockFee` (default 0) is the fee it would charge, so the fee-cap refusal is testable offline. */
export function createMockMetalClient(balances: Record<string, bigint> = {}, mockFee = 0n): MetalClient & { balances: Map<string, bigint> } {
  const map = new Map(Object.entries(balances).map(([a, b]) => [a.toLowerCase(), b]));
  let nonce = 0;
  const sent = new Set<string>();
  return {
    chainId: METAL_TESTNET.chainId, mode: "mock", balances: map,
    async reconcile({ txHash }) { return sent.has(txHash) ? { txHash, finalized: true } : null; },
    async balanceOf(address) { return map.get(address.toLowerCase()) ?? 0n; },
    async transfer({ from, to, amount, memo, feeCap, onSigned }) {
      if (feeCap === undefined || mockFee > feeCap) throw new PaymentRefused("metal_fee_cap", "Mock Metal: the network fee would exceed the signed fee cap.");
      const have = map.get(from.toLowerCase()) ?? 0n;
      if (amount <= 0n || have < amount) throw new PaymentRefused("insufficient_usdz", "Mock Metal: insufficient USDZ balance.");
      nonce += 1;
      const txHash = `0x${digest(from, to, amount.toString(), memo, String(nonce))}`;
      await onSigned?.(txHash);
      map.set(from.toLowerCase(), have - amount);
      map.set(to.toLowerCase(), (map.get(to.toLowerCase()) ?? 0n) + amount);
      sent.add(txHash);
      return { txHash, finalized: true };
    },
  };
}
// Real client: createMetalTestnetClient / selectMetalClient in ./metal.ts (kept separate so the mock has no chain deps).
/** cents -> USDZ base units (18 decimals): 1 cent = 10^16 (the "usd-usdz-par" conversion). */
export const centsToUsdz = (cents: string) => BigInt(cents) * 10n ** 16n;

/**
 * USDZ rail. The transfer goes to the signed target's payee for the signed rail amount with the signed fee cap; the
 * adapter has no allowlist and takes no payee from anyone. A testnet client requires a durable ledger, and a transfer
 * that is not final is never reported as settled (the row stays "sent" for read-only reconcile).
 */
export function createMetalUsdzAdapter(client: MetalClient, payer: string, ledger: DispatchLedger): PaymentAdapter & { recoverLegacy(intentId: string): Promise<PaymentResult> } {
  const live = client.mode !== "mock";
  const sameTx = (a: unknown, b: string) => typeof a === "string" && a.toLowerCase() === b.toLowerCase();
  const referenceMismatch = (recorded: string) => new PaymentRefused("dispatch_result_mismatch", `Metal: rail reference does not match the recorded transaction ${recorded}; not marking it paid, not resending.`);
  const toResult = (tx: { txHash: string; finalized: boolean }, target: { payee: string; railAmount: string }): PaymentResult => {
    if (tx.finalized !== true) throw new PaymentRefused("metal_not_final", `Metal: ${tx.txHash} is not final yet; keep pending, do not resend.`);
    return { rail: "metal-usdz", mode: client.mode, status: "succeeded", reference: tx.txHash,
      detail: { chainId: String(client.chainId), token: `USDZ ${METAL_TESTNET.usdz}`, amountBaseUnits: target.railAmount, to: target.payee, finalized: "true" } };
  };
  // Reconcile uses only the recorded row (its tx hash, payee and amount; for v3.1 rows these were verified against the
  // signed snapshot on read). Read-only: never signs or sends.
  const reconcile: LedgerReconcile | undefined = client.reconcile ? async record => {
    if (!record.txHash) return null;
    const tx = await client.reconcile!({ txHash: record.txHash, from: payer, to: record.payee, amount: BigInt(record.railAmount) });
    if (tx && !sameTx(tx.txHash, record.txHash)) throw referenceMismatch(record.txHash);
    return tx && tx.finalized === true ? toResult(tx, { payee: record.payee, railAmount: record.railAmount }) : null;
  } : undefined;
  return {
    rail: "metal-usdz", mode: client.mode,
    recoverLegacy(intentId) {
      try { return requireBoundLedger(ledger, live, "metal-usdz").recoverLegacy("metal-usdz", intentId, reconcile); } catch (error) { return Promise.reject(error); }
    },
    pay(request) {
      let bound: DispatchLedger;
      try { bound = requireBoundLedger(ledger, live, "metal-usdz"); } catch (error) { return Promise.reject(error); }
      return bound.run("metal-usdz", request, async ({ onSigned, target, request: r }) => {
        const signed = target.signed;
        if (signed.network !== `evm:${client.chainId}` || signed.asset !== METAL_USDZ_ASSET || signed.decimals !== METAL_TESTNET.decimals || signed.fee.asset !== METAL_USDZ_ASSET) {
          throw new PaymentRefused("metal_target_mismatch", "Metal: the signed target is for a different network or asset than this client.");
        }
        let recorded: string | undefined;
        const tx = await client.transfer({ from: payer, to: target.payee, amount: BigInt(target.railAmount), memo: r.receipt.mandateHash, feeCap: BigInt(signed.fee.capBaseUnits),
          onSigned: async txHash => { await onSigned(txHash); recorded = txHash; } });
        // Only the hash the ledger recorded before broadcast may settle the row; anything else stays "sent" for reconcile.
        if (!recorded || !sameTx(tx.txHash, recorded)) throw referenceMismatch(recorded ?? "none");
        return toResult(tx, target);
      }, reconcile);
    },
  };
}

/* ------------------------------ target resolvers ------------------------------ */
/** Server-side destination resolution (run before approval). Unknown merchant or rail: null, never a guess. */
export type TargetResolverInput = { rail: string; merchant: { id: string }; recipientRef: string; currency: "USD"; sourceAmountBaseUnits: string; nowSeconds: number };
export const METAL_FEE_CAP_BASE_UNITS = "1000000"; // 1e6 USDZ base units: gasLimit (<= ~250k) * maxFeePerGas (1) with headroom
export const CONVERSION_LOCK_SECONDS = 900;
export function createMetalTargetResolver(merchantAddresses: Record<string, string>, chainId: number = METAL_TESTNET.chainId) {
  const book = Object.freeze({ ...merchantAddresses });
  return (input: TargetResolverInput): TpaPaymentTarget | null => {
    if (input.rail !== "metal-usdz" || input.currency !== "USD") return null;
    const address = Object.prototype.hasOwnProperty.call(book, input.merchant.id) ? book[input.merchant.id] : undefined;
    if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
    return {
      rail: "metal-usdz", network: `evm:${chainId}`, asset: METAL_USDZ_ASSET, decimals: 18, recipientRef: input.recipientRef, payee: `evm:${address.toLowerCase()}`,
      sourceCurrency: "USD", sourceAmountBaseUnits: input.sourceAmountBaseUnits, railAmount: centsToUsdz(input.sourceAmountBaseUnits).toString(),
      conversion: { id: "usd-usdz-par", rateNumerator: (10n ** 16n).toString(), rateDenominator: "1", expires: input.nowSeconds + CONVERSION_LOCK_SECONDS },
      fee: { asset: METAL_USDZ_ASSET, capBaseUnits: METAL_FEE_CAP_BASE_UNITS },
    };
  };
}
/** Airwallex: MOCK fixtures only (merchant id -> fixture id) until the real destination mapping is documented. */
export function createAiriFixtureResolver(fixtures: Record<string, string>) {
  const book = Object.freeze({ ...fixtures });
  return (input: TargetResolverInput): TpaPaymentTarget | null => {
    if (input.rail !== "airwallex-airi" || input.currency !== "USD") return null;
    const fixture = Object.prototype.hasOwnProperty.call(book, input.merchant.id) ? book[input.merchant.id] : undefined;
    if (!fixture || !/^[a-z0-9_-]{1,64}$/.test(fixture)) return null;
    return {
      rail: "airwallex-airi", network: "airwallex:mock-fixture", asset: "iso4217:USD", decimals: 2, recipientRef: input.recipientRef, payee: `awx-mock-fixture:${fixture}`,
      sourceCurrency: "USD", sourceAmountBaseUnits: input.sourceAmountBaseUnits, railAmount: input.sourceAmountBaseUnits,
      conversion: { id: "usd-usd-identity", rateNumerator: "1", rateDenominator: "1", expires: input.nowSeconds + CONVERSION_LOCK_SECONDS },
      fee: { asset: "iso4217:USD", capBaseUnits: "0" },
    };
  };
}
/** Combines per-rail resolvers into the service's TpaTargetResolver. */
export function combineTargetResolvers(...resolvers: ((input: TargetResolverInput) => TpaPaymentTarget | null)[]) {
  return { async resolve(input: TargetResolverInput) { for (const r of resolvers) { const t = r(input); if (t) return t; } return null; } };
}
