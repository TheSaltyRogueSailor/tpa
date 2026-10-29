/**
 * Payment rails behind one interface. The mock Airi and Metal adapters dispatch through a DispatchLedger: one
 * payment per consumed TPA intent, bound (when the ledger has the TPA evidence reader, as in shopper/flow.ts) to the
 * amount, currency and merchant of the server-signed mandate and to one checkout id. A bare ConsumeReceipt object is
 * only a shape check; the binding comes from the ledger reading the consumed intent server side.
 *
 *   Airwallex (Kit 09): MockAiriAdapter now. Kit 09 pays through Airi CLI (allowlisted public beta):
 *     select payment method -> create payment mandate -> fetch one-time card credentials -> checkout
 *     -> report result. We have no Airi access yet, so the mock reproduces that sequence and its
 *     idempotency rule ("check the prior attempt before any retry").
 *   Airwallex sandbox REST: AirwallexSandboxAdapter, only used when AWX_CLIENT_ID / AWX_API_KEY are set.
 *     NOT exercised yet (no keys). Endpoints per airwallexdev.com/guide.
 *   Metal (USDZ on Metal alta-testnet): MetalUsdzAdapter over a MetalClient. MockMetalClient by default; the
 *     real client (viem + @metalntwx/metal-ts, chain 63825, USDZ at 0x...b5d5, 18 decimals) lives in
 *     shopper/metal.ts and is selected only with METAL_LIVE=1 plus METAL_RPC_URL and METAL_PAYER_KEY.
 */
import { createHash } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import type { TpaDispatchRecord, TpaDispatchStore } from "../src/dispatch.js";

export type ConsumeReceipt = { consumed: true; intentId: string; mandateHash: string };
export type PaymentRequest = {
  receipt: ConsumeReceipt;
  merchant: { id: string; name: string };
  currency: "USD";
  amountBaseUnits: string; // cents
  checkoutId: string;
};
export type PaymentResult = { rail: string; mode: "mock" | "sandbox" | "testnet"; status: "succeeded"; reference: string; detail: Record<string, string> };
export interface PaymentAdapter { readonly rail: string; readonly mode: PaymentResult["mode"]; pay(request: PaymentRequest): Promise<PaymentResult> }

export class PaymentRefused extends Error { constructor(readonly reason: string, message: string) { super(message); this.name = "PaymentRefused"; } }
function requireReceipt(request: PaymentRequest) {
  const r = request?.receipt;
  if (!r || r.consumed !== true || typeof r.mandateHash !== "string" || !/^[a-f0-9]{64}$/.test(r.mandateHash) || typeof r.intentId !== "string" || !r.intentId) throw new PaymentRefused("no_tpa_receipt", "No TPA consume receipt: payment rails only run after the mandate exact-match check.");
}
const digest = (...parts: string[]) => createHash("sha256").update(parts.join("|")).digest("hex");

/**
 * Immutable copy of a payment request, taken synchronously at the adapter / ledger boundary before any await.
 * Only the known fields are copied (as primitive strings), then deep-frozen, so a caller that keeps the original
 * object cannot change the amount, payee, merchant or checkout after the permission check.
 */
export type FrozenPaymentRequest = Readonly<{ receipt: Readonly<ConsumeReceipt>; merchant: Readonly<{ id: string; name: string }>; currency: "USD"; amountBaseUnits: string; checkoutId: string }>;
export function snapshotRequest(request: PaymentRequest): FrozenPaymentRequest {
  requireReceipt(request);
  const str = (v: unknown, reason: string) => { if (typeof v !== "string" || !v) throw new PaymentRefused(reason, `Payment request field is missing or not a string (${reason}).`); return v; };
  const amount = str(request.amountBaseUnits, "invalid_amount");
  if (!/^[1-9][0-9]{0,15}$/.test(amount)) throw new PaymentRefused("invalid_amount", "Amount is not a positive integer number of cents.");
  if (request.currency !== "USD") throw new PaymentRefused("invalid_currency", "Only USD payments are supported.");
  return Object.freeze({
    receipt: Object.freeze({ consumed: true as const, intentId: request.receipt.intentId, mandateHash: request.receipt.mandateHash }),
    merchant: Object.freeze({ id: str(request.merchant?.id, "invalid_merchant"), name: typeof request.merchant?.name === "string" ? request.merchant.name : "" }),
    currency: "USD" as const, amountBaseUnits: amount, checkoutId: str(request.checkoutId, "invalid_checkout"),
  });
}

/* ------------------------------ dispatch ledger ------------------------------ */
/**
 * One payment dispatch per consumed TPA intent. The ledger, not the caller's receipt, decides whether money may move:
 *   - binding (required): `lookupIntent` (the owner-scoped TPA evidence reader) must show the intent "consumed" under
 *     the same mandate hash (which covers items, shipping, tax and total), and the amount, currency and merchant id
 *     the rail is asked to pay must equal that server-signed 3.0 mandate. A ledger cannot be built without it, and
 *     every adapter requires a ledger made by createDispatchLedger. The checkout id, rail, allowlisted payee and rail
 *     amount are fixed by the first reservation and can never change for that intent.
 *   - immutable request: the request and rail target are snapshotted and frozen before the first await; the reserved
 *     row, the in-flight fingerprint and the executed transfer all come from that one snapshot.
 *   - atomic reservation: a durable TpaDispatchStore row (MySQL table tpa_payment_dispatches in a host deployment, or
 *     the lock-protected JSON journal in the standalone demo) is inserted before anything is signed; a duplicate
 *     insert loses. Concurrent calls in one process share one promise only when their fingerprints match.
 *   - unknown outcome: the tx id is recorded ("sent") before broadcast. A "sent" row is never re-signed; a retry first
 *     reconciles by tx id and is refused (dispatch_pending_reconcile) until the rail confirms it.
 *   - results are checked (rail, reference, payee, amount, finality) before a row is marked succeeded.
 * Live adapters (Metal testnet, Airwallex sandbox) additionally require a durable store.
 */
export type DispatchRecord = TpaDispatchRecord;
export type BoundIntent = { id: string; mandateHash: string; state: string; mandate: { version: string; currency: string; amountBaseUnits: string; merchant?: { id: string } } };
export type DispatchTarget = { payee: string; railAmount: string };
export type DispatchHooks = { onSigned(txHash: string): Promise<void>; request: FrozenPaymentRequest; target: Readonly<DispatchTarget> };
export interface DispatchLedger {
  /** True when the backing store survives restarts and is shared across processes (MySQL, locked file journal). */
  readonly durable: boolean;
  run(rail: string, request: PaymentRequest, target: DispatchTarget, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: (record: DispatchRecord) => Promise<PaymentResult | null>): Promise<PaymentResult>;
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
  const isRecord = (r: unknown): r is DispatchRecord => !!r && typeof r === "object" && typeof (r as DispatchRecord).intentId === "string" && ["reserved", "sent", "succeeded"].includes((r as DispatchRecord).status);
  function load(): DispatchRecord[] {
    if (!existsSync(path)) return [];
    let rows: unknown;
    try { rows = JSON.parse(readFileSync(path, "utf8")); } catch { throw unavailable("is unreadable or malformed"); }
    if (!Array.isArray(rows) || !rows.every(isRecord)) throw unavailable("is malformed");
    return rows;
  }
  function save(rows: DispatchRecord[]) {
    const tmp = `${path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try { writeSync(fd, JSON.stringify(rows, null, 2)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, path);
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

/** Canonical fingerprint of one dispatch: everything the reservation fixes. */
const fingerprintOf = (f: { intentId: string; mandateHash: string; checkoutId: string; rail: string; merchantId: string; currency: string; amountBaseUnits: string; payee: string; railAmount: string }) =>
  digest(JSON.stringify([f.intentId, f.mandateHash, f.checkoutId, f.rail, f.merchantId, f.currency, f.amountBaseUnits, f.payee, f.railAmount]));

export function createDispatchLedger(options: DispatchLedgerOptions): DispatchLedger {
  if (!options || typeof options.lookupIntent !== "function") throw new PaymentRefused("ledger_unbound", "createDispatchLedger needs lookupIntent (the owner-scoped TPA intent reader); refusing to build an unbound ledger.");
  if (!options.store) throw new PaymentRefused("ledger_unbound", "createDispatchLedger needs a dispatch store.");
  const { store, lookupIntent } = options;
  const now = options.now ?? Date.now;
  const inflight = new Map<string, { fingerprint: string; promise: Promise<PaymentResult> }>();

  async function bind(request: FrozenPaymentRequest) {
    const intent = await lookupIntent(request.receipt.intentId);
    const m = intent?.mandate;
    if (!intent || intent.id !== request.receipt.intentId || intent.state !== "consumed" || intent.mandateHash !== request.receipt.mandateHash || !m || m.version !== "3.0"
      || m.amountBaseUnits !== request.amountBaseUnits || m.currency !== request.currency || m.merchant?.id !== request.merchant.id) {
      throw new PaymentRefused("dispatch_not_bound", "Payment does not match a consumed, server-signed TPA mandate (amount, currency, merchant).");
    }
  }
  /** A rail result may only settle the row it was produced for. */
  function checkResult(result: PaymentResult | null | undefined, rail: string, target: Readonly<DispatchTarget>): PaymentResult {
    const d = result?.detail ?? {};
    if (!result || result.status !== "succeeded" || result.rail !== rail || typeof result.reference !== "string" || !result.reference
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

  async function dispatch(rail: string, request: FrozenPaymentRequest, target: Readonly<DispatchTarget>, fingerprint: string, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: (record: DispatchRecord) => Promise<PaymentResult | null>) {
    await bind(request);
    const at = now();
    const record: DispatchRecord = { intentId: request.receipt.intentId, mandateHash: request.receipt.mandateHash, checkoutId: request.checkoutId, rail, merchantId: request.merchant.id,
      currency: request.currency, amountBaseUnits: request.amountBaseUnits, payee: target.payee, railAmount: target.railAmount, status: "reserved", createdAtMs: at, updatedAtMs: at };
    const reserved = await store.reserve(record);
    if (!reserved.created) {
      const existing = reserved.existing;
      if (fingerprintOf(existing) !== fingerprint) throw new PaymentRefused("dispatch_conflict", "This TPA intent was already dispatched for a different checkout, rail, payee or amount.");
      if (existing.status === "succeeded" && existing.result) return checkResult(existing.result as PaymentResult, rail, target);
      if (existing.status === "reserved") throw new PaymentRefused("dispatch_in_progress", "Another worker holds the dispatch reservation for this intent.");
      const settled = reconcile ? await reconcile(existing) : null;
      if (!settled) throw new PaymentRefused("dispatch_pending_reconcile", `A transaction for this intent was already signed (${existing.txHash ?? "unknown"}); not resending until it is reconciled.`);
      return settle(existing.intentId, checkResult(settled, rail, target));
    }
    let signedTx: string | undefined;
    try {
      const result = await execute({ request, target, onSigned: async txHash => {
        if (!(await store.markSent(request.receipt.intentId, txHash, now()))) throw new PaymentRefused("dispatch_conflict", "Dispatch reservation changed before broadcast; not sending.");
        signedTx = txHash;
      } });
      return await settle(request.receipt.intentId, checkResult(result, rail, target));
    } catch (error) {
      // Nothing signed: release so a retry is allowed. Signed: keep "sent" so a retry reconciles instead of resending.
      if (!signedTx) await store.release(request.receipt.intentId).catch(() => undefined);
      throw error;
    }
  }

  const ledger: DispatchLedger = {
    durable: store.durable === true,
    run(rail, request, target, execute, reconcile) {
      // Snapshot synchronously, before any await: nothing the caller does to its objects afterwards is seen here.
      let snap: FrozenPaymentRequest;
      let frozenTarget: Readonly<DispatchTarget>;
      try {
        snap = snapshotRequest(request);
        if (typeof rail !== "string" || !rail || typeof target?.payee !== "string" || !target.payee || typeof target.railAmount !== "string" || !target.railAmount) throw new PaymentRefused("invalid_target", "Rail, payee and rail amount are required.");
        frozenTarget = Object.freeze({ payee: target.payee, railAmount: target.railAmount });
      } catch (error) { return Promise.reject(error); }
      const fingerprint = fingerprintOf({ intentId: snap.receipt.intentId, mandateHash: snap.receipt.mandateHash, checkoutId: snap.checkoutId, rail, merchantId: snap.merchant.id,
        currency: snap.currency, amountBaseUnits: snap.amountBaseUnits, payee: frozenTarget.payee, railAmount: frozenTarget.railAmount });
      const key = snap.receipt.intentId;
      const running = inflight.get(key);
      if (running) {
        if (running.fingerprint !== fingerprint) return Promise.reject(new PaymentRefused("dispatch_conflict", "A different payment for this TPA intent is already in flight (checkout, rail, payee or amount differ)."));
        return running.promise;
      }
      const promise = dispatch(rail, snap, frozenTarget, fingerprint, execute, reconcile).finally(() => inflight.delete(key));
      inflight.set(key, { fingerprint, promise });
      return promise;
    },
    async settled(checkoutId, reference) { return store.findSettled(checkoutId, reference); },
  };
  boundLedgers.add(ledger);
  return Object.freeze(ledger);
}

/* --------------------------- Airwallex / Airi (Kit 09) --------------------------- */
/** Mock rail: needs a permission-bound ledger (memory store is fine, nothing real moves). */
export function createMockAiriAdapter(ledger: DispatchLedger): PaymentAdapter & { attempts: Map<string, PaymentResult> } {
  const attempts = new Map<string, PaymentResult>();
  return {
    rail: "airwallex-airi", mode: "mock", attempts,
    pay(request) {
      let bound: DispatchLedger, snap: FrozenPaymentRequest;
      try { bound = requireBoundLedger(ledger, false, "airwallex-airi"); snap = snapshotRequest(request); } catch (error) { return Promise.reject(error); }
      // Kit 09 rule: before any retry, check the prior attempt. One mandate, one payment (enforced by the ledger).
      return bound.run("airwallex-airi", snap, { payee: snap.merchant.id, railAmount: snap.amountBaseUnits }, async ({ request: r }) => {
      // TODO(airi): `airi` CLI calls once allowlisted: select payment method, create payment mandate bound
      // to merchant + amount, fetch one-time credentials (kept server side, never in model context), then
      // report the merchant result back. Exact subcommands come from the Airi CLI repo after access.
      const paymentMandateId = `pm_mock_${digest(r.receipt.mandateHash).slice(0, 16)}`;
      const result: PaymentResult = {
        rail: "airwallex-airi", mode: "mock", status: "succeeded", reference: `awx_mock_${digest(r.receipt.intentId, r.checkoutId).slice(0, 20)}`,
        detail: { paymentMandateId, oneTimeCard: "**** **** **** 0000 (mock, never exposed to the agent)", amount: (Number(r.amountBaseUnits) / 100).toFixed(2), currency: r.currency },
      };
      attempts.set(r.receipt.intentId, result);
      return result;
      });
    },
  };
}

/**
 * Airwallex sandbox REST (payment acceptance). Untested until we have sandbox keys.
 * Needs AWX_CLIENT_ID, AWX_API_KEY, and AWX_TEST_CARD_NUMBER (the sandbox test card from the guide).
 * Amounts are MAJOR units on Airwallex (cents / 100).
 * Every call goes through the durable, permission-bound dispatch ledger: the consumed intent is verified and the
 * dispatch reserved before any network call, and the deterministic create request_id is recorded ("sent") after
 * login and before the payment intent is created, so an unknown outcome is never retried blindly.
 */
export function createAirwallexSandboxAdapter(ledger: DispatchLedger, env = process.env, fetchImpl: typeof fetch = fetch): PaymentAdapter {
  const base = "https://api.sandbox.airwallex.com/api/v1";
  return {
    rail: "airwallex-sandbox", mode: "sandbox",
    pay(request) {
      let bound: DispatchLedger, snap: FrozenPaymentRequest;
      try { bound = requireBoundLedger(ledger, true, "airwallex-sandbox"); snap = snapshotRequest(request); } catch (error) { return Promise.reject(error); }
      if (!env.AWX_CLIENT_ID || !env.AWX_API_KEY || !env.AWX_TEST_CARD_NUMBER) return Promise.reject(new PaymentRefused("not_configured", "Set AWX_CLIENT_ID, AWX_API_KEY and AWX_TEST_CARD_NUMBER to use the Airwallex sandbox."));
      return bound.run("airwallex-sandbox", snap, { payee: snap.merchant.id, railAmount: snap.amountBaseUnits }, async ({ request: r, onSigned }) => {
        const createId = randomUUIDFrom(r.receipt.intentId, "create");
        const login = await fetchImpl(`${base}/authentication/login`, { method: "POST", headers: { "x-client-id": env.AWX_CLIENT_ID!, "x-api-key": env.AWX_API_KEY! } });
        const { token } = await login.json() as { token: string };
        await onSigned(`awx_request_${createId}`); // durable marker before any call that can move money
        const auth = { Authorization: `Bearer ${token}`, "content-type": "application/json" };
        // request_id is derived from the TPA intent so a retry of the same payment reuses it (Airwallex dedupes).
        const created = await fetchImpl(`${base}/pa/payment_intents/create`, { method: "POST", headers: auth, body: JSON.stringify({
          request_id: createId, amount: Number(r.amountBaseUnits) / 100, currency: r.currency,
          merchant_order_id: r.checkoutId, metadata: { tpa_mandate_hash: r.receipt.mandateHash } }) });
        const intent = await created.json() as { id: string };
        const confirmed = await fetchImpl(`${base}/pa/payment_intents/${intent.id}/confirm`, { method: "POST", headers: auth, body: JSON.stringify({
          request_id: randomUUIDFrom(r.receipt.intentId, "confirm"),
          payment_method: { type: "card", card: { number: env.AWX_TEST_CARD_NUMBER, expiry_month: "12", expiry_year: "2030", cvc: "123" } } }) });
        const body = await confirmed.json() as { status?: string };
        if (body.status !== "SUCCEEDED") throw new PaymentRefused("airwallex_status", `Airwallex returned status ${body.status ?? "unknown"}.`);
        return { rail: "airwallex-sandbox", mode: "sandbox", status: "succeeded", reference: intent.id, detail: { status: body.status } };
      });
    },
  };
}
function randomUUIDFrom(...parts: string[]) {
  const h = digest(...parts);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/* ------------------------------- Metal (USDZ) ------------------------------- */
export const METAL_TESTNET = { chainId: 63825, usdz: "0x000000000000000000000000000000000000b5d5", decimals: 18 } as const;
/** Minimal chain surface the adapter needs. Real implementation: viem public/wallet client on METAL_RPC_URL. */
export interface MetalClient {
  readonly chainId: number;
  readonly mode: "mock" | "testnet";
  balanceOf(address: string): Promise<bigint>;
  /** MIP20 transfer of USDZ base units; resolves once the transfer is final. */
  transfer(input: { from: string; to: string; amount: bigint; memo: string; onSigned?: (txHash: string) => Promise<void> }): Promise<{ txHash: string; finalized: boolean }>;
  /** Look up an already signed transfer by hash; null when it is not (yet) a settled matching transfer. Never resends. */
  reconcile?(input: { txHash: string; from: string; to: string; amount: bigint }): Promise<{ txHash: string; finalized: boolean } | null>;
}
export function createMockMetalClient(balances: Record<string, bigint> = {}): MetalClient & { balances: Map<string, bigint> } {
  const map = new Map(Object.entries(balances).map(([a, b]) => [a.toLowerCase(), b]));
  let nonce = 0;
  const sent = new Set<string>();
  return {
    chainId: METAL_TESTNET.chainId, mode: "mock", balances: map,
    async reconcile({ txHash }) { return sent.has(txHash) ? { txHash, finalized: true } : null; },
    async balanceOf(address) { return map.get(address.toLowerCase()) ?? 0n; },
    async transfer({ from, to, amount, memo, onSigned }) {
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
/** cents -> USDZ base units (18 decimals): 1 cent = 10^16. */
export const centsToUsdz = (cents: string) => BigInt(cents) * 10n ** 16n;

/**
 * USDZ rail. The payee is the allowlisted address for the merchant and the amount is derived from the frozen request
 * snapshot; the transfer itself uses only the ledger's frozen target. A testnet client requires a durable ledger, and
 * a transfer that is not final is never reported as settled (the row stays "sent" for reconcile).
 */
export function createMetalUsdzAdapter(client: MetalClient, payer: string, merchantAddresses: Record<string, string>, ledger: DispatchLedger): PaymentAdapter {
  const live = client.mode !== "mock";
  const allowlist = Object.freeze({ ...merchantAddresses });
  const sameTx = (a: unknown, b: string) => typeof a === "string" && a.toLowerCase() === b.toLowerCase();
  const referenceMismatch = (recorded: string) => new PaymentRefused("dispatch_result_mismatch", `Metal: rail reference does not match the recorded transaction ${recorded}; not marking it paid, not resending.`);
  const toResult = (tx: { txHash: string; finalized: boolean }, target: Readonly<DispatchTarget>): PaymentResult => {
    if (tx.finalized !== true) throw new PaymentRefused("metal_not_final", `Metal: ${tx.txHash} is not final yet; keep pending, do not resend.`);
    return { rail: "metal-usdz", mode: client.mode, status: "succeeded", reference: tx.txHash,
      detail: { chainId: String(client.chainId), token: `USDZ ${METAL_TESTNET.usdz}`, amountBaseUnits: target.railAmount, to: target.payee, finalized: "true" } };
  };
  return {
    rail: "metal-usdz", mode: client.mode,
    pay(request) {
      let bound: DispatchLedger, snap: FrozenPaymentRequest, target: Readonly<DispatchTarget>;
      try {
        bound = requireBoundLedger(ledger, live, "metal-usdz");
        snap = snapshotRequest(request);
        const to = Object.prototype.hasOwnProperty.call(allowlist, snap.merchant.id) ? allowlist[snap.merchant.id] : undefined;
        if (!to) throw new PaymentRefused("unknown_merchant_address", `No Metal address on file for merchant ${snap.merchant.id}.`);
        target = Object.freeze({ payee: to, railAmount: centsToUsdz(snap.amountBaseUnits).toString() });
      } catch (error) { return Promise.reject(error); }
      const reconcile = client.reconcile ? async (record: DispatchRecord) => {
        if (!record.txHash) return null;
        const tx = await client.reconcile!({ txHash: record.txHash, from: payer, to: record.payee, amount: BigInt(record.railAmount) });
        if (tx && !sameTx(tx.txHash, record.txHash)) throw referenceMismatch(record.txHash);
        return tx && tx.finalized === true ? toResult(tx, { payee: record.payee, railAmount: record.railAmount }) : null;
      } : undefined;
      return bound.run("metal-usdz", snap, target, async ({ onSigned, target: t, request: r }) => {
        let recorded: string | undefined;
        const tx = await client.transfer({ from: payer, to: t.payee, amount: BigInt(t.railAmount), memo: r.receipt.mandateHash,
          onSigned: async txHash => { await onSigned(txHash); recorded = txHash; } });
        // Only the hash the ledger recorded before broadcast may settle the row; anything else stays "sent" for reconcile.
        if (!recorded || !sameTx(tx.txHash, recorded)) throw referenceMismatch(recorded ?? "none");
        return toResult(tx, t);
      }, reconcile);
    },
  };
}
