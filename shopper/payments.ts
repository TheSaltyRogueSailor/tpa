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
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
  const r = request.receipt;
  if (!r || r.consumed !== true || !/^[a-f0-9]{64}$/.test(r.mandateHash) || !r.intentId) throw new PaymentRefused("no_tpa_receipt", "No TPA consume receipt: payment rails only run after the mandate exact-match check.");
}
const digest = (...parts: string[]) => createHash("sha256").update(parts.join("|")).digest("hex");

/* ------------------------------ dispatch ledger ------------------------------ */
/**
 * One payment dispatch per consumed TPA intent. The ledger, not the caller's receipt, decides whether money may move:
 *   - binding: with `lookupIntent` (the TPA evidence reader), the intent must be stored as "consumed" under the same
 *     mandate hash (which covers items, shipping, tax and total), and the amount, currency and merchant id the rail is
 *     asked to pay must equal that server-signed 3.0 mandate. The checkout id, rail, allowlisted payee and rail amount
 *     are fixed by the first reservation and can never change for that intent.
 *   - atomic reservation: a durable TpaDispatchStore row (MySQL table tpa_payment_dispatches in a host deployment) is
 *     inserted before anything is signed; a duplicate insert loses. Concurrent calls in one process share one promise.
 *   - unknown outcome: the tx id is recorded ("sent") before broadcast. A "sent" row is never re-signed; a retry first
 *     reconciles by tx id and is refused (dispatch_pending_reconcile) until the rail confirms it.
 */
export type DispatchRecord = TpaDispatchRecord;
export type BoundIntent = { id: string; mandateHash: string; state: string; mandate: { version: string; currency: string; amountBaseUnits: string; merchant?: { id: string } } };
export type DispatchHooks = { onSigned(txHash: string): Promise<void> };
export type DispatchTarget = { payee: string; railAmount: string };
export interface DispatchLedger {
  run(rail: string, request: PaymentRequest, target: DispatchTarget, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: (record: DispatchRecord) => Promise<PaymentResult | null>): Promise<PaymentResult>;
  /** The settled dispatch for a checkout and rail reference, if any (what a merchant may trust). */
  settled(checkoutId: string, reference: string): Promise<DispatchRecord | null>;
}

/** Process-local store for unit tests and for adapters built without a store. Not durable. */
export function createMemoryDispatchStore(): TpaDispatchStore {
  const rows = new Map<string, DispatchRecord>();
  const copy = (r: DispatchRecord | undefined) => (r ? structuredClone(r) : null);
  return {
    async reserve(record) { const existing = rows.get(record.intentId); if (existing) return { created: false, existing: copy(existing)! }; rows.set(record.intentId, structuredClone({ ...record, status: "reserved" })); return { created: true }; },
    async get(intentId) { return copy(rows.get(intentId)); },
    async markSent(intentId, txHash, atMs) { const r = rows.get(intentId); if (!r || r.status !== "reserved") return false; Object.assign(r, { status: "sent", txHash, updatedAtMs: atMs }); return true; },
    async markSucceeded(intentId, result, atMs) { const r = rows.get(intentId); if (!r || r.status === "succeeded") return false; Object.assign(r, { status: "succeeded", result: structuredClone(result), updatedAtMs: atMs }); return true; },
    async release(intentId) { const r = rows.get(intentId); if (!r || r.status !== "reserved" || r.txHash) return false; rows.delete(intentId); return true; },
    async findSettled(checkoutId, reference) { for (const r of rows.values()) if (r.status === "succeeded" && r.checkoutId === checkoutId && r.result?.reference === reference) return copy(r); return null; },
  };
}

/**
 * Same contract persisted to a local JSON file (written atomically via rename after every transition). For the
 * standalone shopper demo, which runs on the in-memory TPA store and has no MySQL; hosts use createTpaDispatchStore.
 */
export function createFileDispatchStore(path: string): TpaDispatchStore {
  const memory = createMemoryDispatchStore();
  const load = (): DispatchRecord[] => (existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) as DispatchRecord[] : []);
  const ready = (async () => { for (const r of load()) { const { status, txHash, result, updatedAtMs } = r; await memory.reserve(r); if (txHash) await memory.markSent(r.intentId, txHash, updatedAtMs); if (status === "succeeded" && result) await memory.markSucceeded(r.intentId, result, updatedAtMs); } })();
  const ids = new Set(load().map(r => r.intentId));
  const save = async () => {
    const rows: DispatchRecord[] = [];
    for (const id of ids) { const r = await memory.get(id); if (r) rows.push(r); }
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(`${path}.tmp`, JSON.stringify(rows, null, 2), { mode: 0o600 });
    renameSync(`${path}.tmp`, path);
  };
  const wrap = <A extends unknown[], R>(fn: (...args: A) => Promise<R>, mutates: boolean) => async (...args: A) => { await ready; const out = await fn(...args); if (mutates) await save(); return out; };
  return {
    reserve: wrap(async (record: DispatchRecord) => { ids.add(record.intentId); return memory.reserve(record); }, true),
    get: wrap(memory.get, false),
    markSent: wrap(memory.markSent, true),
    markSucceeded: wrap(memory.markSucceeded, true),
    release: wrap(memory.release, true),
    findSettled: wrap(memory.findSettled, false),
  };
}

export function createDispatchLedger(options: { store?: TpaDispatchStore; lookupIntent?: (intentId: string) => Promise<BoundIntent | null>; now?: () => number } = {}): DispatchLedger {
  const now = options.now ?? Date.now;
  const store = options.store ?? createMemoryDispatchStore();
  const inflight = new Map<string, Promise<PaymentResult>>();

  async function bind(request: PaymentRequest) {
    if (!options.lookupIntent) return;
    const intent = await options.lookupIntent(request.receipt.intentId);
    const m = intent?.mandate;
    if (!intent || intent.state !== "consumed" || intent.mandateHash !== request.receipt.mandateHash || !m || m.version !== "3.0"
      || m.amountBaseUnits !== request.amountBaseUnits || m.currency !== request.currency || m.merchant?.id !== request.merchant.id) {
      throw new PaymentRefused("dispatch_not_bound", "Payment does not match a consumed, server-signed TPA mandate (amount, currency, merchant).");
    }
  }
  const sameDispatch = (r: DispatchRecord, rail: string, request: PaymentRequest, target: DispatchTarget) => r.mandateHash === request.receipt.mandateHash && r.checkoutId === request.checkoutId
    && r.rail === rail && r.amountBaseUnits === request.amountBaseUnits && r.currency === request.currency && r.merchantId === request.merchant.id && r.payee === target.payee && r.railAmount === target.railAmount;

  async function dispatch(rail: string, request: PaymentRequest, target: DispatchTarget, execute: (hooks: DispatchHooks) => Promise<PaymentResult>, reconcile?: (record: DispatchRecord) => Promise<PaymentResult | null>) {
    await bind(request);
    const at = now();
    const reserved = await store.reserve({ intentId: request.receipt.intentId, mandateHash: request.receipt.mandateHash, checkoutId: request.checkoutId, rail, merchantId: request.merchant.id,
      currency: request.currency, amountBaseUnits: request.amountBaseUnits, payee: target.payee, railAmount: target.railAmount, status: "reserved", createdAtMs: at, updatedAtMs: at });
    if (!reserved.created) {
      const existing = reserved.existing;
      if (!sameDispatch(existing, rail, request, target)) throw new PaymentRefused("dispatch_conflict", "This TPA intent was already dispatched for a different checkout, rail, payee or amount.");
      if (existing.status === "succeeded" && existing.result) return existing.result as PaymentResult;
      if (existing.status === "reserved") throw new PaymentRefused("dispatch_in_progress", "Another worker holds the dispatch reservation for this intent.");
      const settled = reconcile ? await reconcile(existing) : null;
      if (!settled) throw new PaymentRefused("dispatch_pending_reconcile", `A transaction for this intent was already signed (${existing.txHash ?? "unknown"}); not resending until it is reconciled.`);
      await store.markSucceeded(existing.intentId, settled, now());
      return settled;
    }
    let signedTx: string | undefined;
    try {
      const result = await execute({ onSigned: async txHash => {
        if (!(await store.markSent(request.receipt.intentId, txHash, now()))) throw new PaymentRefused("dispatch_conflict", "Dispatch reservation changed before broadcast; not sending.");
        signedTx = txHash;
      } });
      if (!(await store.markSucceeded(request.receipt.intentId, result, now()))) throw new PaymentRefused("dispatch_conflict", "Dispatch record changed while paying.");
      return result;
    } catch (error) {
      // Nothing signed: release so a retry is allowed. Signed: keep "sent" so a retry reconciles instead of resending.
      if (!signedTx) await store.release(request.receipt.intentId).catch(() => undefined);
      throw error;
    }
  }

  return {
    run(rail, request, target, execute, reconcile) {
      try { requireReceipt(request); } catch (error) { return Promise.reject(error); }
      const key = request.receipt.intentId;
      const running = inflight.get(key);
      if (running) return running;
      const p = dispatch(rail, request, target, execute, reconcile).finally(() => inflight.delete(key));
      inflight.set(key, p);
      return p;
    },
    async settled(checkoutId, reference) { return store.findSettled(checkoutId, reference); },
  };
}

/* --------------------------- Airwallex / Airi (Kit 09) --------------------------- */
export function createMockAiriAdapter(ledger: DispatchLedger = createDispatchLedger()): PaymentAdapter & { attempts: Map<string, PaymentResult> } {
  const attempts = new Map<string, PaymentResult>();
  return {
    rail: "airwallex-airi", mode: "mock", attempts,
    pay(request) {
      // Kit 09 rule: before any retry, check the prior attempt. One mandate, one payment (enforced by the ledger).
      return ledger.run("airwallex-airi", request, { payee: request.merchant?.id ?? "", railAmount: request.amountBaseUnits }, async () => {
      // TODO(airi): `airi` CLI calls once allowlisted: select payment method, create payment mandate bound
      // to merchant + amount, fetch one-time credentials (kept server side, never in model context), then
      // report the merchant result back. Exact subcommands come from the Airi CLI repo after access.
      const paymentMandateId = `pm_mock_${digest(request.receipt.mandateHash).slice(0, 16)}`;
      const result: PaymentResult = {
        rail: "airwallex-airi", mode: "mock", status: "succeeded", reference: `awx_mock_${digest(request.receipt.intentId, request.checkoutId).slice(0, 20)}`,
        detail: { paymentMandateId, oneTimeCard: "**** **** **** 0000 (mock, never exposed to the agent)", amount: (Number(request.amountBaseUnits) / 100).toFixed(2), currency: request.currency },
      };
      attempts.set(request.receipt.intentId, result);
      return result;
      });
    },
  };
}

/**
 * Airwallex sandbox REST (payment acceptance). Untested until we have sandbox keys.
 * Needs AWX_CLIENT_ID, AWX_API_KEY, and AWX_TEST_CARD_NUMBER (the sandbox test card from the guide).
 * Amounts are MAJOR units on Airwallex (cents / 100).
 */
export function createAirwallexSandboxAdapter(env = process.env, fetchImpl: typeof fetch = fetch): PaymentAdapter {
  const base = "https://api.sandbox.airwallex.com/api/v1";
  return {
    rail: "airwallex-sandbox", mode: "sandbox",
    async pay(request) {
      requireReceipt(request);
      if (!env.AWX_CLIENT_ID || !env.AWX_API_KEY || !env.AWX_TEST_CARD_NUMBER) throw new PaymentRefused("not_configured", "Set AWX_CLIENT_ID, AWX_API_KEY and AWX_TEST_CARD_NUMBER to use the Airwallex sandbox.");
      const login = await fetchImpl(`${base}/authentication/login`, { method: "POST", headers: { "x-client-id": env.AWX_CLIENT_ID, "x-api-key": env.AWX_API_KEY } });
      const { token } = await login.json() as { token: string };
      const auth = { Authorization: `Bearer ${token}`, "content-type": "application/json" };
      // request_id is derived from the TPA intent so a retry of the same payment reuses it (Airwallex dedupes).
      const created = await fetchImpl(`${base}/pa/payment_intents/create`, { method: "POST", headers: auth, body: JSON.stringify({
        request_id: randomUUIDFrom(request.receipt.intentId, "create"), amount: Number(request.amountBaseUnits) / 100, currency: request.currency,
        merchant_order_id: request.checkoutId, metadata: { tpa_mandate_hash: request.receipt.mandateHash } }) });
      const intent = await created.json() as { id: string };
      const confirmed = await fetchImpl(`${base}/pa/payment_intents/${intent.id}/confirm`, { method: "POST", headers: auth, body: JSON.stringify({
        request_id: randomUUIDFrom(request.receipt.intentId, "confirm"),
        payment_method: { type: "card", card: { number: env.AWX_TEST_CARD_NUMBER, expiry_month: "12", expiry_year: "2030", cvc: "123" } } }) });
      const body = await confirmed.json() as { status?: string };
      if (body.status !== "SUCCEEDED") throw new PaymentRefused("airwallex_status", `Airwallex returned status ${body.status ?? "unknown"}.`);
      return { rail: "airwallex-sandbox", mode: "sandbox", status: "succeeded", reference: intent.id, detail: { status: body.status } };
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

export function createMetalUsdzAdapter(client: MetalClient, payer: string, merchantAddresses: Record<string, string>, ledger: DispatchLedger = createDispatchLedger()): PaymentAdapter {
  const toResult = (tx: { txHash: string; finalized: boolean }, amount: bigint, to: string): PaymentResult => ({ rail: "metal-usdz", mode: client.mode, status: "succeeded", reference: tx.txHash,
    detail: { chainId: String(client.chainId), token: `USDZ ${METAL_TESTNET.usdz}`, amountBaseUnits: amount.toString(), to, finalized: String(tx.finalized) } });
  return {
    rail: "metal-usdz", mode: client.mode,
    pay(request) {
      const to = merchantAddresses[request.merchant?.id];
      const amount = () => centsToUsdz(request.amountBaseUnits);
      const reconcile = client.reconcile ? async (record: DispatchRecord) => {
        if (!record.txHash || !to) return null;
        const tx = await client.reconcile!({ txHash: record.txHash, from: payer, to, amount: amount() });
        return tx ? toResult(tx, amount(), to) : null;
      } : undefined;
      if (!to) return Promise.reject(new PaymentRefused("unknown_merchant_address", `No Metal address on file for merchant ${request.merchant?.id}.`));
      let railAmount: string;
      try { railAmount = amount().toString(); } catch { return Promise.reject(new PaymentRefused("invalid_amount", "Amount is not an integer number of cents.")); }
      return ledger.run("metal-usdz", request, { payee: to, railAmount }, async ({ onSigned }) => {
        if (!to) throw new PaymentRefused("unknown_merchant_address", `No Metal address on file for merchant ${request.merchant.id}.`);
        const tx = await client.transfer({ from: payer, to, amount: amount(), memo: request.receipt.mandateHash, onSigned });
        return toResult(tx, amount(), to);
      }, reconcile);
    },
  };
}
