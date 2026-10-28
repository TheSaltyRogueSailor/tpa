/**
 * Payment rails behind one interface. Every adapter refuses to move money unless it is handed the
 * receipt of a successful TPA consume (the exact-match check against the passkey-approved mandate).
 *
 *   Airwallex (Kit 09): MockAiriAdapter now. Kit 09 pays through Airi CLI (allowlisted public beta):
 *     select payment method -> create payment mandate -> fetch one-time card credentials -> checkout
 *     -> report result. We have no Airi access yet, so the mock reproduces that sequence and its
 *     idempotency rule ("check the prior attempt before any retry").
 *   Airwallex sandbox REST: AirwallexSandboxAdapter, only used when AWX_CLIENT_ID / AWX_API_KEY are set.
 *     NOT exercised yet (no keys). Endpoints per airwallexdev.com/guide.
 *   Metal (USDZ on Metal testnet): MetalUsdzAdapter over a MetalClient. MockMetalClient now; the real
 *     client (viem + @metalntwx/metal-ts, chain 63825, USDZ at 0x...b5d5, 18 decimals) is a TODO until
 *     Metal testnet billing is back and we have an RPC endpoint + funded key.
 */
import { createHash } from "node:crypto";

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

/* --------------------------- Airwallex / Airi (Kit 09) --------------------------- */
export function createMockAiriAdapter(): PaymentAdapter & { attempts: Map<string, PaymentResult> } {
  const attempts = new Map<string, PaymentResult>();
  return {
    rail: "airwallex-airi", mode: "mock", attempts,
    async pay(request) {
      requireReceipt(request);
      // Kit 09 rule: before any retry, check the prior attempt. One mandate, one payment.
      const prior = attempts.get(request.receipt.intentId);
      if (prior) return prior;
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
  transfer(input: { from: string; to: string; amount: bigint; memo: string }): Promise<{ txHash: string; finalized: boolean }>;
}
export function createMockMetalClient(balances: Record<string, bigint> = {}): MetalClient & { balances: Map<string, bigint> } {
  const map = new Map(Object.entries(balances).map(([a, b]) => [a.toLowerCase(), b]));
  let nonce = 0;
  return {
    chainId: METAL_TESTNET.chainId, mode: "mock", balances: map,
    async balanceOf(address) { return map.get(address.toLowerCase()) ?? 0n; },
    async transfer({ from, to, amount, memo }) {
      const have = map.get(from.toLowerCase()) ?? 0n;
      if (amount <= 0n || have < amount) throw new PaymentRefused("insufficient_usdz", "Mock Metal: insufficient USDZ balance.");
      map.set(from.toLowerCase(), have - amount);
      map.set(to.toLowerCase(), (map.get(to.toLowerCase()) ?? 0n) + amount);
      nonce += 1;
      return { txHash: `0x${digest(from, to, amount.toString(), memo, String(nonce))}`, finalized: true };
    },
  };
}
/**
 * TODO(metal): real client once testnet billing works and we have an RPC endpoint and a funded key.
 *   pnpm add @metalntwx/metal-ts@0.3.2 viem@2.57.7
 *   env: METAL_RPC_URL=https://rpc-testnet.metalntwx.com/v1/<endpoint-id>, METAL_PAYER_KEY (never committed)
 *   balanceOf -> readContract(erc20Abi, USDZ, "balanceOf"); transfer -> writeContract(erc20Abi, "transfer"),
 *   then wait for the finalized receipt (see docs.metalntwx.com Settlement and Finality).
 */
export function createMetalTestnetClient(): MetalClient {
  throw new PaymentRefused("not_configured", "Metal testnet client not wired yet: needs METAL_RPC_URL and a funded USDZ key (testnet billing is down).");
}
/** cents -> USDZ base units (18 decimals): 1 cent = 10^16. */
export const centsToUsdz = (cents: string) => BigInt(cents) * 10n ** 16n;

export function createMetalUsdzAdapter(client: MetalClient, payer: string, merchantAddresses: Record<string, string>): PaymentAdapter {
  const done = new Map<string, PaymentResult>();
  return {
    rail: "metal-usdz", mode: client.mode,
    async pay(request) {
      requireReceipt(request);
      const prior = done.get(request.receipt.intentId);
      if (prior) return prior;
      const to = merchantAddresses[request.merchant.id];
      if (!to) throw new PaymentRefused("unknown_merchant_address", `No Metal address on file for merchant ${request.merchant.id}.`);
      const amount = centsToUsdz(request.amountBaseUnits);
      const tx = await client.transfer({ from: payer, to, amount, memo: request.receipt.mandateHash });
      const result: PaymentResult = { rail: "metal-usdz", mode: client.mode, status: "succeeded", reference: tx.txHash,
        detail: { chainId: String(client.chainId), token: `USDZ ${METAL_TESTNET.usdz}`, amountBaseUnits: amount.toString(), to, finalized: String(tx.finalized) } };
      done.set(request.receipt.intentId, result);
      return result;
    },
  };
}
