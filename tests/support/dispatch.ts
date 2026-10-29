/**
 * Test-only v3.1 fixtures: real signed-shape bound checkout mandates (both hashes computed by src/binding.ts) and an
 * intent reader that reports them as consumed. Offline only: no provider, chain or network.
 */
import { createHash } from "node:crypto";
import {
  createAiriFixtureResolver, createDispatchLedger, createMemoryDispatchStore, createMetalTargetResolver,
  type BoundIntent, type DispatchLedger, type PaymentRequest,
} from "../../shopper/payments.js";
import { checkoutFingerprint, paymentTargetHash, type TpaPaymentTarget } from "../../src/binding.js";
import type { TpaDispatchStore } from "../../src/dispatch.js";
import {
  TPA_BOUND_CHECKOUT_LEDGER_DOMAIN, boundFingerprintInput, canonicalTpaMandate, normalizeTpaCheckout, tpaBoundCheckoutMandateSchema,
  type TpaBoundCheckoutMandate, type TpaCheckoutInput,
} from "../../src/domain.js";

export const PAYER = "0x0000000000000000000000000000000000000001";
export const PAYEE = "0x0000000000000000000000000000000000000002";
export const ONE_DOLLAR_USDZ = 10n ** 18n;
export const sha256 = (v: string) => createHash("sha256").update(v, "utf8").digest("hex");

/** A $1.00 checkout (one line, free shipping, no tax) so Metal rail amounts are a round 1e18. */
export const reviewCheckout = (over: Partial<TpaCheckoutInput> = {}): TpaCheckoutInput => ({
  currency: "USD", recipient: "user:7001", merchant: { id: "review-merchant", name: "Review merchant" },
  items: [{ sku: "REVIEW-1", qty: 1, unitPriceBaseUnits: "100" }], shipping: { method: "standard", costBaseUnits: "0" }, taxBaseUnits: "0", totalBaseUnits: "100",
  ...over,
});

export type Fixture = {
  intentId: string; quoteId: string; mandate: TpaBoundCheckoutMandate; mandateHash: string; checkout: TpaCheckoutInput;
  /** A fresh request object (callers may mutate it freely). */
  request(over?: Partial<PaymentRequest>): PaymentRequest;
  intent: BoundIntent;
};
export type FixtureOptions = {
  intentId?: string; quoteId?: string; rail?: "metal-usdz" | "airwallex-airi"; checkout?: TpaCheckoutInput; payee?: string;
  /** Unix seconds the mandate is issued at (default: now). */
  issuedAt?: number; ttlSeconds?: number; quoteTtlSeconds?: number; conversionTtlSeconds?: number;
  target?: (t: TpaPaymentTarget) => TpaPaymentTarget;
};

export function boundFixture(options: FixtureOptions = {}): Fixture {
  const intentId = options.intentId ?? "review-intent";
  const quoteId = options.quoteId ?? "review-quote";
  const checkoutInput = options.checkout ?? reviewCheckout();
  const checkout = normalizeTpaCheckout(structuredClone(checkoutInput));
  const issuedAt = options.issuedAt ?? Math.floor(Date.now() / 1000);
  const rail = options.rail ?? "metal-usdz";
  const resolverInput = { rail, merchant: checkout.merchant, recipientRef: checkout.recipient, currency: "USD" as const, sourceAmountBaseUnits: checkout.totalBaseUnits, nowSeconds: issuedAt };
  let target = rail === "metal-usdz"
    ? createMetalTargetResolver({ [checkout.merchant.id]: options.payee ?? PAYEE })(resolverInput)!
    : createAiriFixtureResolver({ [checkout.merchant.id]: "review-fixture" })(resolverInput)!;
  if (options.conversionTtlSeconds !== undefined) target = { ...target, conversion: { ...target.conversion, expires: issuedAt + options.conversionTtlSeconds } };
  if (options.target) target = options.target(target);
  const quote = { merchantId: checkout.merchant.id, quoteId, expires: issuedAt + (options.quoteTtlSeconds ?? 900) };
  const expires = Math.min(issuedAt + (options.ttlSeconds ?? 300), quote.expires, target.conversion.expires);
  const mandate = tpaBoundCheckoutMandateSchema.parse({
    type: "TPA-mandate", version: "3.1", action: "bound-checkout-authorization", issuerUserId: 1, currency: "USD",
    merchant: checkout.merchant, items: checkout.items, shipping: checkout.shipping, subtotalBaseUnits: checkout.subtotalBaseUnits, taxBaseUnits: checkout.taxBaseUnits,
    amountBaseUnits: checkout.totalBaseUnits, recipient: checkout.recipient, feeBaseUnits: "0", quote, paymentTarget: target,
    checkoutFingerprint: checkoutFingerprint(boundFingerprintInput({ ...checkout, currency: "USD", amountBaseUnits: checkout.totalBaseUnits, quote })),
    paymentTargetHash: paymentTargetHash(target), nonce: sha256(`nonce:${intentId}`), issuedAt, expires, scope: "single_use", ledgerDomain: TPA_BOUND_CHECKOUT_LEDGER_DOMAIN,
  });
  const mandateHash = sha256(canonicalTpaMandate(mandate));
  return {
    intentId, quoteId, mandate, mandateHash, checkout: checkoutInput,
    request: (over = {}) => ({ receipt: { consumed: true, intentId, mandateHash }, checkoutId: quoteId, checkout: structuredClone(checkoutInput), ...over }),
    intent: { id: intentId, mandateHash, state: "consumed", revokedAtMs: null, mandate },
  };
}

/** Test-only intent reader: reports each fixture's intent as consumed under exactly its signed mandate. */
export function consumedLookup(...fixtures: Fixture[]) {
  return async (intentId: string): Promise<BoundIntent | null> => {
    const f = fixtures.find(x => x.intentId === intentId);
    return f ? structuredClone(f.intent) : null;
  };
}
/** A permission-bound ledger for unit tests (memory store unless one is given). */
export function boundLedger(fixtures: Fixture[], store: TpaDispatchStore = createMemoryDispatchStore(), now?: () => number): DispatchLedger {
  return createDispatchLedger({ store, lookupIntent: consumedLookup(...fixtures), ...(now ? { now } : {}) });
}
