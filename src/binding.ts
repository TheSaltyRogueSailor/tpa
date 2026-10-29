import { createHash } from "node:crypto";
import { z } from "zod";

/**
 * TPA v3.1 checkout binding (proposal: .scratch/checkout-binding-proposal.md; decisions from review 2026-10-29).
 *
 * Two hashes are computed over closed, ordered tuples (never arbitrary caller JSON) and signed INSIDE the v3.1
 * mandate tuple (src/domain.ts):
 *   checkoutFingerprint = SHA-256("TPA-CHECKOUT-FP/3.1\n" + JSON(checkout tuple))
 *   paymentTargetHash   = SHA-256("TPA-PAYMENT-TARGET/3.1\n" + JSON(target tuple))
 * All amounts are base-unit decimal strings; identifiers are normalized (lowercase hex, tagged payees).
 * This module has no runtime imports from domain.ts (domain.ts imports it).
 */
export const TPA_CHECKOUT_FP_DOMAIN = "TPA-CHECKOUT-FP/3.1" as const;
export const TPA_PAYMENT_TARGET_DOMAIN = "TPA-PAYMENT-TARGET/3.1" as const;
export const TPA_DISPATCH_SNAPSHOT_VERSION = "tpa-dispatch-snapshot/3.1" as const;

export const TPA_QUOTE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const units = /^(0|[1-9][0-9]{0,17})$/;
const positive = /^[1-9][0-9]{0,77}$/;
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

/* ------------------------------ checkout fingerprint ------------------------------ */

/** Exactly what the checkout fingerprint covers. Built only from normalizeTpaCheckout output plus the server quote. */
export type TpaCheckoutFingerprintInput = Readonly<{
  currency: "USD";
  merchant: Readonly<{ id: string; name: string }>;
  recipient: string;
  /** Strictly ascending by SKU, one line per SKU. */
  items: readonly Readonly<{ sku: string; qty: number; unitPriceBaseUnits: string }>[];
  shipping: Readonly<{ method: string; costBaseUnits: string }>;
  subtotalBaseUnits: string;
  taxBaseUnits: string;
  totalBaseUnits: string;
  /** Merchant-scoped trusted server quote (today: the TAP checkoutId), resolved server side, never from the agent. */
  quote: Readonly<{ merchantId: string; quoteId: string }>;
}>;

export class TpaBindingError extends Error {
  constructor(readonly reason: string) { super(reason); this.name = "TpaBindingError"; }
}

export function checkoutFingerprintTuple(input: TpaCheckoutFingerprintInput): unknown[] {
  if (input.currency !== "USD") throw new TpaBindingError("fingerprint_currency");
  if (input.quote.merchantId !== input.merchant.id || !TPA_QUOTE_ID.test(input.quote.quoteId)) throw new TpaBindingError("fingerprint_quote");
  let subtotal = 0n;
  for (let i = 0; i < input.items.length; i += 1) {
    const item = input.items[i]!;
    if (!Number.isSafeInteger(item.qty) || item.qty < 1 || !units.test(item.unitPriceBaseUnits)) throw new TpaBindingError("fingerprint_item");
    if (i > 0 && !(input.items[i - 1]!.sku < item.sku)) throw new TpaBindingError("fingerprint_item_order");
    subtotal += BigInt(item.qty) * BigInt(item.unitPriceBaseUnits);
  }
  if (input.items.length < 1 || ![input.shipping.costBaseUnits, input.subtotalBaseUnits, input.taxBaseUnits].every(v => units.test(v)) || !positive.test(input.totalBaseUnits)) throw new TpaBindingError("fingerprint_amount");
  if (BigInt(input.subtotalBaseUnits) !== subtotal || BigInt(input.totalBaseUnits) !== subtotal + BigInt(input.shipping.costBaseUnits) + BigInt(input.taxBaseUnits)) throw new TpaBindingError("fingerprint_total");
  return [
    TPA_CHECKOUT_FP_DOMAIN, input.currency, input.merchant.id, input.merchant.name, input.recipient,
    input.items.map(item => [item.sku, item.qty, item.unitPriceBaseUnits]),
    input.shipping.method, input.shipping.costBaseUnits, input.subtotalBaseUnits, input.taxBaseUnits, input.totalBaseUnits,
    input.quote.merchantId, input.quote.quoteId,
  ];
}

export function checkoutFingerprint(input: TpaCheckoutFingerprintInput): string {
  return sha256(`${TPA_CHECKOUT_FP_DOMAIN}\n${JSON.stringify(checkoutFingerprintTuple(input))}`);
}

/* --------------------------------- payment target --------------------------------- */

export const TPA_TARGET_RAILS = ["metal-usdz", "airwallex-airi"] as const;
export const METAL_USDZ_ASSET = "erc20:0x000000000000000000000000000000000000b5d5" as const;

/**
 * Per-rail constants. Airwallex: the real Airi/Airwallex destination contract is not documented yet, so the only
 * Airwallex target is an explicit MOCK fixture; anything else is refused (destination_unknown).
 */
const RAIL_RULES = {
  "metal-usdz": { networks: /^evm:63825$/, asset: METAL_USDZ_ASSET, decimals: 18, payee: /^evm:0x[0-9a-f]{40}$/, feeAsset: METAL_USDZ_ASSET },
  "airwallex-airi": { networks: /^airwallex:mock-fixture$/, asset: "iso4217:USD", decimals: 2, payee: /^awx-mock-fixture:[a-z0-9_-]{1,64}$/, feeAsset: "iso4217:USD" },
} as const;

export const tpaPaymentTargetSchema = z.object({
  rail: z.enum(TPA_TARGET_RAILS),
  network: z.string().max(64),
  asset: z.string().max(80),
  decimals: z.number().int().min(0).max(36),
  /** The checkout recipient the target was resolved for (the mandate recipient). */
  recipientRef: z.string().min(1).max(64),
  /** Tagged, rail-specific actual payee: "evm:0x<40 lowercase hex>" or "awx-mock-fixture:<id>". */
  payee: z.string().max(140),
  sourceCurrency: z.literal("USD"),
  sourceAmountBaseUnits: z.string().regex(positive),
  /** Exact amount the rail moves, in `asset` base units: source * rateNumerator / rateDenominator, no rounding. */
  railAmount: z.string().regex(positive),
  conversion: z.object({
    id: z.string().regex(/^[a-z0-9][a-z0-9._:-]{0,63}$/),
    rateNumerator: z.string().regex(positive),
    rateDenominator: z.string().regex(positive),
    /** Unix seconds; locked at approval, zero tolerance. */
    expires: z.number().int().positive(),
  }).strict(),
  /** Maximum network/service fee the payer may spend, in `fee.asset` base units. "0" means no fee may be charged. */
  fee: z.object({ asset: z.string().max(80), capBaseUnits: z.string().regex(units) }).strict(),
}).strict().superRefine((t, ctx) => {
  const rule = RAIL_RULES[t.rail];
  const bad = (field: string) => ctx.addIssue({ code: "custom", message: `target ${field} is not valid for ${t.rail}`, path: [field] });
  if (!rule.networks.test(t.network)) bad("network");
  if (t.asset !== rule.asset) bad("asset");
  if (t.decimals !== rule.decimals) bad("decimals");
  if (!rule.payee.test(t.payee)) bad("payee");
  if (t.fee.asset !== rule.feeAsset) bad("fee");
  if (t.rail === "airwallex-airi" && t.fee.capBaseUnits !== "0") bad("fee");
  const num = BigInt(t.conversion.rateNumerator), den = BigInt(t.conversion.rateDenominator);
  const scaled = BigInt(t.sourceAmountBaseUnits) * num;
  if (scaled % den !== 0n || (scaled / den).toString() !== t.railAmount) bad("railAmount");
});
export type TpaPaymentTarget = Readonly<z.infer<typeof tpaPaymentTargetSchema>>;

export function paymentTargetTuple(value: unknown): unknown[] {
  const t = tpaPaymentTargetSchema.parse(value);
  return [
    TPA_PAYMENT_TARGET_DOMAIN, t.rail, t.network, t.asset, String(t.decimals), t.recipientRef, t.payee,
    t.sourceCurrency, t.sourceAmountBaseUnits, t.railAmount,
    t.conversion.id, t.conversion.rateNumerator, t.conversion.rateDenominator, String(t.conversion.expires),
    t.fee.asset, t.fee.capBaseUnits,
  ];
}

export function paymentTargetHash(value: unknown): string {
  return sha256(`${TPA_PAYMENT_TARGET_DOMAIN}\n${JSON.stringify(paymentTargetTuple(value))}`);
}

/** Untagged payee as the rail uses it (Metal: 0x address; Airwallex mock: the fixture tag itself). */
export function railPayee(target: TpaPaymentTarget): string {
  return target.rail === "metal-usdz" ? target.payee.slice("evm:".length) : target.payee;
}

/* --------------------------------- dispatch snapshot --------------------------------- */

const snapshotItem = z.object({ sku: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/), qty: z.number().int().min(1).max(10_000), unitPriceBaseUnits: z.string().regex(units) }).strict();
/**
 * What tpa_payment_dispatches.snapshotJson holds for a v3.1 row: the immutable signed terms the row may execute or
 * reconcile against. Both hashes are recomputed from it on every read and must equal the row columns and the
 * signed mandate.
 */
export const tpaDispatchSnapshotSchema = z.object({
  v: z.literal(TPA_DISPATCH_SNAPSHOT_VERSION),
  mandateVersion: z.literal("3.1"),
  checkout: z.object({
    currency: z.literal("USD"),
    merchant: z.object({ id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/), name: z.string().min(1).max(120) }).strict(),
    recipient: z.string().min(1).max(64),
    items: z.array(snapshotItem).min(1).max(50),
    shipping: z.object({ method: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/), costBaseUnits: z.string().regex(units) }).strict(),
    subtotalBaseUnits: z.string().regex(units),
    taxBaseUnits: z.string().regex(units),
    totalBaseUnits: z.string().regex(positive),
    quote: z.object({ merchantId: z.string().max(64), quoteId: z.string().regex(TPA_QUOTE_ID) }).strict(),
  }).strict(),
  target: tpaPaymentTargetSchema,
  checkoutFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  paymentTargetHash: z.string().regex(/^[a-f0-9]{64}$/),
}).strict().superRefine((s, ctx) => {
  try { if (checkoutFingerprint(s.checkout) !== s.checkoutFingerprint) ctx.addIssue({ code: "custom", message: "checkoutFingerprint", path: ["checkoutFingerprint"] }); }
  catch { ctx.addIssue({ code: "custom", message: "checkout", path: ["checkout"] }); }
  if (paymentTargetHash(s.target) !== s.paymentTargetHash) ctx.addIssue({ code: "custom", message: "paymentTargetHash", path: ["paymentTargetHash"] });
  if (s.target.recipientRef !== s.checkout.recipient || s.target.sourceAmountBaseUnits !== s.checkout.totalBaseUnits) ctx.addIssue({ code: "custom", message: "target terms", path: ["target"] });
});
export type TpaDispatchSnapshot = Readonly<z.infer<typeof tpaDispatchSnapshotSchema>>;
