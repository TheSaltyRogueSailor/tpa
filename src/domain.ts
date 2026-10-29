import { z } from "zod";
import { TPA_QUOTE_ID, checkoutFingerprint, paymentTargetHash, paymentTargetTuple, tpaPaymentTargetSchema } from "./binding.js";

/** Explicit product boundary for this authorization pilot. */
export const TPA_MODE = {
  mode: "authorization-pilot",
  paymentExecution: false,
  onChainSubmission: false,
  independentLiveness: "not-configured",
  identityClaim: "registered-credential-control",
} as const;

export const TPA_TTL_SECONDS = 300;
export const TPA_CEREMONY_TTL_MS = 120_000;
export const TPA_CURRENCIES = ["USD", "DOGE"] as const;

const MAX_UINT256 = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935");
const amount = z
  .string()
  .regex(/^[1-9][0-9]{0,77}$/)
  .refine(value => BigInt(value) <= MAX_UINT256, "Amount is invalid or too large.");

export const tpaTransferInput = z.object({
  currency: z.enum(TPA_CURRENCIES),
  amountBaseUnits: amount,
  recipient: z.string().min(1).max(64),
  consent: z.literal(true),
}).strict();
export type TpaTransferInput = z.infer<typeof tpaTransferInput>;

/**
 * This is intentionally the original immutable authorization protocol domain.
 * Do not change `ledgerDomain`, type, version, or action for existing evidence.
 * Version 2.0 is the LEGACY transfer mandate: it binds only issuer, currency,
 * network, amount, recipient and a zero fee. New intents use version 3.0.
 */
export const tpaTransferMandateSchema = z.object({
  type: z.literal("TPA-mandate"),
  version: z.literal("2.0"),
  action: z.literal("transfer-authorization-pilot"),
  issuerUserId: z.number().int().positive(),
  currency: z.enum(TPA_CURRENCIES),
  paymentNetwork: z.enum(["internal-usd-pilot", "dogecoin-mainnet"]),
  amountBaseUnits: amount,
  recipient: z.string().min(1).max(64),
  feeBaseUnits: z.literal("0"),
  nonce: z.string().regex(/^[a-f0-9]{64}$/),
  issuedAt: z.number().int().nonnegative(),
  expires: z.number().int().positive(),
  scope: z.literal("single_use"),
  ledgerDomain: z.literal("dingdong-tpa/rootstock-testnet/attestation-v2"),
}).strict().superRefine((mandate, context) => {
  if (mandate.expires <= mandate.issuedAt || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) {
    context.addIssue({ code: "custom", message: "Invalid mandate lifetime." });
  }
  if ((mandate.currency === "USD") !== (mandate.paymentNetwork === "internal-usd-pilot")) {
    context.addIssue({ code: "custom", message: "Currency and network differ." });
  }
  if (mandate.currency === "USD" && !/^user:[1-9][0-9]{0,9}$/.test(mandate.recipient)) {
    context.addIssue({ code: "custom", message: "USD pilot recipient must be a named internal account reference." });
  }
});
export type TpaTransferMandate = z.infer<typeof tpaTransferMandateSchema>;

/* ------------------------------------------------------------------------- */
/* Version 3.0: checkout mandate binding merchant, line items, shipping, tax. */
/* All money is an integer count of currency base units held in a string.     */
/* ------------------------------------------------------------------------- */

export const TPA_MAX_LINE_ITEMS = 50;
export const TPA_MAX_ITEM_QTY = 10_000;
export const TPA_CHECKOUT_LEDGER_DOMAIN = "dingdong-tpa/rootstock-testnet/attestation-v3" as const;

/** Non-negative integer base units, at most 18 digits (no floats, no exponent, no sign). */
const componentUnits = z.string().regex(/^(0|[1-9][0-9]{0,17})$/, "Expected a non-negative integer base-unit string.");
/** Display text bound into the mandate: exact NFC, no control characters, no surrounding whitespace. */
const boundText = z.string().min(1).max(120).refine(
  value => value === value.normalize("NFC") && value.trim() === value && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value),
  "Text must be NFC-normalized, trimmed and free of control characters.",
);
export const tpaMerchant = z.object({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/),
  name: boundText,
}).strict();
export const tpaLineItem = z.object({
  sku: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/),
  qty: z.number().int().min(1).max(TPA_MAX_ITEM_QTY),
  unitPriceBaseUnits: componentUnits,
}).strict();
export const tpaShipping = z.object({
  method: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/),
  costBaseUnits: componentUnits,
}).strict();
export type TpaMerchant = z.infer<typeof tpaMerchant>;
export type TpaLineItem = z.infer<typeof tpaLineItem>;
export type TpaShipping = z.infer<typeof tpaShipping>;

function itemsSubtotal(items: readonly TpaLineItem[]): bigint {
  return items.reduce((sum, item) => sum + BigInt(item.qty) * BigInt(item.unitPriceBaseUnits), 0n);
}

export const tpaCheckoutMandateSchema = z.object({
  type: z.literal("TPA-mandate"),
  version: z.literal("3.0"),
  action: z.literal("checkout-authorization"),
  issuerUserId: z.number().int().positive(),
  currency: z.enum(TPA_CURRENCIES),
  paymentNetwork: z.enum(["internal-usd-pilot", "dogecoin-mainnet"]),
  merchant: tpaMerchant,
  /** Canonical order: strictly ascending by SKU (one line per SKU). */
  items: z.array(tpaLineItem).min(1).max(TPA_MAX_LINE_ITEMS),
  shipping: tpaShipping,
  subtotalBaseUnits: componentUnits,
  taxBaseUnits: componentUnits,
  /** The checkout total: subtotal + shipping + tax. This is the amount authorized to move. */
  amountBaseUnits: amount,
  recipient: z.string().min(1).max(64),
  feeBaseUnits: z.literal("0"),
  nonce: z.string().regex(/^[a-f0-9]{64}$/),
  issuedAt: z.number().int().nonnegative(),
  expires: z.number().int().positive(),
  scope: z.literal("single_use"),
  ledgerDomain: z.literal(TPA_CHECKOUT_LEDGER_DOMAIN),
}).strict().superRefine((mandate, context) => {
  if (mandate.expires <= mandate.issuedAt || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) {
    context.addIssue({ code: "custom", message: "Invalid mandate lifetime." });
  }
  if ((mandate.currency === "USD") !== (mandate.paymentNetwork === "internal-usd-pilot")) {
    context.addIssue({ code: "custom", message: "Currency and network differ." });
  }
  if (mandate.currency === "USD" && !/^user:[1-9][0-9]{0,9}$/.test(mandate.recipient)) {
    context.addIssue({ code: "custom", message: "USD pilot recipient must be a named internal account reference." });
  }
  for (let index = 1; index < mandate.items.length; index += 1) {
    if (!(mandate.items[index - 1]!.sku < mandate.items[index]!.sku)) {
      context.addIssue({ code: "custom", message: "Line items must be in canonical SKU order with no duplicate SKU." });
      break;
    }
  }
  const subtotal = itemsSubtotal(mandate.items);
  if (BigInt(mandate.subtotalBaseUnits) !== subtotal) context.addIssue({ code: "custom", message: "Subtotal does not equal the sum of line items." });
  if (BigInt(mandate.amountBaseUnits) !== subtotal + BigInt(mandate.shipping.costBaseUnits) + BigInt(mandate.taxBaseUnits)) {
    context.addIssue({ code: "custom", message: "Total does not equal subtotal + shipping + tax." });
  }
});
export type TpaCheckoutMandate = z.infer<typeof tpaCheckoutMandateSchema>;

/* ------------------------------------------------------------------------- */
/* Version 3.1: bound checkout mandate. Everything in 3.0 plus the trusted     */
/* server quote, the frozen payment target, and both binding hashes, all      */
/* inside the signed canonical tuple. 2.0 and 3.0 bytes and domains unchanged. */
/* ------------------------------------------------------------------------- */

export const TPA_BOUND_CHECKOUT_LEDGER_DOMAIN = "dingdong-tpa/checkout-binding/attestation-v3.1" as const;

export const tpaBoundCheckoutMandateSchema = z.object({
  type: z.literal("TPA-mandate"),
  version: z.literal("3.1"),
  action: z.literal("bound-checkout-authorization"),
  issuerUserId: z.number().int().positive(),
  currency: z.literal("USD"),
  merchant: tpaMerchant,
  items: z.array(tpaLineItem).min(1).max(TPA_MAX_LINE_ITEMS),
  shipping: tpaShipping,
  subtotalBaseUnits: componentUnits,
  taxBaseUnits: componentUnits,
  amountBaseUnits: amount,
  recipient: z.string().regex(/^user:[1-9][0-9]{0,9}$/),
  feeBaseUnits: z.literal("0"),
  /** Trusted server quote the owner reviewed (merchant scoped). `expires` is unix seconds. */
  quote: z.object({ merchantId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/), quoteId: z.string().regex(TPA_QUOTE_ID), expires: z.number().int().positive() }).strict(),
  /** Frozen before approval from trusted server resolution; never filled in later. */
  paymentTarget: tpaPaymentTargetSchema,
  checkoutFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  paymentTargetHash: z.string().regex(/^[a-f0-9]{64}$/),
  nonce: z.string().regex(/^[a-f0-9]{64}$/),
  issuedAt: z.number().int().nonnegative(),
  expires: z.number().int().positive(),
  scope: z.literal("single_use"),
  ledgerDomain: z.literal(TPA_BOUND_CHECKOUT_LEDGER_DOMAIN),
}).strict().superRefine((mandate, context) => {
  const issue = (message: string) => context.addIssue({ code: "custom", message });
  if (mandate.expires <= mandate.issuedAt || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) issue("Invalid mandate lifetime.");
  if (mandate.expires > mandate.quote.expires || mandate.expires > mandate.paymentTarget.conversion.expires) issue("Mandate outlives its quote or conversion.");
  for (let index = 1; index < mandate.items.length; index += 1) {
    if (!(mandate.items[index - 1]!.sku < mandate.items[index]!.sku)) { issue("Line items must be in canonical SKU order with no duplicate SKU."); break; }
  }
  const subtotal = itemsSubtotal(mandate.items);
  if (BigInt(mandate.subtotalBaseUnits) !== subtotal) issue("Subtotal does not equal the sum of line items.");
  if (BigInt(mandate.amountBaseUnits) !== subtotal + BigInt(mandate.shipping.costBaseUnits) + BigInt(mandate.taxBaseUnits)) issue("Total does not equal subtotal + shipping + tax.");
  if (mandate.quote.merchantId !== mandate.merchant.id) issue("Quote is not scoped to this merchant.");
  const target = mandate.paymentTarget;
  if (target.recipientRef !== mandate.recipient || target.sourceCurrency !== mandate.currency || target.sourceAmountBaseUnits !== mandate.amountBaseUnits) issue("Payment target does not match the checkout.");
  try { if (checkoutFingerprint(boundFingerprintInput(mandate)) !== mandate.checkoutFingerprint) issue("checkoutFingerprint does not match the checkout."); }
  catch { issue("checkoutFingerprint input is invalid."); }
  try { if (paymentTargetHash(target) !== mandate.paymentTargetHash) issue("paymentTargetHash does not match the payment target."); }
  catch { issue("paymentTarget is invalid."); }
});
export type TpaBoundCheckoutMandate = z.infer<typeof tpaBoundCheckoutMandateSchema>;

/** The fingerprint input of a signed 3.1 mandate (the same fields compareCheckoutToMandate checks, plus the quote). */
export function boundFingerprintInput(mandate: Pick<TpaBoundCheckoutMandate, "currency" | "merchant" | "recipient" | "items" | "shipping" | "subtotalBaseUnits" | "taxBaseUnits" | "amountBaseUnits" | "quote">) {
  return {
    currency: mandate.currency, merchant: { id: mandate.merchant.id, name: mandate.merchant.name }, recipient: mandate.recipient,
    items: mandate.items.map(i => ({ sku: i.sku, qty: i.qty, unitPriceBaseUnits: i.unitPriceBaseUnits })),
    shipping: { method: mandate.shipping.method, costBaseUnits: mandate.shipping.costBaseUnits },
    subtotalBaseUnits: mandate.subtotalBaseUnits, taxBaseUnits: mandate.taxBaseUnits, totalBaseUnits: mandate.amountBaseUnits,
    quote: { merchantId: mandate.quote.merchantId, quoteId: mandate.quote.quoteId },
  } as const;
}

/** Any persisted mandate: legacy transfer (2.0), checkout (3.0) or bound checkout (3.1). */
export const tpaMandateSchema = z.union([tpaTransferMandateSchema, tpaCheckoutMandateSchema, tpaBoundCheckoutMandateSchema]);
export type TpaMandate = TpaTransferMandate | TpaCheckoutMandate | TpaBoundCheckoutMandate;
export type TpaAnyCheckoutMandate = TpaCheckoutMandate | TpaBoundCheckoutMandate;

/**
 * True for every mandate that binds a checkout (3.0 and 3.1). Every lifecycle gate (store, demo memory store,
 * service) keys signed-only behavior off this, so 3.1 can never fall into the unsigned legacy path.
 */
export function isCheckoutMandate(mandate: TpaMandate): mandate is TpaAnyCheckoutMandate {
  return mandate.version === "3.0" || mandate.version === "3.1";
}
export function isBoundCheckoutMandate(mandate: TpaMandate): mandate is TpaBoundCheckoutMandate {
  return mandate.version === "3.1";
}

/** Fixed ordered tuple: no arbitrary JSON fields and no floating-point amounts. */
export function canonicalTpaMandate(value: unknown): string {
  const mandate = tpaMandateSchema.parse(value);
  if (mandate.version === "3.1") {
    // Explicit 3.1 branch with its own domain; the 2.0 and 3.0 tuples below are byte-for-byte unchanged.
    return JSON.stringify([
      mandate.type, mandate.version, mandate.action, mandate.issuerUserId, mandate.currency,
      [mandate.merchant.id, mandate.merchant.name],
      mandate.items.map(item => [item.sku, item.qty, item.unitPriceBaseUnits]),
      [mandate.shipping.method, mandate.shipping.costBaseUnits],
      mandate.subtotalBaseUnits, mandate.taxBaseUnits, mandate.amountBaseUnits, mandate.recipient, mandate.feeBaseUnits,
      [mandate.quote.merchantId, mandate.quote.quoteId, mandate.quote.expires],
      paymentTargetTuple(mandate.paymentTarget),
      mandate.checkoutFingerprint, mandate.paymentTargetHash,
      mandate.nonce, mandate.issuedAt, mandate.expires, mandate.scope, mandate.ledgerDomain,
    ]);
  }
  if (mandate.version === "2.0") {
    return JSON.stringify([
      mandate.type, mandate.version, mandate.action, mandate.issuerUserId, mandate.currency,
      mandate.paymentNetwork, mandate.amountBaseUnits, mandate.recipient, mandate.feeBaseUnits,
      mandate.nonce, mandate.issuedAt, mandate.expires, mandate.scope, mandate.ledgerDomain,
    ]);
  }
  if (mandate.version !== "3.0") throw new Error("Unknown TPA mandate version.");
  return JSON.stringify([
    mandate.type, mandate.version, mandate.action, mandate.issuerUserId, mandate.currency, mandate.paymentNetwork,
    [mandate.merchant.id, mandate.merchant.name],
    mandate.items.map(item => [item.sku, item.qty, item.unitPriceBaseUnits]),
    [mandate.shipping.method, mandate.shipping.costBaseUnits],
    mandate.subtotalBaseUnits, mandate.taxBaseUnits, mandate.amountBaseUnits,
    mandate.recipient, mandate.feeBaseUnits, mandate.nonce, mandate.issuedAt, mandate.expires, mandate.scope, mandate.ledgerDomain,
  ]);
}

/* ---------------------------- checkout input ---------------------------- */

/** What an agent/merchant presents: at creation (with consent) and again, unchanged, at use time. */
export const tpaCheckoutInput = z.object({
  currency: z.enum(TPA_CURRENCIES),
  recipient: z.string().min(1).max(64),
  merchant: tpaMerchant,
  items: z.array(tpaLineItem).min(1).max(TPA_MAX_LINE_ITEMS),
  shipping: tpaShipping,
  taxBaseUnits: componentUnits,
  totalBaseUnits: amount,
}).strict();
export type TpaCheckoutInput = z.infer<typeof tpaCheckoutInput>;
export const tpaCheckoutIntentInput = tpaCheckoutInput.extend({ consent: z.literal(true) }).strict();
export type TpaCheckoutIntentInput = z.infer<typeof tpaCheckoutIntentInput>;

export type TpaCheckoutRefusalReason =
  | "checkout_invalid" | "checkout_duplicate_sku" | "checkout_total_inconsistent" | "checkout_required"
  | "currency_mismatch" | "recipient_mismatch" | "merchant_mismatch" | "items_mismatch"
  | "shipping_mismatch" | "tax_mismatch" | "total_mismatch" | "quote_mismatch";

export class TpaCheckoutError extends Error {
  constructor(readonly reason: TpaCheckoutRefusalReason) { super(reason); this.name = "TpaCheckoutError"; }
}

export type TpaNormalizedCheckout = {
  currency: TpaCheckoutInput["currency"]; recipient: string; merchant: TpaMerchant; items: TpaLineItem[];
  shipping: TpaShipping; subtotalBaseUnits: string; taxBaseUnits: string; totalBaseUnits: string;
};

/** Validates and canonicalizes a checkout: items sorted by SKU, one line per SKU, total = subtotal + shipping + tax. */
export function normalizeTpaCheckout(value: unknown): TpaNormalizedCheckout {
  const parsed = tpaCheckoutInput.safeParse(value);
  if (!parsed.success) throw new TpaCheckoutError("checkout_invalid");
  const checkout = parsed.data;
  const items = [...checkout.items].map(item => ({ ...item })).sort((a, b) => (a.sku < b.sku ? -1 : a.sku > b.sku ? 1 : 0));
  for (let index = 1; index < items.length; index += 1) if (items[index - 1]!.sku === items[index]!.sku) throw new TpaCheckoutError("checkout_duplicate_sku");
  const subtotal = itemsSubtotal(items);
  if (subtotal + BigInt(checkout.shipping.costBaseUnits) + BigInt(checkout.taxBaseUnits) !== BigInt(checkout.totalBaseUnits)) {
    throw new TpaCheckoutError("checkout_total_inconsistent");
  }
  return {
    currency: checkout.currency, recipient: checkout.recipient, merchant: { id: checkout.merchant.id, name: checkout.merchant.name },
    items, shipping: { method: checkout.shipping.method, costBaseUnits: checkout.shipping.costBaseUnits },
    subtotalBaseUnits: subtotal.toString(), taxBaseUnits: checkout.taxBaseUnits, totalBaseUnits: checkout.totalBaseUnits,
  };
}

/** Exact match of an actual checkout against a signed checkout mandate. Returns the first difference, or null. */
export function compareCheckoutToMandate(mandate: TpaAnyCheckoutMandate, value: unknown): TpaCheckoutRefusalReason | null {
  let checkout: TpaNormalizedCheckout;
  try { checkout = normalizeTpaCheckout(value); }
  catch (error) { return error instanceof TpaCheckoutError ? error.reason : "checkout_invalid"; }
  if (checkout.merchant.id !== mandate.merchant.id || checkout.merchant.name !== mandate.merchant.name) return "merchant_mismatch";
  if (checkout.recipient !== mandate.recipient) return "recipient_mismatch";
  if (checkout.currency !== mandate.currency) return "currency_mismatch";
  if (JSON.stringify(checkout.items.map(i => [i.sku, i.qty, i.unitPriceBaseUnits])) !== JSON.stringify(mandate.items.map(i => [i.sku, i.qty, i.unitPriceBaseUnits]))) return "items_mismatch";
  if (checkout.shipping.method !== mandate.shipping.method || checkout.shipping.costBaseUnits !== mandate.shipping.costBaseUnits) return "shipping_mismatch";
  if (checkout.taxBaseUnits !== mandate.taxBaseUnits) return "tax_mismatch";
  if (checkout.totalBaseUnits !== mandate.amountBaseUnits || checkout.subtotalBaseUnits !== mandate.subtotalBaseUnits) return "total_mismatch";
  return null;
}

export function decimalToBaseUnits(value: string, currency: "USD" | "DOGE"): string {
  const digits = currency === "USD" ? 2 : 8;
  if (!new RegExp(`^(0|[1-9][0-9]*)(\\.[0-9]{1,${digits}})?$`).test(value)) {
    throw new Error(`Enter a positive amount with at most ${digits} decimal places.`);
  }
  const [whole, fraction = ""] = value.split(".");
  return amount.parse(BigInt(whole + fraction.padEnd(digits, "0")).toString());
}

export function formatBaseUnits(value: string, currency: "USD" | "DOGE"): string {
  if (!/^[0-9]+$/.test(value)) throw new Error("Invalid base-unit amount.");
  const digits = currency === "USD" ? 2 : 8;
  const padded = value.padStart(digits + 1, "0");
  return `${padded.slice(0, -digits)}.${padded.slice(-digits)}`;
}
