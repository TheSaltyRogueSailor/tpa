/**
 * TPA Shield pre-flight checks for AI agents.
 *
 * Every function here is pure and read-only: it reuses the TPA library's own validation and
 * exact-match logic (src/domain.ts, src/service.ts, src/dashboard.ts) and only returns a decision.
 * Nothing here signs, sends a transaction, touches a wallet, reads a secret or opens a network
 * connection. A "pass" means the terms are well formed and unchanged. It is NOT an approval:
 * real money movement still needs the owner's passkey-signed, single-use TPA mandate.
 */
import { z } from "zod";
import {
  TPA_CEREMONY_TTL_MS, TPA_CURRENCIES, TPA_MAX_ITEM_QTY, TPA_MAX_LINE_ITEMS, TPA_MODE, TPA_TTL_SECONDS,
  TpaCheckoutError, compareCheckoutToMandate, decimalToBaseUnits, normalizeTpaCheckout, tpaTransferInput,
  type TpaAnyCheckoutMandate, type TpaNormalizedCheckout,
} from "../src/domain.js";
import { describeReason } from "../src/dashboard.js";
import { TpaServiceError, validateRecipient } from "../src/service.js";

export const SHIELD_VERSION = "0.1.0";
export const PREFLIGHT_NOTE = "Pre-flight check only. A pass is not an approval: TPA still requires the owner's passkey on the exact terms, a server-signed single-use mandate, and an exact match at payment time.";

export type ShieldReason = { code: string; text: string };
export type ShieldDecision = {
  decision: "pass" | "block";
  check: "check_checkout" | "check_payment" | "check_transfer";
  reasons: ShieldReason[];
  checksRun: string[];
  normalized?: Record<string, unknown>;
  note: string;
};

/** Reason codes produced by the pre-flight tools that the dashboard text table does not already cover. */
const SHIELD_REASON_TEXT: Readonly<Record<string, string>> = {
  checkout_invalid: "Checkout is missing a field, has an unknown field, or has a value in the wrong format",
  checkout_duplicate_sku: "Checkout lists the same SKU on more than one line",
  checkout_total_inconsistent: "Total does not equal items plus shipping plus tax",
  recipient_invalid: "Recipient is not valid for this currency",
  transfer_invalid: "Transfer is missing a field or has a value in the wrong format",
  approved_invalid: "The approved terms themselves are invalid, so nothing can match them",
  amount_invalid: "Amount is not a positive number with the allowed decimal places",
};

export function explainReason(code: string): { code: string; text: string; category: string; known: boolean } {
  const bare = code.startsWith("terms_changed:") ? code.slice("terms_changed:".length) : code;
  const dashboardText = describeReason(code);
  const known = dashboardText !== code || code in SHIELD_REASON_TEXT || bare in SHIELD_REASON_TEXT;
  const text = dashboardText !== code ? dashboardText : SHIELD_REASON_TEXT[code] ?? SHIELD_REASON_TEXT[bare] ?? "Unknown reason code";
  const category = code.startsWith("terms_changed:") ? "terms changed after approval"
    : code.startsWith("mandate_signature_invalid") ? "mandate signature"
    : ["credential", "ceremony", "challenge_unbound"].includes(code) ? "person (passkey)"
    : ["not_signed", "nonce_replayed", "bad_tag", "wrong_tag", "window_too_long", "unknown_key", "created_in_future"].includes(code) || code.startsWith("container_") ? "presence (agent signature)"
    : code === "intent" ? "single use / replay"
    : known ? "request validation" : "unknown";
  return { code, text, category, known };
}

function reason(code: string): ShieldReason {
  return { code, text: explainReason(code).text };
}

function decide(check: ShieldDecision["check"], reasons: ShieldReason[], checksRun: string[], normalized?: Record<string, unknown>): ShieldDecision {
  return { decision: reasons.length === 0 ? "pass" : "block", check, reasons, checksRun, ...(normalized ? { normalized } : {}), note: PREFLIGHT_NOTE };
}

function recipientProblem(currency: "USD" | "DOGE", recipient: string): ShieldReason | null {
  try { validateRecipient(currency, recipient); return null; }
  catch (error) {
    if (error instanceof TpaServiceError) return { code: "recipient_invalid", text: error.message };
    return reason("recipient_invalid");
  }
}

type CheckoutResult = { ok: true; checkout: TpaNormalizedCheckout } | { ok: false; reasons: ShieldReason[] };

function validateCheckout(value: unknown): CheckoutResult {
  let checkout: TpaNormalizedCheckout;
  try { checkout = normalizeTpaCheckout(value); }
  catch (error) { return { ok: false, reasons: [reason(error instanceof TpaCheckoutError ? error.reason : "checkout_invalid")] }; }
  const recipient = recipientProblem(checkout.currency, checkout.recipient);
  return recipient ? { ok: false, reasons: [recipient] } : { ok: true, checkout };
}

/** The fields of a checkout mandate that the TPA exact-match compares. The mandate is built from approved terms only. */
function approvedTerms(checkout: TpaNormalizedCheckout): TpaAnyCheckoutMandate {
  return {
    currency: checkout.currency, recipient: checkout.recipient, merchant: checkout.merchant, items: checkout.items,
    shipping: checkout.shipping, subtotalBaseUnits: checkout.subtotalBaseUnits, taxBaseUnits: checkout.taxBaseUnits,
    amountBaseUnits: checkout.totalBaseUnits,
  } as unknown as TpaAnyCheckoutMandate;
}

const CHECKOUT_CHECKS = ["checkout schema (TPA v3 checkout input)", "one line per SKU", "total = items + shipping + tax", "recipient rule for the currency"];

/** Is this checkout well formed enough for TPA to ask the owner to approve it? */
export function checkCheckout(checkout: unknown): ShieldDecision {
  const result = validateCheckout(checkout);
  if (!result.ok) return decide("check_checkout", result.reasons, CHECKOUT_CHECKS);
  return decide("check_checkout", [], CHECKOUT_CHECKS, result.checkout as unknown as Record<string, unknown>);
}

/**
 * Same exact-match the TPA service runs in consume(): compares the checkout about to be paid with the one the owner approved.
 * Any change to merchant, recipient, currency, items, prices, shipping, tax or total blocks with terms_changed:<reason>.
 */
export function checkPayment(approved: unknown, presented: unknown): ShieldDecision {
  const checksRun = [...CHECKOUT_CHECKS, "exact match against approved terms (merchant, recipient, currency, items, prices, shipping, tax, total)"];
  const base = validateCheckout(approved);
  if (!base.ok) return decide("check_payment", [reason("approved_invalid"), ...base.reasons], checksRun);
  const difference = compareCheckoutToMandate(approvedTerms(base.checkout), presented);
  if (difference) return decide("check_payment", [reason(`terms_changed:${difference}`)], checksRun);
  const current = validateCheckout(presented);
  if (!current.ok) return decide("check_payment", current.reasons, checksRun);
  return decide("check_payment", [], checksRun, current.checkout as unknown as Record<string, unknown>);
}

const transferShape = tpaTransferInput.omit({ consent: true });
export const transferArgs = z.object({
  currency: z.enum(TPA_CURRENCIES),
  recipient: z.string(),
  amountBaseUnits: z.string().optional(),
  amount: z.string().optional(),
});
export type TransferArgs = z.infer<typeof transferArgs>;

type TransferResult = { ok: true; transfer: z.infer<typeof transferShape> } | { ok: false; reasons: ShieldReason[] };

function validateTransfer(value: TransferArgs): TransferResult {
  let amountBaseUnits = value.amountBaseUnits;
  if (value.amount !== undefined) {
    if (amountBaseUnits !== undefined) return { ok: false, reasons: [{ code: "transfer_invalid", text: "Give amount or amountBaseUnits, not both." }] };
    try { amountBaseUnits = decimalToBaseUnits(value.amount, value.currency); }
    catch { return { ok: false, reasons: [reason("amount_invalid")] }; }
  }
  const parsed = transferShape.safeParse({ currency: value.currency, recipient: value.recipient, amountBaseUnits });
  if (!parsed.success) return { ok: false, reasons: [reason("transfer_invalid")] };
  const recipient = recipientProblem(parsed.data.currency, parsed.data.recipient);
  return recipient ? { ok: false, reasons: [recipient] } : { ok: true, transfer: parsed.data };
}

/** Simple transfer check (TPA 2.0 transfer terms): amount, recipient, currency, and optionally an exact match against approved terms. */
export function checkTransfer(transfer: TransferArgs, approved?: TransferArgs): ShieldDecision {
  const checksRun = ["transfer schema (amount, recipient, currency)", "recipient rule for the currency"];
  if (approved) checksRun.push("exact match against approved transfer (amount, recipient, currency)");
  const current = validateTransfer(transfer);
  if (!current.ok) return decide("check_transfer", current.reasons, checksRun);
  if (approved) {
    const base = validateTransfer(approved);
    if (!base.ok) return decide("check_transfer", [reason("approved_invalid"), ...base.reasons], checksRun);
    const a = base.transfer, p = current.transfer;
    if (a.amountBaseUnits !== p.amountBaseUnits || a.recipient !== p.recipient || a.currency !== p.currency) {
      return decide("check_transfer", [reason("terms_changed:legacy_mismatch")], checksRun);
    }
  }
  return decide("check_transfer", [], checksRun, current.transfer);
}

export function getPolicy() {
  return {
    name: "TPA Shield",
    version: SHIELD_VERSION,
    mode: TPA_MODE,
    readOnly: true,
    currencies: TPA_CURRENCIES,
    amounts: "Integer base-unit strings (USD cents, DOGE 1e-8). check_transfer also accepts a decimal amount.",
    recipientRules: {
      USD: "Internal pilot account reference, for example user:42",
      DOGE: "Checksummed Dogecoin mainnet public address (checked offline, no network call)",
    },
    limits: { maxLineItems: TPA_MAX_LINE_ITEMS, maxItemQty: TPA_MAX_ITEM_QTY, approvalTtlSeconds: TPA_TTL_SECONDS, passkeyCeremonyTtlMs: TPA_CEREMONY_TTL_MS },
    preflightChecks: {
      check_checkout: CHECKOUT_CHECKS,
      check_payment: "Everything in check_checkout, plus the same exact-match TPA runs at payment time against the approved checkout.",
      check_transfer: "Amount, recipient and currency format, plus an optional exact match against an approved transfer.",
    },
    enforcedOnlyByTheFullTpaService: [
      "Owner passkey approval of the exact terms (Person)",
      "Server-signed mandate and signature verification",
      "Single use: an approval cannot be replayed",
      "Approval, quote and conversion expiry",
      "Quote and payment-target binding (v3.1)",
      "Agent request signatures (Visa Trusted Agent Protocol, Presence)",
    ],
    notIncluded: [
      "Token rug-pull or honeypot screening (not implemented in TPA yet)",
      "Oracle price checks such as Pyth (not implemented in TPA yet)",
    ],
    guarantees: "These tools never sign, send transactions, hold keys, read secrets, or call the network.",
    note: PREFLIGHT_NOTE,
  };
}
