/**
 * Owner approval display data for a v3.1 bound checkout mandate. Derived only from the signed mandate, so what the
 * owner is shown cannot differ from what is signed. Pure: no I/O, no clock.
 *
 * Fee semantics (v3.1): `feeBaseUnits` "0" means a zero TPA / platform fee. It does NOT include network (gas) fees.
 * Network fees are separate and bounded by the signed `paymentTarget.fee` cap, in BASE UNITS of the fee asset.
 */
import { METAL_USDZ_ASSET, type TpaPaymentTarget } from "./binding.js";
import type { TpaBoundCheckoutMandate } from "./domain.js";

export type TpaAmountDisplay = Readonly<{ asset: string; symbol: string; decimals: number | null; baseUnits: string; formatted: string }>;
export type TpaApprovalSummary = Readonly<{
  mandateVersion: "3.1";
  merchant: Readonly<{ id: string; name: string }>;
  quoteId: string;
  recipient: string;
  checkoutTotal: TpaAmountDisplay;
  rail: TpaPaymentTarget["rail"];
  network: string;
  payee: string;
  railAmount: TpaAmountDisplay;
  conversion: Readonly<{ id: string; rateNumerator: string; rateDenominator: string; nominal: string; expires: number; expiresIso: string; note: string }>;
  tpaFee: Readonly<{ baseUnits: "0"; meaning: string }>;
  networkFeeCap: TpaAmountDisplay & Readonly<{ meaning: string }>;
  /** Worst case the payer's wallet can be debited, per asset: rail amount plus the network fee cap. */
  maxWalletDebit: readonly TpaAmountDisplay[];
  quoteExpires: number;
  approvalExpires: number;
  approvalExpiresIso: string;
  expiryMeaning: string;
  limits: readonly string[];
}>;

const SYMBOLS: Record<string, string> = { [METAL_USDZ_ASSET]: "USDZ", "iso4217:USD": "USD" };
/** Known conversion ids and what they honestly are. Unknown ids are shown as server quoted, nothing more. */
export const TPA_CONVERSION_NOTES: Readonly<Record<string, string>> = Object.freeze({
  "usd-usdz-par": "Demo / testnet assumption: a fixed nominal 1 USD = 1 USDZ. Not proof of reserves, of a market peg, of redemption, or of any FX execution.",
  "usd-usd-identity": "Same currency: no conversion.",
});

/** Exact base units to a decimal string (no floats, no rounding). */
export function formatAssetBaseUnits(baseUnits: string | bigint, decimals: number): string {
  const v = BigInt(baseUnits);
  const neg = v < 0n;
  const digits = (neg ? -v : v).toString().padStart(decimals + 1, "0");
  const whole = decimals === 0 ? digits : digits.slice(0, -decimals);
  const frac = decimals === 0 ? "" : digits.slice(-decimals).replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? `.${frac}` : ""}`;
}
const amount = (asset: string, decimals: number | null, baseUnits: string): TpaAmountDisplay => {
  const symbol = SYMBOLS[asset] ?? asset;
  return { asset, symbol, decimals, baseUnits, formatted: decimals === null ? `${baseUnits} base units of ${symbol}` : `${formatAssetBaseUnits(baseUnits, decimals)} ${symbol}` };
};
const iso = (seconds: number) => new Date(seconds * 1_000).toISOString();

export function tpaApprovalSummary(mandate: TpaBoundCheckoutMandate): TpaApprovalSummary {
  const t = mandate.paymentTarget;
  const feeDecimals = t.fee.asset === t.asset ? t.decimals : null;
  const railAmount = amount(t.asset, t.decimals, t.railAmount);
  const feeCap = amount(t.fee.asset, feeDecimals, t.fee.capBaseUnits);
  const debits = new Map<string, bigint>([[t.asset, BigInt(t.railAmount)]]);
  debits.set(t.fee.asset, (debits.get(t.fee.asset) ?? 0n) + BigInt(t.fee.capBaseUnits));
  const maxWalletDebit = [...debits].map(([asset, v]) => amount(asset, asset === t.asset ? t.decimals : feeDecimals, v.toString()));
  // Nominal rate shown per 1 USD (100 source base units), exact when it divides evenly.
  const perDollar = 100n * BigInt(t.conversion.rateNumerator);
  const den = BigInt(t.conversion.rateDenominator);
  const nominal = perDollar % den === 0n ? `1 USD = ${formatAssetBaseUnits(perDollar / den, t.decimals)} ${railAmount.symbol} (nominal)` : `1 USD = ${perDollar}/${den} base units of ${railAmount.symbol} (nominal)`;
  return {
    mandateVersion: "3.1",
    merchant: { id: mandate.merchant.id, name: mandate.merchant.name },
    quoteId: mandate.quote.quoteId,
    recipient: mandate.recipient,
    checkoutTotal: amount("iso4217:USD", 2, mandate.amountBaseUnits),
    rail: t.rail, network: t.network, payee: t.payee,
    railAmount,
    conversion: { id: t.conversion.id, rateNumerator: t.conversion.rateNumerator, rateDenominator: t.conversion.rateDenominator, nominal,
      expires: t.conversion.expires, expiresIso: iso(t.conversion.expires), note: TPA_CONVERSION_NOTES[t.conversion.id] ?? "Conversion quoted by the server at approval; fixed, no tolerance." },
    tpaFee: { baseUnits: mandate.feeBaseUnits, meaning: "Zero TPA / platform fee. Network (gas) fees are separate; see networkFeeCap." },
    networkFeeCap: { ...feeCap, meaning: `Maximum network (gas) fee, in base units of ${feeCap.symbol}. The payment is refused before signing if it could exceed this.` },
    maxWalletDebit,
    quoteExpires: mandate.quote.expires,
    approvalExpires: mandate.expires, approvalExpiresIso: iso(mandate.expires),
    expiryMeaning: "The trusted server will not sign or submit a payment after this time. It is not a chain-enforced deadline; a payment submitted before it may settle later.",
    limits: [
      "Network fee: the cap is enforced before signing; the actual gas charged is not separately recorded in the result.",
      ...(t.rail === "airwallex-airi" ? ["Airwallex: mock fixture destination only; no provider call is made."] : []),
    ],
  };
}
