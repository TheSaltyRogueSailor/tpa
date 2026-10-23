import { z } from "zod";

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
 */
export const tpaMandateSchema = z.object({
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
export type TpaMandate = z.infer<typeof tpaMandateSchema>;

/** Fixed ordered tuple: no arbitrary JSON fields and no floating-point amounts. */
export function canonicalTpaMandate(value: unknown): string {
  const mandate = tpaMandateSchema.parse(value);
  return JSON.stringify([
    mandate.type, mandate.version, mandate.action, mandate.issuerUserId, mandate.currency,
    mandate.paymentNetwork, mandate.amountBaseUnits, mandate.recipient, mandate.feeBaseUnits,
    mandate.nonce, mandate.issuedAt, mandate.expires, mandate.scope, mandate.ledgerDomain,
  ]);
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
