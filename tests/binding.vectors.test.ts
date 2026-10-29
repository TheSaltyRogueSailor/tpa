/**
 * v3.1 binding: golden canonical/hash vectors, preimage parity, closed-tuple refusals, per-field hash sensitivity,
 * and proof that v2.0 / v3.0 canonical bytes are unchanged (golden values computed from origin/main ce601fc).
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  TPA_CHECKOUT_FP_DOMAIN, TPA_PAYMENT_TARGET_DOMAIN, TpaBindingError, checkoutFingerprint, checkoutFingerprintTuple,
  paymentTargetHash, paymentTargetTuple, railPayee, tpaPaymentTargetSchema, type TpaCheckoutFingerprintInput,
} from "../src/binding.js";
import {
  TPA_BOUND_CHECKOUT_LEDGER_DOMAIN, TPA_CHECKOUT_LEDGER_DOMAIN, canonicalTpaMandate, isBoundCheckoutMandate, isCheckoutMandate,
  tpaBoundCheckoutMandateSchema, tpaCheckoutMandateSchema, tpaMandateSchema,
} from "../src/domain.js";

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

const FP: TpaCheckoutFingerprintInput = {
  currency: "USD", merchant: { id: "harbor-supply", name: "Harbor Supply Co." }, recipient: "user:7001",
  items: [{ sku: "COF-BEANS-1KG", qty: 1, unitPriceBaseUnits: "2400" }, { sku: "FILTER-100", qty: 2, unitPriceBaseUnits: "600" }],
  shipping: { method: "standard", costBaseUnits: "599" }, subtotalBaseUnits: "3600", taxBaseUnits: "297", totalBaseUnits: "4496",
  quote: { merchantId: "harbor-supply", quoteId: "chk_golden_0001" },
};
const USDZ = "erc20:0x000000000000000000000000000000000000b5d5";
const T = {
  rail: "metal-usdz", network: "evm:63825", asset: USDZ, decimals: 18, recipientRef: "user:7001",
  payee: "evm:0x00000000000000000000000000000000000000aa", sourceCurrency: "USD", sourceAmountBaseUnits: "4496", railAmount: "44960000000000000000",
  conversion: { id: "usd-usdz-par", rateNumerator: "10000000000000000", rateDenominator: "1", expires: 1800000900 },
  fee: { asset: USDZ, capBaseUnits: "1000000" },
} as const;

const GOLDEN = {
  fpPreimage: 'TPA-CHECKOUT-FP/3.1\n["TPA-CHECKOUT-FP/3.1","USD","harbor-supply","Harbor Supply Co.","user:7001",[["COF-BEANS-1KG",1,"2400"],["FILTER-100",2,"600"]],"standard","599","3600","297","4496","harbor-supply","chk_golden_0001"]',
  fp: "ccfb3cce300b6e52e55f870819cb9701a570e1ece095baa68097242323807c7e",
  targetPreimage: 'TPA-PAYMENT-TARGET/3.1\n["TPA-PAYMENT-TARGET/3.1","metal-usdz","evm:63825","erc20:0x000000000000000000000000000000000000b5d5","18","user:7001","evm:0x00000000000000000000000000000000000000aa","USD","4496","44960000000000000000","usd-usdz-par","10000000000000000","1","1800000900","erc20:0x000000000000000000000000000000000000b5d5","1000000"]',
  target: "ad62bf0ab2c58f4cba132ef885a7143dbfeefab2e2b5bbc2276f7b987b3551f9",
  mandate: "9be95828c4a5cbce2cad52858ea0bbedf1a3217de49e205531af06e0d85a82a3",
  /** sha256(canonicalTpaMandate) of fixed v2.0 / v3.0 mandates, computed against origin/main ce601fc. */
  v2: "eb9358b03a1ae7b31f807d5e510f424ec038b7f1ebbf436f2fe071f3dafc329e",
  v3: "2a468b7759a1b131e2dcf5e0b4c48bc81e658bfa4186fc83e2564f6031078087",
};

const quote = { merchantId: "harbor-supply", quoteId: "chk_golden_0001", expires: 1800000900 };
const mandateInput = () => ({
  type: "TPA-mandate", version: "3.1", action: "bound-checkout-authorization", issuerUserId: 1, currency: "USD",
  merchant: FP.merchant, items: FP.items, shipping: FP.shipping, subtotalBaseUnits: "3600", taxBaseUnits: "297", amountBaseUnits: "4496",
  recipient: "user:7001", feeBaseUnits: "0", quote, paymentTarget: T, checkoutFingerprint: GOLDEN.fp, paymentTargetHash: GOLDEN.target,
  nonce: "3".repeat(64), issuedAt: 1800000000, expires: 1800000300, scope: "single_use", ledgerDomain: TPA_BOUND_CHECKOUT_LEDGER_DOMAIN,
}) as Record<string, unknown>;

const V2 = { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot",
  amountBaseUnits: "1249", recipient: "user:7001", feeBaseUnits: "0", nonce: "1".repeat(64), issuedAt: 1800000000, expires: 1800000300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" };
const V3 = { type: "TPA-mandate", version: "3.0", action: "checkout-authorization", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot",
  merchant: FP.merchant, items: FP.items, shipping: FP.shipping, subtotalBaseUnits: "3600", taxBaseUnits: "297", amountBaseUnits: "4496", recipient: "user:7001", feeBaseUnits: "0",
  nonce: "2".repeat(64), issuedAt: 1800000000, expires: 1800000300, scope: "single_use", ledgerDomain: TPA_CHECKOUT_LEDGER_DOMAIN };

describe("v3.1 golden vectors and parity", () => {
  it("checkout fingerprint: exact preimage and hash", () => {
    expect(`${TPA_CHECKOUT_FP_DOMAIN}\n${JSON.stringify(checkoutFingerprintTuple(FP))}`).toBe(GOLDEN.fpPreimage);
    expect(checkoutFingerprint(FP)).toBe(GOLDEN.fp);
    expect(sha(GOLDEN.fpPreimage)).toBe(GOLDEN.fp);
  });
  it("payment target: exact preimage and hash", () => {
    expect(`${TPA_PAYMENT_TARGET_DOMAIN}\n${JSON.stringify(paymentTargetTuple(T))}`).toBe(GOLDEN.targetPreimage);
    expect(paymentTargetHash(T)).toBe(GOLDEN.target);
    expect(sha(GOLDEN.targetPreimage)).toBe(GOLDEN.target);
    expect(railPayee(tpaPaymentTargetSchema.parse(T))).toBe("0x00000000000000000000000000000000000000aa");
  });
  it("v3.1 canonical mandate carries the target tuple and both hashes, and has a golden hash", () => {
    const m = tpaBoundCheckoutMandateSchema.parse(mandateInput());
    const canonical = canonicalTpaMandate(m);
    expect(sha(canonical)).toBe(GOLDEN.mandate);
    const tuple = JSON.parse(canonical) as unknown[];
    expect(tuple.slice(0, 3)).toEqual(["TPA-mandate", "3.1", "bound-checkout-authorization"]);
    expect(tuple).toContainEqual(paymentTargetTuple(T));
    expect(tuple).toContain(GOLDEN.fp);
    expect(tuple).toContain(GOLDEN.target);
    expect(tuple.at(-1)).toBe(TPA_BOUND_CHECKOUT_LEDGER_DOMAIN);
    expect(isCheckoutMandate(m) && isBoundCheckoutMandate(m)).toBe(true);
  });
  it("key order of the caller object does not change any hash (closed ordered tuples)", () => {
    const reversed = Object.fromEntries(Object.entries(T).reverse());
    expect(paymentTargetHash(reversed)).toBe(GOLDEN.target);
    const m = Object.fromEntries(Object.entries(mandateInput()).reverse());
    expect(sha(canonicalTpaMandate(tpaBoundCheckoutMandateSchema.parse(m)))).toBe(GOLDEN.mandate);
  });
});

describe("legacy bytes and domains are unchanged", () => {
  it("v2.0 and v3.0 canonical hashes equal origin/main", () => {
    expect(sha(canonicalTpaMandate(tpaMandateSchema.parse(V2)))).toBe(GOLDEN.v2);
    expect(sha(canonicalTpaMandate(tpaCheckoutMandateSchema.parse(V3)))).toBe(GOLDEN.v3);
  });
  it("versions, actions and ledger domains cannot be mixed", () => {
    expect(tpaMandateSchema.safeParse({ ...V3, ledgerDomain: TPA_BOUND_CHECKOUT_LEDGER_DOMAIN }).success).toBe(false);
    expect(tpaMandateSchema.safeParse({ ...mandateInput(), ledgerDomain: TPA_CHECKOUT_LEDGER_DOMAIN }).success).toBe(false);
    expect(tpaMandateSchema.safeParse({ ...mandateInput(), version: "3.0" }).success).toBe(false);
    expect(tpaMandateSchema.safeParse({ ...mandateInput(), action: "checkout-authorization" }).success).toBe(false);
    expect(tpaMandateSchema.safeParse({ ...V3, version: "3.1" }).success).toBe(false);
    const v3 = tpaCheckoutMandateSchema.parse(V3);
    expect(isCheckoutMandate(v3)).toBe(true);
    expect(isBoundCheckoutMandate(v3)).toBe(false);
  });
});

describe("closed tuples refuse malformed input", () => {
  const bad = (over: Partial<TpaCheckoutFingerprintInput>, reason: string) =>
    expect(() => checkoutFingerprint({ ...FP, ...over })).toThrow(new TpaBindingError(reason));
  it("checkout fingerprint", () => {
    bad({ items: [...FP.items].reverse() }, "fingerprint_item_order");
    bad({ items: [FP.items[0]!, FP.items[0]!] }, "fingerprint_item_order");
    bad({ subtotalBaseUnits: "3601" }, "fingerprint_total");
    bad({ totalBaseUnits: "4497" }, "fingerprint_total");
    bad({ taxBaseUnits: "29.7" }, "fingerprint_amount");
    bad({ items: [{ sku: "A", qty: 0, unitPriceBaseUnits: "1" }] }, "fingerprint_item");
    bad({ quote: { merchantId: "other", quoteId: "chk_golden_0001" } }, "fingerprint_quote");
    bad({ quote: { merchantId: "harbor-supply", quoteId: " bad" } }, "fingerprint_quote");
    expect(() => checkoutFingerprint({ ...FP, currency: "DOGE" as "USD" })).toThrow(new TpaBindingError("fingerprint_currency"));
  });
  it("payment target", () => {
    const fails = (t: unknown) => expect(tpaPaymentTargetSchema.safeParse(t).success).toBe(false);
    fails({ ...T, extra: 1 });
    fails({ ...T, payee: "0x00000000000000000000000000000000000000aa" });
    fails({ ...T, payee: "evm:0x00000000000000000000000000000000000000AA" });
    fails({ ...T, network: "evm:1" });
    fails({ ...T, asset: "erc20:0x0000000000000000000000000000000000000001" });
    fails({ ...T, decimals: 6 });
    fails({ ...T, railAmount: "44960000000000000001" });
    fails({ ...T, conversion: { ...T.conversion, rateDenominator: "3" } });
    fails({ ...T, fee: { asset: "iso4217:USD", capBaseUnits: "0" } });
    fails({ ...T, rail: "airwallex-airi" });
    fails({ rail: "airwallex-airi", network: "airwallex:mock-fixture", asset: "iso4217:USD", decimals: 2, recipientRef: "user:7001", payee: "awx-mock-fixture:harbor",
      sourceCurrency: "USD", sourceAmountBaseUnits: "4496", railAmount: "4496", conversion: { id: "usd-usd-identity", rateNumerator: "1", rateDenominator: "1", expires: 1800000900 },
      fee: { asset: "iso4217:USD", capBaseUnits: "1" } });
    fails({ ...T, payee: "awx:real-beneficiary-guess" });
  });
});

describe("every bound field changes the hash", () => {
  const fp = (over: Partial<TpaCheckoutFingerprintInput>) => checkoutFingerprint({ ...FP, ...over });
  it("checkout fields", () => {
    const variants = [
      fp({ items: [{ ...FP.items[0]!, unitPriceBaseUnits: "2401" }, FP.items[1]!], subtotalBaseUnits: "3601", totalBaseUnits: "4497" }),
      fp({ items: [{ ...FP.items[0]!, sku: "COF-BEANS-2KG" }, FP.items[1]!] }),
      fp({ items: [FP.items[0]!, { ...FP.items[1]!, qty: 3 }], subtotalBaseUnits: "4200", totalBaseUnits: "5096" }),
      fp({ items: [FP.items[0]!, { ...FP.items[1]!, sku: "FILTER-200" }] }),
      fp({ shipping: { method: "express", costBaseUnits: "599" } }),
      fp({ shipping: { method: "standard", costBaseUnits: "600" }, totalBaseUnits: "4497" }),
      fp({ taxBaseUnits: "298", totalBaseUnits: "4497" }),
      fp({ merchant: { id: "harbor-supply-2", name: FP.merchant.name }, quote: { merchantId: "harbor-supply-2", quoteId: "chk_golden_0001" } }),
      fp({ merchant: { id: FP.merchant.id, name: "Harbor Supply Inc." } }),
      fp({ recipient: "user:7002" }),
      fp({ quote: { merchantId: "harbor-supply", quoteId: "chk_golden_0002" } }),
    ];
    expect(new Set([GOLDEN.fp, ...variants]).size).toBe(variants.length + 1);
  });
  it("target fields", () => {
    const variants = [
      { ...T, payee: "evm:0x00000000000000000000000000000000000000ab" },
      { ...T, recipientRef: "user:7002" },
      { ...T, sourceAmountBaseUnits: "4497", railAmount: "44970000000000000000" },
      { ...T, conversion: { ...T.conversion, id: "usd-usdz-par-2" } },
      { ...T, conversion: { ...T.conversion, rateNumerator: "20000000000000000", rateDenominator: "2" } },
      { ...T, conversion: { ...T.conversion, expires: 1800000901 } },
      { ...T, fee: { ...T.fee, capBaseUnits: "1000001" } },
    ].map(paymentTargetHash);
    expect(new Set([GOLDEN.target, ...variants]).size).toBe(variants.length + 1);
  });
});

describe("v3.1 mandate schema refuses inconsistent signed terms", () => {
  const fails = (over: Record<string, unknown>) => expect(tpaBoundCheckoutMandateSchema.safeParse({ ...mandateInput(), ...over }).success).toBe(false);
  it("tampered or missing hashes", () => {
    fails({ checkoutFingerprint: "0".repeat(64) });
    fails({ paymentTargetHash: "0".repeat(64) });
    fails({ checkoutFingerprint: undefined });
    fails({ paymentTargetHash: undefined });
    fails({ paymentTarget: undefined });
    fails({ quote: undefined });
  });
  it("terms that disagree with the bound hashes", () => {
    fails({ recipient: "user:7002" });
    fails({ amountBaseUnits: "4497" });
    fails({ quote: { ...quote, quoteId: "chk_other" } });
    fails({ quote: { ...quote, merchantId: "other" } });
    fails({ paymentTarget: { ...T, recipientRef: "user:7002" } });
    fails({ feeBaseUnits: "1" });
  });
  it("lifetime cannot outlive the quote or the conversion (zero tolerance)", () => {
    fails({ expires: 1800000301 });
    fails({ quote: { ...quote, expires: 1800000299 } });
    const t = { ...T, conversion: { ...T.conversion, expires: 1800000299 } };
    fails({ paymentTarget: t, paymentTargetHash: paymentTargetHash(t) });
  });
});
