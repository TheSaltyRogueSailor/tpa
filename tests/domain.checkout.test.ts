import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalTpaMandate, compareCheckoutToMandate, normalizeTpaCheckout, tpaCheckoutMandateSchema, type TpaCheckoutInput } from "../src/domain.js";
import { deriveTpaMandateChallenge } from "../src/evidence.js";
import { createTpaMandateSigner, tpaMandateSignerFromEnv } from "../src/signing.js";

const CHECKOUT: TpaCheckoutInput = {
  currency: "USD", recipient: "user:42", merchant: { id: "acme-store", name: "Acme Store" },
  items: [{ sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }, { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }],
  shipping: { method: "standard", costBaseUnits: "500" }, taxBaseUnits: "280", totalBaseUnits: "3780",
};
const mandate = (checkout = CHECKOUT) => {
  const n = normalizeTpaCheckout(checkout);
  return tpaCheckoutMandateSchema.parse({
    type: "TPA-mandate", version: "3.0", action: "checkout-authorization", issuerUserId: 1, currency: n.currency, paymentNetwork: "internal-usd-pilot",
    merchant: n.merchant, items: n.items, shipping: n.shipping, subtotalBaseUnits: n.subtotalBaseUnits, taxBaseUnits: n.taxBaseUnits, amountBaseUnits: n.totalBaseUnits,
    recipient: n.recipient, feeBaseUnits: "0", nonce: "e".repeat(64), issuedAt: 1000, expires: 1300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v3",
  });
};

describe("checkout mandate canonicalization (no database)", () => {
  it("is deterministic: line order and object key order do not change the canonical form", () => {
    const reordered = { totalBaseUnits: "3780", taxBaseUnits: "280", shipping: { costBaseUnits: "500", method: "standard" }, items: [...CHECKOUT.items].reverse(), merchant: { name: "Acme Store", id: "acme-store" }, recipient: "user:42", currency: "USD" as const };
    expect(canonicalTpaMandate(mandate(reordered))).toBe(canonicalTpaMandate(mandate()));
    expect(canonicalTpaMandate(mandate())).toContain('[["MUG-01",2,"750"],["TEE-02",1,"1500"]]');
  });
  it("every bound field changes the canonical form", () => {
    const base = canonicalTpaMandate(mandate());
    const variants: TpaCheckoutInput[] = [
      { ...CHECKOUT, merchant: { id: "acme-store", name: "Acme Store 2" } },
      { ...CHECKOUT, shipping: { method: "express", costBaseUnits: "500" } },
      { ...CHECKOUT, taxBaseUnits: "281", totalBaseUnits: "3781" },
      { ...CHECKOUT, items: [CHECKOUT.items[0]!, { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "751" }], totalBaseUnits: "3782" },
    ];
    for (const variant of variants) expect(canonicalTpaMandate(mandate(variant))).not.toBe(base);
  });
  it("schema rejects unsorted items, wrong subtotal and wrong total in a stored mandate", () => {
    const m = mandate();
    expect(tpaCheckoutMandateSchema.safeParse({ ...m, items: [...m.items].reverse() }).success).toBe(false);
    expect(tpaCheckoutMandateSchema.safeParse({ ...m, subtotalBaseUnits: "2999" }).success).toBe(false);
    expect(tpaCheckoutMandateSchema.safeParse({ ...m, amountBaseUnits: "3781" }).success).toBe(false);
  });
  it("exact-match comparison accepts the same cart and names the first difference otherwise", () => {
    expect(compareCheckoutToMandate(mandate(), { ...CHECKOUT, items: [...CHECKOUT.items].reverse() })).toBeNull();
    expect(compareCheckoutToMandate(mandate(), { ...CHECKOUT, merchant: { id: "x", name: "Acme Store" } })).toBe("merchant_mismatch");
    expect(compareCheckoutToMandate(mandate(), { ...CHECKOUT, extra: 1 })).toBe("checkout_invalid");
  });
  it("challenge derivation is SHA-256(mandateHash || nonce) and rejects malformed inputs", () => {
    const nonce = Buffer.alloc(32, 7).toString("base64url");
    expect(deriveTpaMandateChallenge("ab".repeat(32), nonce)).toHaveLength(43);
    expect(() => deriveTpaMandateChallenge("zz", nonce)).toThrow();
    expect(() => deriveTpaMandateChallenge("ab".repeat(32), "short")).toThrow();
  });
  it("signer: env loader, rotation set, and refusal of non-Ed25519 keys (keys generated in memory only)", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    expect(tpaMandateSignerFromEnv({})).toBeUndefined();
    const fromEnv = tpaMandateSignerFromEnv({ TPA_MANDATE_SIGNING_KEY_ID: "k1", TPA_MANDATE_SIGNING_KEY: pem.replace(/\n/g, "\\n") })!;
    const sig = fromEnv.sign("hello");
    expect(fromEnv.verify("hello", sig)).toBeNull();
    expect(fromEnv.verify("hello!", sig)).toBe("bad_signature");
    expect(fromEnv.verify("hello", { ...sig, keyId: "k2" })).toBe("unknown_key");
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey;
    expect(() => createTpaMandateSigner({ activeKeyId: "k1", privateKey: ec })).toThrow();
    expect(() => createTpaMandateSigner({ activeKeyId: "bad id", privateKey })).toThrow();
  });
});
