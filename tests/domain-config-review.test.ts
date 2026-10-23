import { describe, expect, it } from "vitest";
import { createTpaAuthority, hasTpaRequestOrigin, tpaAuthorityFromEnv } from "../src/config.js";
import { TPA_MODE, canonicalTpaMandate, decimalToBaseUnits, formatBaseUnits, tpaMandateSchema, tpaTransferInput } from "../src/domain.js";
import { assertFreshTpaReview } from "../src/review.js";

const mandate = { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "2000", recipient: "user:1", feeBaseUnits: "0", nonce: "a".repeat(64), issuedAt: 1000, expires: 1300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" } as const;

describe("immutable mandate and authority policy", () => {
  it("preserves ordered canonical mandate evidence and no execution authority", () => { expect(canonicalTpaMandate(Object.fromEntries(Object.entries(mandate).reverse()))).toBe(canonicalTpaMandate(mandate)); expect(() => canonicalTpaMandate({ ...mandate, ledgerDomain: "other" })).toThrow(); expect(TPA_MODE).toMatchObject({ paymentExecution: false, onChainSubmission: false, independentLiveness: "not-configured" }); });
  it("uses exact base units instead of floats and rejects unsafe input", () => { expect(decimalToBaseUnits("20.05", "USD")).toBe("2005"); expect(formatBaseUnits("1", "DOGE")).toBe("0.00000001"); expect(() => decimalToBaseUnits("1e3", "USD")).toThrow(); expect(tpaTransferInput.safeParse({ currency: "USD", amountBaseUnits: "0", recipient: "user:1", consent: true }).success).toBe(false); expect(tpaMandateSchema.safeParse({ ...mandate, expires: 1301 }).success).toBe(false); });
  it("requires an explicitly configured exact HTTPS authority", () => { expect(createTpaAuthority({}).valid).toBe(false); expect(createTpaAuthority({ origin: "http://tpa.example.test", rpID: "tpa.example.test" }).valid).toBe(false); const authority = createTpaAuthority({ origin: "https://tpa.example.test", rpID: "tpa.example.test" }); expect(authority.valid).toBe(true); expect(hasTpaRequestOrigin({ origin: "https://tpa.example.test", host: "attacker.test" }, authority)).toBe(true); expect(hasTpaRequestOrigin({ origin: "https://attacker.test", host: "tpa.example.test" }, authority)).toBe(false); });
  it("requires explicit true activation even with a valid configured authority", () => {
    const config = { origin: "https://tpa.example.test", rpID: "tpa.example.test" };
    expect(createTpaAuthority(config).enabled).toBe(false);
    for (const value of [undefined, "false", "TRUE", "1", ""]) expect(tpaAuthorityFromEnv({ TPA_ORIGIN: config.origin, TPA_RP_ID: config.rpID, TPA_AUTHORIZATION_ENABLED: value }).enabled).toBe(false);
    expect(tpaAuthorityFromEnv({ TPA_ORIGIN: config.origin, TPA_RP_ID: config.rpID, TPA_AUTHORIZATION_ENABLED: "true" }).enabled).toBe(true);
  });
  it("requires fresh reviewed evidence before a client action", () => { const review = { id: "id", mandate, mandateHash: "b".repeat(64), state: "pending", expiresAtMs: 2000 }; expect(assertFreshTpaReview(review, { ...review }, "authorize", 1000)).toEqual(review); expect(() => assertFreshTpaReview(review, { ...review, mandateHash: "c".repeat(64) }, "authorize", 1000)).toThrow(/changed/i); const expired = { ...review, expiresAtMs: 1000 }; expect(() => assertFreshTpaReview(expired, expired, "authorize", 1000)).toThrow(/expired/i); });
});
