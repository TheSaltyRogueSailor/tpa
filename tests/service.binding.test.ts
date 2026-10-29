/**
 * v3.1 service binding: quotes are resolved from the server's own record (owner, merchant scope, terms, expiry),
 * the destination is resolved and frozen before approval, and both hashes are signed inside the mandate.
 * In-memory persistence and a synthetic passkey only: no database, provider, chain or network.
 */
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import { createAiriFixtureResolver, createMetalTargetResolver, combineTargetResolvers } from "../shopper/payments.js";
import { formatAssetBaseUnits, tpaApprovalSummary } from "../src/approval.js";
import { checkoutFingerprint, paymentTargetHash } from "../src/binding.js";
import { createTpaAuthority } from "../src/config.js";
import { TPA_TTL_SECONDS, boundFingerprintInput, canonicalTpaMandate, isBoundCheckoutMandate, normalizeTpaCheckout, tpaBoundCheckoutMandateSchema, type TpaCheckoutInput } from "../src/domain.js";
import { createTpaService, type TpaBoundIntentInput, type TpaQuoteResolver, type TpaTargetResolver, type TpaTrustedQuote } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import { syntheticAuthenticator } from "./support/authenticator.js";
import { PAYEE, reviewCheckout, sha256 } from "./support/dispatch.js";

const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";
const T0 = 1_800_000_000_000;
const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
const ctx = { owner, headers: { origin: ORIGIN } };
const MERCHANT = "review-merchant";

type RigOptions = { quotes?: TpaQuoteResolver | null; targets?: TpaTargetResolver | null; quote?: Partial<TpaTrustedQuote>; failAudit?: (action: string) => boolean };

async function rig(options: RigOptions = {}) {
  let clock = T0;
  const memory = createMemoryTpaPersistence({ ownerIds: [1, 2] });
  const evidence = options.failAudit
    ? { ...memory.evidence, audit: async (event: Parameters<typeof memory.evidence.audit>[0]) => { if (options.failAudit!(event.action)) throw new Error("audit down"); return memory.evidence.audit(event); } }
    : memory.evidence;
  const record: TpaTrustedQuote = { merchantId: MERCHANT, quoteId: "q-1", ownerUserId: 1, checkout: reviewCheckout(), expiresAtMs: T0 + 900_000, ...options.quote };
  const quotes: TpaQuoteResolver = options.quotes === undefined
    ? { async resolve({ merchantId, quoteId }) { return merchantId === record.merchantId && quoteId === "q-1" ? structuredClone(record) : null; } }
    : options.quotes ?? (undefined as never);
  const metal = createMetalTargetResolver({ [MERCHANT]: PAYEE }, 63825);
  const targets: TpaTargetResolver = options.targets === undefined
    ? combineTargetResolvers(metal, createAiriFixtureResolver({ [MERCHANT]: "review-fixture" }))
    : options.targets ?? (undefined as never);
  const signer = createTpaMandateSigner({ activeKeyId: "test-key", privateKey: generateKeyPairSync("ed25519").privateKey });
  const service = createTpaService({
    store: memory.store, evidence, signer, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock,
    ...(options.quotes === null ? {} : { quotes }), ...(options.targets === null ? {} : { targets }),
  });
  const phone = syntheticAuthenticator(ORIGIN, RP_ID);
  const reg = await service.registrationOptions(ctx, { label: "phone", consent: true });
  await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: phone.register(reg.options.challenge) });
  const approve = async (intentId: string) => {
    const started = await service.authenticationOptions(ctx, { intentId, consent: true });
    await service.authorize(ctx, { intentId, ceremonyId: started.ceremonyId, response: phone.assert(started.options.challenge), consent: true });
  };
  return { service, memory, approve, setClock: (ms: number) => { clock = ms; }, record };
}

const bound = (over: Record<string, unknown> = {}): TpaBoundIntentInput => ({ merchantId: MERCHANT, quoteId: "q-1", rail: "metal-usdz", consent: true, ...over } as TpaBoundIntentInput);
const refused = (code: string, reason?: string) => expect.objectContaining({ name: "TpaServiceError", code, ...(reason ? { reason } : {}) });

describe("bound intent creation resolves the quote server side", () => {
  it("issues a signed 3.1 mandate with both hashes recomputable from server records", async () => {
    const { service, record } = await rig();
    const intent = await service.createIntent(ctx, bound());
    const m = tpaBoundCheckoutMandateSchema.parse(intent.mandate);
    expect(isBoundCheckoutMandate(m)).toBe(true);
    expect(intent.mandateHash).toBe(sha256(canonicalTpaMandate(m)));
    const n = normalizeTpaCheckout(record.checkout);
    expect(m.checkoutFingerprint).toBe(checkoutFingerprint(boundFingerprintInput({ ...n, currency: "USD", amountBaseUnits: n.totalBaseUnits, quote: m.quote })));
    expect(m.paymentTargetHash).toBe(paymentTargetHash(m.paymentTarget));
    expect(m.quote).toEqual({ merchantId: MERCHANT, quoteId: "q-1", expires: (T0 + 900_000) / 1000 });
    expect(m.paymentTarget.payee).toBe(`evm:${PAYEE}`);
    expect(m.feeBaseUnits).toBe("0");
    expect(m.expires).toBe(T0 / 1000 + TPA_TTL_SECONDS);
  });
  it("expires at the earliest of TTL, quote expiry and conversion expiry", async () => {
    const short = await rig({ quote: { expiresAtMs: T0 + 60_000 } });
    expect((await short.service.createIntent(ctx, bound())).mandate.expires).toBe(T0 / 1000 + 60);
    const conv: TpaTargetResolver = { resolve: async input => { const t = createMetalTargetResolver({ [MERCHANT]: PAYEE }, 63825)(input)!; return { ...t, conversion: { ...t.conversion, expires: input.nowSeconds + 45 } }; } };
    expect((await (await rig({ targets: conv })).service.createIntent(ctx, bound())).mandate.expires).toBe(T0 / 1000 + 45);
  });
  it("the agent supplies identifiers only; terms it shows must equal the server quote exactly", async () => {
    const { service } = await rig();
    await expect(service.createIntent(ctx, bound({ checkout: reviewCheckout() }))).resolves.toBeTruthy();
    await expect(service.createIntent(ctx, bound({ checkout: reviewCheckout({ taxBaseUnits: "1", totalBaseUnits: "101" }) }))).rejects.toEqual(refused("invalid", "quote_mismatch"));
    await expect(service.createIntent(ctx, bound({ amountBaseUnits: "1" }))).rejects.toEqual(refused("invalid", "checkout_invalid"));
    await expect(service.createIntent(ctx, bound({ payee: PAYEE }))).rejects.toEqual(refused("invalid", "checkout_invalid"));
  });
  it("refuses unknown, foreign, mismatched and expired quotes", async () => {
    const { service } = await rig();
    await expect(service.createIntent(ctx, bound({ quoteId: "q-404" }))).rejects.toEqual(refused("invalid", "quote_unknown"));
    await expect(service.createIntent(ctx, bound({ merchantId: "other-merchant" }))).rejects.toEqual(refused("invalid", "quote_unknown"));
    await expect((await rig({ quote: { ownerUserId: 2 } })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "quote_not_owned"));
    await expect((await rig({ quote: { expiresAtMs: T0 } })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "quote_expired"));
    const lying: TpaQuoteResolver = { resolve: async () => ({ merchantId: MERCHANT, quoteId: "q-2", ownerUserId: 1, checkout: reviewCheckout(), expiresAtMs: T0 + 900_000 }) };
    await expect((await rig({ quotes: lying })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "quote_mismatch"));
    const foreign: TpaQuoteResolver = { resolve: async () => ({ merchantId: MERCHANT, quoteId: "q-1", ownerUserId: 1, checkout: reviewCheckout({ merchant: { id: "other", name: "x" } }), expiresAtMs: T0 + 900_000 }) };
    await expect((await rig({ quotes: foreign })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "quote_mismatch"));
    const down: TpaQuoteResolver = { resolve: async () => { throw new Error("down"); } };
    await expect((await rig({ quotes: down })).service.createIntent(ctx, bound())).rejects.toEqual(refused("unavailable", "quote_lookup_failed"));
  });
  it("never guesses a destination", async () => {
    const none: TpaTargetResolver = { resolve: async () => null };
    await expect((await rig({ targets: none })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "destination_unknown"));
    const { service } = await rig();
    await expect(service.createIntent(ctx, bound({ merchantId: MERCHANT, rail: "airwallex-airi" }))).resolves.toBeTruthy();
    const unmappedAiri = await rig({ targets: { resolve: async input => createAiriFixtureResolver({})(input) } });
    await expect(unmappedAiri.service.createIntent(ctx, bound({ rail: "airwallex-airi" }))).rejects.toEqual(refused("invalid", "destination_unknown"));
    const guessed: TpaTargetResolver = { resolve: async input => ({ ...createMetalTargetResolver({ [MERCHANT]: PAYEE }, 63825)(input)!, payee: "awx:beneficiary" }) };
    await expect((await rig({ targets: guessed })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "destination_invalid"));
    const otherRecipient: TpaTargetResolver = { resolve: async input => createMetalTargetResolver({ [MERCHANT]: PAYEE }, 63825)({ ...input, recipientRef: "user:9" }) };
    await expect((await rig({ targets: otherRecipient })).service.createIntent(ctx, bound())).rejects.toEqual(refused("invalid", "destination_mismatch"));
    const down: TpaTargetResolver = { resolve: async () => { throw new Error("down"); } };
    await expect((await rig({ targets: down })).service.createIntent(ctx, bound())).rejects.toEqual(refused("unavailable", "destination_lookup_failed"));
  });
  it("refuses when quote or destination resolution is not configured", async () => {
    await expect((await rig({ quotes: null })).service.createIntent(ctx, bound())).rejects.toEqual(refused("unavailable", "binding_not_configured"));
    await expect((await rig({ targets: null })).service.createIntent(ctx, bound())).rejects.toEqual(refused("unavailable", "binding_not_configured"));
  });
  it("an intent-creation audit failure rolls the intent back", async () => {
    const r = await rig({ failAudit: action => action === "intent_created" });
    await expect(r.service.createIntent(ctx, bound())).rejects.toEqual(expect.objectContaining({ name: "TpaServiceError" }));
    expect(r.memory.tamper.intents.size).toBe(0);
    expect(r.memory.tamper.signatures.size).toBe(0);
  });
});

describe("consume of a 3.1 mandate", () => {
  const consume = (service: Awaited<ReturnType<typeof rig>>["service"], intentId: string, checkout: TpaCheckoutInput = reviewCheckout(), quoteId: string | null = "q-1") =>
    service.consume(ctx, { intentId, consent: true, checkout, ...(quoteId === null ? {} : { quoteId }) });

  it("requires the signed quote id and the exact checkout", async () => {
    const { service, approve } = await rig();
    const intent = await service.createIntent(ctx, bound());
    await approve(intent.id);
    await expect(consume(service, intent.id, reviewCheckout(), "q-2")).rejects.toEqual(refused("terms_changed", "quote_mismatch"));
    await expect(consume(service, intent.id, reviewCheckout(), null)).rejects.toEqual(refused("terms_changed", "quote_mismatch"));
    await expect(consume(service, intent.id, reviewCheckout({ recipient: "user:7002" }))).rejects.toEqual(refused("terms_changed", "recipient_mismatch"));
    await expect(consume(service, intent.id, reviewCheckout({ items: [{ sku: "REVIEW-2", qty: 1, unitPriceBaseUnits: "100" }] }))).rejects.toEqual(refused("terms_changed", "items_mismatch"));
    const ok = await consume(service, intent.id);
    expect(ok.consumed).toBe(true);
    await expect(consume(service, intent.id)).rejects.toEqual(refused("intent"));
  });
  it("refuses after the quote expired even within the mandate TTL window bookkeeping", async () => {
    const r = await rig({ quote: { expiresAtMs: T0 + 60_000 } });
    const intent = await r.service.createIntent(ctx, bound());
    await r.approve(intent.id);
    r.setClock(T0 + 60_000);
    await expect(consume(r.service, intent.id)).rejects.toEqual(refused("intent"));
  });
  it("a consume completion-audit failure leaves the mandate unconsumed", async () => {
    const r = await rig({ failAudit: action => action === "consumed" });
    const intent = await r.service.createIntent(ctx, bound());
    await r.approve(intent.id);
    await expect(consume(r.service, intent.id)).rejects.toEqual(expect.objectContaining({ name: "TpaServiceError" }));
    expect(r.memory.tamper.intents.get(intent.id)?.state).toBe("authorized");
  });
});

describe("readSignedIntent (the dispatch ledger's only intent source)", () => {
  it("returns the verified intent and refuses tampered mandates or signatures", async () => {
    const { service, memory, approve } = await rig();
    const intent = await service.createIntent(ctx, bound());
    await approve(intent.id);
    expect((await service.readSignedIntent(ctx, { intentId: intent.id }))?.mandateHash).toBe(intent.mandateHash);
    expect(await service.readSignedIntent(ctx, { intentId: "f".repeat(64) })).toBeNull();

    const sig = memory.tamper.signatures.get(intent.id)!;
    memory.tamper.signatures.set(intent.id, { ...sig, signature: Buffer.alloc(64, 1).toString("base64url") });
    await expect(service.readSignedIntent(ctx, { intentId: intent.id })).rejects.toEqual(refused("mandate_signature_invalid"));
    memory.tamper.signatures.set(intent.id, sig);

    const row = memory.tamper.intents.get(intent.id)!;
    const forged = { ...JSON.parse(row.mandateJson), paymentTarget: { ...tpaBoundCheckoutMandateSchema.parse(intent.mandate).paymentTarget, payee: "evm:0x00000000000000000000000000000000000000ee" } };
    memory.tamper.intents.set(intent.id, { ...row, mandateJson: JSON.stringify(forged) });
    await expect(service.readSignedIntent(ctx, { intentId: intent.id })).rejects.toEqual(expect.objectContaining({ name: "TpaServiceError" }));
  });
  it("evidence.readIntent keeps its legacy contract (no signature check, owner-bound)", async () => {
    const { service, memory } = await rig();
    const intent = await service.createIntent(ctx, bound());
    expect((await memory.evidence.readIntent({ userId: 1, origin: ORIGIN, intentId: intent.id }))?.mandateHash).toBe(intent.mandateHash);
    expect(await memory.evidence.readIntent({ userId: 2, origin: ORIGIN, intentId: intent.id })).toBeNull();
    expect(await memory.evidence.readIntent({ userId: 1, origin: "https://other.test", intentId: intent.id })).toBeNull();
  });
});

describe("owner approval display data (v3.1)", () => {
  it("createIntent returns the approval summary derived from the signed mandate", async () => {
    const { service } = await rig();
    const intent = await service.createIntent(ctx, bound());
    const m = tpaBoundCheckoutMandateSchema.parse(intent.mandate);
    expect("approval" in intent && intent.approval).toEqual(tpaApprovalSummary(m));
  });
  it("Metal: network, exact rail amount, demo conversion, TPA fee vs network fee cap in base units, max wallet debit", async () => {
    const { service } = await rig();
    const v = tpaApprovalSummary(tpaBoundCheckoutMandateSchema.parse((await service.createIntent(ctx, bound())).mandate));
    expect(v).toMatchObject({ mandateVersion: "3.1", rail: "metal-usdz", network: "evm:63825", payee: `evm:${PAYEE}`, quoteId: "q-1",
      checkoutTotal: { baseUnits: "100", formatted: "1 USD" },
      railAmount: { symbol: "USDZ", decimals: 18, baseUnits: "1000000000000000000", formatted: "1 USDZ" },
      conversion: { id: "usd-usdz-par", nominal: "1 USD = 1 USDZ (nominal)", expires: T0 / 1000 + 900 },
      tpaFee: { baseUnits: "0" },
      networkFeeCap: { symbol: "USDZ", baseUnits: "1000000", formatted: "0.000000000001 USDZ" },
      maxWalletDebit: [{ symbol: "USDZ", baseUnits: "1000000000001000000", formatted: "1.000000000001 USDZ" }] });
    expect(v.conversion.note).toMatch(/^Demo \/ testnet assumption/);
    expect(v.conversion.note).toContain("Not proof of reserves");
    expect(v.tpaFee.meaning).toContain("Zero TPA / platform fee");
    expect(v.tpaFee.meaning).toContain("Network (gas) fees are separate");
    expect(v.networkFeeCap.meaning).toContain("base units");
    expect(v.expiryMeaning).toContain("not a chain-enforced deadline");
    expect(v.conversion.expiresIso).toBe(new Date((T0 / 1000 + 900) * 1000).toISOString());
  });
  it("Airwallex: mock fixture, zero network fee cap, labelled as mock", async () => {
    const { service } = await rig();
    const v = tpaApprovalSummary(tpaBoundCheckoutMandateSchema.parse((await service.createIntent(ctx, bound({ rail: "airwallex-airi" }))).mandate));
    expect(v).toMatchObject({ network: "airwallex:mock-fixture", payee: "awx-mock-fixture:review-fixture", railAmount: { formatted: "1 USD" }, networkFeeCap: { baseUnits: "0" }, maxWalletDebit: [{ baseUnits: "100", formatted: "1 USD" }] });
    expect(v.limits.join(" ")).toContain("mock fixture destination only");
  });
  it("formats exact base units without floats", () => {
    expect(formatAssetBaseUnits("1", 18)).toBe("0.000000000000000001");
    expect(formatAssetBaseUnits("123456789012345678901234567890", 18)).toBe("123456789012.34567890123456789");
    expect(formatAssetBaseUnits("1249", 2)).toBe("12.49");
    expect(formatAssetBaseUnits("0", 18)).toBe("0");
  });
});
