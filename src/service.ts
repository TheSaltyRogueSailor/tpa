import { createHash, randomBytes } from "node:crypto";
import { createTpaAuthority, hasTpaRequestOrigin, type OriginHeaders, type TpaAuthority, type TpaAuthorityConfig } from "./config.js";
import {
  TPA_BOUND_CHECKOUT_LEDGER_DOMAIN, TPA_CHECKOUT_LEDGER_DOMAIN, TPA_MODE, TPA_TTL_SECONDS, TpaCheckoutError, boundFingerprintInput, canonicalTpaMandate,
  compareCheckoutToMandate, isBoundCheckoutMandate, isCheckoutMandate, normalizeTpaCheckout, tpaBoundCheckoutMandateSchema, tpaCheckoutInput,
  tpaCheckoutIntentInput, tpaMerchant, tpaTransferInput, type TpaBoundCheckoutMandate, type TpaCheckoutInput, type TpaCheckoutIntentInput,
  type TpaCheckoutMandate, type TpaMandate, type TpaMerchant, type TpaTransferInput,
} from "./domain.js";
import { TPA_QUOTE_ID, TPA_TARGET_RAILS, TpaBindingError, checkoutFingerprint, paymentTargetHash, tpaPaymentTargetSchema, type TpaPaymentTarget } from "./binding.js";
import { tpaApprovalSummary } from "./approval.js";
import { z } from "zod";
import { TpaEvidenceError, deriveTpaMandateChallenge, type TpaEvidenceStore, type TpaStoredSignature } from "./evidence.js";
import type { TpaMandateSigner } from "./signing.js";
import type { TpaIntentPublic } from "./store.js";
import { isDogecoinAddress } from "./dogecoin.js";
import type { TpaAuthenticatedOwner } from "./host/contracts.js";
import type { TpaStore } from "./store.js";
import {
  authenticationOptions as makeAuthenticationOptions,
  parseAuthenticationResponse,
  parseRegistrationResponse,
  registrationOptions as makeRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
} from "./webauthn.js";

export type TpaServiceErrorCode =
  | "forbidden" | "unauthenticated" | "unavailable" | "rate" | "ceremony" | "intent" | "credential" | "invalid"
  /** The presented checkout differs from the signed mandate (see `reason`). */
  | "terms_changed"
  /** The server signature on the mandate is missing, from an unknown key id, or does not verify. */
  | "mandate_signature_invalid"
  /** The passkey challenge is not SHA-256(mandateHash || bindingNonce) for this intent. */
  | "challenge_unbound"
  /** Stored evidence is internally inconsistent (for example a mandate edited without its hash). */
  | "integrity";

export class TpaServiceError extends Error {
  constructor(readonly code: TpaServiceErrorCode, message: string, readonly reason?: string) {
    super(message);
    this.name = "TpaServiceError";
  }
}

/** A merchant quote as the server's own record holds it (today: the TAP checkoutId). Never taken from the agent. */
export type TpaTrustedQuote = Readonly<{ merchantId: string; quoteId: string; ownerUserId: number; checkout: TpaCheckoutInput; expiresAtMs: number }>;
/** Server-side quote lookup (merchant-scoped). Returns null when the quote is unknown to the server. */
export interface TpaQuoteResolver { resolve(input: { ownerUserId: number; merchantId: string; quoteId: string }): Promise<TpaTrustedQuote | null> }
/**
 * Server-side destination resolution, run BEFORE approval so the target is frozen into the signed mandate.
 * Returns null when the destination is unknown or unverified (the intent is then refused, never guessed).
 */
export interface TpaTargetResolver {
  resolve(input: { rail: (typeof TPA_TARGET_RAILS)[number]; merchant: TpaMerchant; recipientRef: string; currency: "USD"; sourceAmountBaseUnits: string; nowSeconds: number }): Promise<TpaPaymentTarget | null>;
}

/** Agent input for a bound (3.1) checkout intent: only identifiers; the terms come from the server's quote record. */
export const tpaBoundIntentInput = z.object({
  merchantId: tpaMerchant.shape.id,
  quoteId: z.string().regex(TPA_QUOTE_ID),
  rail: z.enum(TPA_TARGET_RAILS),
  consent: z.literal(true),
  /** Optional: what the agent showed the owner. Must equal the server quote exactly, or the intent is refused. */
  checkout: tpaCheckoutInput.optional(),
}).strict();
export type TpaBoundIntentInput = z.infer<typeof tpaBoundIntentInput>;

export type TpaRequestContext = Readonly<{
  /** Host-authenticated identity only; never derive this from a URL parameter or request body. */
  owner: TpaAuthenticatedOwner | undefined;
  headers: OriginHeaders;
}>;

export type CreateTpaServiceInput = {
  store: TpaStore;
  authority: TpaAuthority | TpaAuthorityConfig;
  /** Server-generated public display name; do not make it a client input. */
  ownerName?(owner: TpaAuthenticatedOwner): string;
  now?(): number;
  randomId?(): string;
  randomChallenge?(): string;
  /** Ed25519 mandate signer (see signing.ts). Required to issue checkout (3.0) mandates. */
  signer?: TpaMandateSigner;
  /** Signature, challenge-binding and audit persistence (migration 0001). Required for checkout mandates. */
  evidence?: TpaEvidenceStore;
  /**
   * Allow the legacy 2.0 transfer mandate (amount + recipient only) to be created.
   * Default false: new intents must be checkout mandates.
   */
  legacyTransferMandates?: boolean;
  /** Trusted quote and destination resolution. Both are required to issue bound (3.1) checkout mandates. */
  quotes?: TpaQuoteResolver;
  targets?: TpaTargetResolver;
};

function digest(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function randomId(): string { return randomBytes(32).toString("hex"); }
function randomChallenge(): string { return randomBytes(32).toString("base64url"); }

function mapStoreError(error: unknown): never {
  if (error && typeof error === "object" && "kind" in error) {
    const kind = String((error as { kind: unknown }).kind);
    if (kind === "rate") throw new TpaServiceError("rate", "TPA authorization request limit reached. Please wait.");
    if (kind === "credential") throw new TpaServiceError("credential", "An active authorization credential is required.");
    if (kind === "ceremony") throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
    if (kind === "intent") throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
    if (kind === "integrity") throw new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.");
  }
  throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
}

function validateRecipient(currency: "USD" | "DOGE", recipient: string): void {
  if (currency === "USD") {
    if (!/^user:[1-9][0-9]{0,9}$/.test(recipient)) throw new TpaServiceError("invalid", "USD pilot recipient must be a named internal account reference.");
    return;
  }
  if (!isDogecoinAddress(recipient)) throw new TpaServiceError("invalid", "DOGE recipient must be a valid Dogecoin mainnet public address.");
}

function publicIntent<T extends { id: string; mandate: unknown; mandateHash: string; state: string; createdAtMs: number; expiresAtMs: number; authorizedAtMs: number | null; consumedAtMs: number | null; revokedAtMs: number | null; authorizedCredentialIdHash: string | null }>(intent: T) { return intent; }

/**
 * A complete application service for the TPA authorization pilot. It accepts
 * only an already-authenticated owner context from a host boundary. It has no
 * transfer, payment-provider, account-balance, or blockchain submission API.
 */
export function createTpaService(input: CreateTpaServiceInput) {
  const authority = "valid" in input.authority ? input.authority : createTpaAuthority(input.authority);
  const now = input.now ?? Date.now;
  const nextId = input.randomId ?? randomId;
  const nextChallenge = input.randomChallenge ?? randomChallenge;

  function requireOwner(context: TpaRequestContext): TpaAuthenticatedOwner {
    if (!context.owner) throw new TpaServiceError("unauthenticated", "An authenticated owner session is required.");
    if (context.owner.owner !== true || !Number.isSafeInteger(context.owner.principalId) || context.owner.principalId < 1 || !/^[a-f0-9]{64}$/.test(context.owner.sessionHash)) {
      throw new TpaServiceError("forbidden", "Owner access is required.");
    }
    return context.owner;
  }

  function requireMutationContext(context: TpaRequestContext): TpaAuthenticatedOwner {
    const owner = requireOwner(context);
    if (!authority.enabled || !authority.valid || !hasTpaRequestOrigin(context.headers, authority)) throw new TpaServiceError("forbidden", "TPA origin is not permitted.");
    return owner;
  }

  const binding = (owner: TpaAuthenticatedOwner) => ({ userId: owner.principalId, sessionHash: owner.sessionHash, origin: authority.origin });
  const signer = input.signer;
  const evidence = input.evidence;
  const hardened = !!(signer && evidence);

  function asServiceError(error: unknown): TpaServiceError {
    if (error instanceof TpaServiceError) return error;
    if (error instanceof TpaEvidenceError) return error.kind === "integrity" ? new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.") : new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
    if (error instanceof TpaCheckoutError) return new TpaServiceError("invalid", "The checkout is invalid.", error.reason);
    if (error && typeof error === "object" && "kind" in error) { try { mapStoreError(error); } catch (mapped) { return mapped as TpaServiceError; } }
    if (error && typeof error === "object" && (error as { name?: unknown }).name === "ZodError") return new TpaServiceError("invalid", "Invalid TPA request.");
    return new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
  }

  /** Best-effort refusal log; a failed audit write never turns a refusal into an approval. */
  async function auditRefusal(action: string, context: TpaRequestContext, intentId: unknown, error: TpaServiceError) {
    if (!evidence) return;
    const owner = context.owner && Number.isSafeInteger(context.owner.principalId) && context.owner.principalId > 0 ? context.owner.principalId : null;
    try { await evidence.audit({ userId: owner, intentId: typeof intentId === "string" ? intentId : null, action, outcome: "refused", reasonCode: error.reason ? `${error.code}:${error.reason}` : error.code, atMs: now() }); }
    catch { /* audit store outage: the refusal itself still stands */ }
  }

  /** Runs an operation; every refusal is normalized to a TpaServiceError and recorded. */
  async function audited<T>(action: string, context: TpaRequestContext, intentId: unknown, operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch (error) {
      const refusal = asServiceError(error);
      await auditRefusal(action, context, intentId, refusal);
      throw refusal;
    }
  }

  /** Approvals and pre-use attempts must be recorded; failure to record refuses the action (fail closed). */
  async function auditRequired(owner: TpaAuthenticatedOwner, action: string, outcome: "approved" | "attempt", intent: { id: string; mandateHash: string } | null, keyId?: string, transaction?: unknown) {
    if (!evidence) return;
    try { await evidence.audit({ userId: owner.principalId, intentId: intent?.id ?? null, action, outcome, reasonCode: outcome === "attempt" ? "pending" : "ok", mandateHash: intent?.mandateHash ?? null, keyId: keyId ?? null, atMs: now(), transaction }); }
    catch { throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable."); }
  }

  /**
   * Incident-response revocation must remain possible when the optional audit
   * backend is unavailable. Unlike approval evidence, this post-commit audit is
   * therefore deliberately best-effort; callers never see a successful revoke
   * reported as a failure merely because observability is degraded.
   */
  async function auditRevocationBestEffort(owner: TpaAuthenticatedOwner, action: "revoked" | "credential_revoked", intent: { id: string; mandateHash: string } | null) {
    if (!evidence) return;
    try { await evidence.audit({ userId: owner.principalId, intentId: intent?.id ?? null, action, outcome: "approved", reasonCode: "ok", mandateHash: intent?.mandateHash ?? null, keyId: null, atMs: now() }); }
    catch { /* revocation has committed; audit availability must not block containment */ }
  }

  /**
   * Verifies server evidence for an already-locked intent. Checkout mandates are
   * never allowed to degrade to unsigned mode; only explicitly enabled legacy
   * v2 mandates may do so when evidence/signing is unavailable.
   */
  async function verifyLockedIntent(owner: TpaAuthenticatedOwner, intent: TpaIntentPublic, transaction?: unknown): Promise<TpaStoredSignature | null> {
    const checkout = isCheckoutMandate(intent.mandate);
    if (!evidence) {
      if (checkout) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "evidence_not_configured");
      if (input.legacyTransferMandates) return null;
      throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "evidence_not_configured");
    }
    if (!signer) {
      if (checkout) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "signer_not_configured");
      if (input.legacyTransferMandates) return null;
      throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "signer_not_configured");
    }
    const signature = (await evidence.getSignatures({ userId: owner.principalId, intentIds: [intent.id], transaction, forUpdate: !!transaction })).get(intent.id);
    if (!signature) {
      if (!checkout && input.legacyTransferMandates) return null;
      throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "missing");
    }
    if (signature.mandateHash !== intent.mandateHash) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "hash_mismatch");
    const failure = signer.verify(canonicalTpaMandate(intent.mandate), signature);
    if (failure) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", failure);
    return signature;
  }

  /** Read-only preflight used only to derive a challenge; transitions re-verify while locked. */
  async function verifiedIntent(owner: TpaAuthenticatedOwner, intentId: string): Promise<{ intent: TpaIntentPublic; signature: TpaStoredSignature | null } | null> {
    // This exact owner/session/origin-bound read is only for challenge creation.
    // It deliberately never uses the last-30 status listing; the state-changing
    // operation then rechecks evidence under its own intent-row lock.
    let intent;
    try { intent = await input.store.readIntent({ ...binding(owner), intentId }); }
    catch (error) { throw asServiceError(error); }
    if (!intent) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
    return { intent, signature: await verifyLockedIntent(owner, intent) };
  }

  const refuseBinding = (reason: string, message = "The checkout binding could not be established.") => new TpaServiceError("invalid", message, reason);

  /**
   * Builds a 3.1 mandate from server records only: the quote is resolved from the trusted quote store (owner,
   * merchant scope and expiry checked) and the payment target is resolved and frozen here, before approval.
   * Nothing the agent sends besides the identifiers is used, and nothing is filled in later.
   */
  async function boundMandate(owner: TpaAuthenticatedOwner, value: unknown, issuedAt: number): Promise<TpaBoundCheckoutMandate> {
    const parsed = tpaBoundIntentInput.safeParse(value);
    if (!parsed.success) throw new TpaServiceError("invalid", "The checkout is invalid.", "checkout_invalid");
    if (!hardened) throw new TpaServiceError("unavailable", "Mandate signing is not configured.", "signer_not_configured");
    if (!input.quotes || !input.targets) throw new TpaServiceError("unavailable", "Quote and destination resolution are not configured.", "binding_not_configured");
    const request = parsed.data;
    let quote: TpaTrustedQuote | null;
    try { quote = await input.quotes.resolve({ ownerUserId: owner.principalId, merchantId: request.merchantId, quoteId: request.quoteId }); }
    catch { throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.", "quote_lookup_failed"); }
    if (!quote) throw refuseBinding("quote_unknown", "The quote is unknown to the server.");
    if (quote.quoteId !== request.quoteId || quote.merchantId !== request.merchantId || quote.checkout?.merchant?.id !== request.merchantId) throw refuseBinding("quote_mismatch", "The quote is not this merchant's quote.");
    if (quote.ownerUserId !== owner.principalId) throw refuseBinding("quote_not_owned", "The quote was not issued for this owner.");
    if (!Number.isSafeInteger(quote.expiresAtMs) || quote.expiresAtMs <= now()) throw refuseBinding("quote_expired", "The quote has expired.");
    const checkout = normalizeTpaCheckout(structuredClone(quote.checkout));
    if (checkout.currency !== "USD") throw refuseBinding("currency_unsupported", "Bound checkout mandates are USD only.");
    validateRecipient(checkout.currency, checkout.recipient);
    if (request.checkout !== undefined) {
      let shown;
      try { shown = normalizeTpaCheckout(request.checkout); } catch { throw refuseBinding("quote_mismatch", "The checkout shown differs from the server quote."); }
      if (JSON.stringify(shown) !== JSON.stringify(checkout)) throw refuseBinding("quote_mismatch", "The checkout shown differs from the server quote.");
    }
    let resolved: TpaPaymentTarget | null;
    try { resolved = await input.targets.resolve({ rail: request.rail, merchant: checkout.merchant, recipientRef: checkout.recipient, currency: "USD", sourceAmountBaseUnits: checkout.totalBaseUnits, nowSeconds: issuedAt }); }
    catch { throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.", "destination_lookup_failed"); }
    if (!resolved) throw refuseBinding("destination_unknown", "No verified payment destination for this merchant and rail.");
    const targetParsed = tpaPaymentTargetSchema.safeParse(structuredClone(resolved));
    if (!targetParsed.success) throw refuseBinding("destination_invalid", "The resolved payment destination is invalid.");
    const target = targetParsed.data;
    if (target.rail !== request.rail || target.recipientRef !== checkout.recipient || target.sourceAmountBaseUnits !== checkout.totalBaseUnits) throw refuseBinding("destination_mismatch", "The resolved payment destination does not match the checkout.");
    const quoteExpires = Math.floor(quote.expiresAtMs / 1_000);
    const expires = Math.min(issuedAt + TPA_TTL_SECONDS, quoteExpires, target.conversion.expires);
    if (expires <= issuedAt) throw refuseBinding("quote_expired", "The quote or conversion expires before it could be approved.");
    const quoteRef = { merchantId: checkout.merchant.id, quoteId: request.quoteId, expires: quoteExpires };
    const fingerprintInput = boundFingerprintInput({ ...checkout, amountBaseUnits: checkout.totalBaseUnits, currency: "USD", quote: quoteRef });
    let fingerprint: string, targetHash: string;
    try { fingerprint = checkoutFingerprint(fingerprintInput); targetHash = paymentTargetHash(target); }
    catch (error) { throw refuseBinding(error instanceof TpaBindingError ? error.reason : "binding_invalid"); }
    return tpaBoundCheckoutMandateSchema.parse({
      type: "TPA-mandate", version: "3.1", action: "bound-checkout-authorization",
      issuerUserId: owner.principalId, currency: "USD",
      merchant: checkout.merchant, items: checkout.items, shipping: checkout.shipping,
      subtotalBaseUnits: checkout.subtotalBaseUnits, taxBaseUnits: checkout.taxBaseUnits, amountBaseUnits: checkout.totalBaseUnits,
      recipient: checkout.recipient, feeBaseUnits: "0", quote: quoteRef, paymentTarget: target,
      checkoutFingerprint: fingerprint, paymentTargetHash: targetHash,
      nonce: nextId(), issuedAt, expires, scope: "single_use", ledgerDomain: TPA_BOUND_CHECKOUT_LEDGER_DOMAIN,
    } satisfies TpaBoundCheckoutMandate);
  }

  return {
    authority,
    mode: TPA_MODE,

    /**
     * Owner-bound, read-only intent for the payment dispatch ledger: the same integrity-checked read as
     * evidence.readIntent, plus server signature verification for every checkout mandate. Null when absent.
     */
    async readSignedIntent(context: TpaRequestContext, value: { intentId: string }): Promise<TpaIntentPublic | null> {
      const owner = requireOwner(context);
      if (!evidence || !signer) throw new TpaServiceError("unavailable", "Mandate signing is not configured.", "signer_not_configured");
      try {
        const intent = await evidence.readIntent({ userId: owner.principalId, origin: authority.origin, intentId: value.intentId });
        if (!intent) return null;
        if (isCheckoutMandate(intent.mandate)) await verifyLockedIntent(owner, intent);
        return intent;
      } catch (error) { throw asServiceError(error); }
    },

    async status(context: TpaRequestContext) {
      const base = { enabled: authority.enabled && authority.valid, configuredOrigin: authority.origin, rpID: authority.rpID, ...TPA_MODE };
      if (!context.owner || !authority.enabled || !authority.valid || !hasTpaRequestOrigin(context.headers, authority, true)) return { ...base, originMatches: false, credentials: [], intents: [] };
      const owner = requireOwner(context);
      try {
        const result = await input.store.tpaStatus(binding(owner));
        if (!signer || !evidence) return { ...base, originMatches: true, ...result };
        const signatures = await evidence.getSignatures({ userId: owner.principalId, intentIds: result.intents.map(intent => intent.id) });
        const intents = result.intents.map(intent => {
          const stored = signatures.get(intent.id);
          const valid = !!stored && stored.mandateHash === intent.mandateHash && signer.verify(canonicalTpaMandate(intent.mandate), stored) === null;
          return { ...intent, serverSignature: stored ? { keyId: stored.keyId, algorithm: stored.algorithm, signature: stored.signature, valid } : null };
        });
        return { ...base, originMatches: true, ...result, intents, mandateSigningKeys: signer.publicKeys() };
      } catch (error) {
        if (error instanceof TpaEvidenceError) throw asServiceError(error);
        return mapStoreError(error);
      }
    },

    async registrationOptions(context: TpaRequestContext, value: { label: string; consent: true }) {
      return audited("registration_options", context, null, async () => {
        const owner = requireMutationContext(context);
        if (typeof value?.label !== "string" || value.label.trim().length < 1 || value.label.trim().length > 64 || value.consent !== true) throw new TpaServiceError("invalid", "A credential label and explicit consent are required.");
        const ceremonyId = nextId(); const challenge = nextChallenge();
        try {
          const created = await input.store.startRegistration({ ...binding(owner), ceremonyId, challenge, label: value.label.trim(), now });
          const options = await makeRegistrationOptions({ challenge, rpID: authority.rpID, userId: owner.principalId, userName: (input.ownerName ?? (identity => `owner-${identity.principalId}`))(owner), excludeCredentials: created.credentialIds });
          return { ceremonyId: created.ceremonyId, options };
        } catch (error) { return mapStoreError(error); }
      });
    },

    async registrationVerify(context: TpaRequestContext, value: { ceremonyId: string; response: unknown }) {
      return audited("registration_verify", context, null, async () => {
        const owner = requireMutationContext(context);
        let ceremony;
        try { ceremony = await input.store.consumeRegistrationCeremony({ ...binding(owner), ceremonyId: value.ceremonyId, now }); }
        catch (error) { return mapStoreError(error); }
        let response;
        try { response = parseRegistrationResponse(value.response); }
        catch { throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted."); }
        try {
          const verified = await verifyRegistration({ response, challenge: ceremony.challenge, origin: authority.origin, rpID: authority.rpID });
          if (!verified.verified || !verified.registrationInfo.userVerified) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
          const info = verified.registrationInfo;
          const credential = await input.store.saveVerifiedCredential({
            ...binding(owner), ceremonyId: ceremony.id, credentialId: info.credential.id, publicKeyBase64: Buffer.from(info.credential.publicKey).toString("base64url"), counter: info.credential.counter, transports: response.response.transports ?? [], label: ceremony.label ?? "Authorization credential", deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp, now,
            afterSave: async (_saved, transaction) => { await auditRequired(owner, "credential_registered", "approved", null, undefined, transaction); },
          });
          return { ceremonyId: ceremony.id, accepted: true as const, credential };
        } catch (error) {
          if (error instanceof TpaServiceError) throw error;
          if (error && typeof error === "object" && "kind" in error) return mapStoreError(error);
          throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
        }
      });
    },

    /**
     * Creates a single-use mandate. Checkout input (merchant, items, shipping, tax,
     * total) yields a server-signed 3.0 mandate. The legacy transfer shape
     * (currency, amount, recipient) is accepted only with `legacyTransferMandates`.
     */
    async createIntent(context: TpaRequestContext, value: TpaCheckoutIntentInput | TpaTransferInput | TpaBoundIntentInput) {
      return audited("create_intent", context, null, async () => {
        const owner = requireMutationContext(context);
        const isBound = !!value && typeof value === "object" && "quoteId" in value;
        const isLegacy = !isBound && !!value && typeof value === "object" && "amountBaseUnits" in value && !("merchant" in value);
        const issuedAt = Math.floor(now() / 1_000);
        let mandate: TpaMandate;
        if (isBound) {
          mandate = await boundMandate(owner, value, issuedAt);
        } else if (isLegacy) {
          if (!input.legacyTransferMandates) throw new TpaServiceError("invalid", "Checkout details (merchant, items, shipping, tax and total) are required.", "checkout_required");
          const transfer = tpaTransferInput.parse(value);
          validateRecipient(transfer.currency, transfer.recipient);
          mandate = {
            type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot",
            issuerUserId: owner.principalId, currency: transfer.currency, paymentNetwork: transfer.currency === "USD" ? "internal-usd-pilot" : "dogecoin-mainnet",
            amountBaseUnits: transfer.amountBaseUnits, recipient: transfer.recipient, feeBaseUnits: "0",
            nonce: nextId(), issuedAt, expires: issuedAt + TPA_TTL_SECONDS, scope: "single_use",
            ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2",
          };
        } else {
          const parsed = tpaCheckoutIntentInput.safeParse(value);
          if (!parsed.success) throw new TpaServiceError("invalid", "The checkout is invalid.", "checkout_invalid");
          const { consent: _consent, ...checkoutInput } = parsed.data;
          const checkout = normalizeTpaCheckout(checkoutInput);
          validateRecipient(checkout.currency, checkout.recipient);
          if (!hardened) throw new TpaServiceError("unavailable", "Mandate signing is not configured.", "signer_not_configured");
          mandate = {
            type: "TPA-mandate", version: "3.0", action: "checkout-authorization",
            issuerUserId: owner.principalId, currency: checkout.currency, paymentNetwork: checkout.currency === "USD" ? "internal-usd-pilot" : "dogecoin-mainnet",
            merchant: checkout.merchant, items: checkout.items, shipping: checkout.shipping,
            subtotalBaseUnits: checkout.subtotalBaseUnits, taxBaseUnits: checkout.taxBaseUnits, amountBaseUnits: checkout.totalBaseUnits,
            recipient: checkout.recipient, feeBaseUnits: "0",
            nonce: nextId(), issuedAt, expires: issuedAt + TPA_TTL_SECONDS, scope: "single_use",
            ledgerDomain: TPA_CHECKOUT_LEDGER_DOMAIN,
          } satisfies TpaCheckoutMandate;
        }
        const canonical = canonicalTpaMandate(mandate);
        const expectedHash = digest(canonical);
        const id = nextId();
        let serverSignature: TpaStoredSignature | null = null;
        if (signer && evidence) {
          const signed = signer.sign(canonical);
          serverSignature = { intentId: id, userId: owner.principalId, mandateHash: expectedHash, ...signed, createdAtMs: now() };
        }
        let intent: TpaIntentPublic;
        try {
          intent = await input.store.createIntent({
            ...binding(owner), id, mandate, now,
            afterCreate: async (created, transaction) => {
              if (created.mandateHash !== expectedHash) throw new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.");
              // v3 only reaches here with signer + evidence (checked before mandate
              // construction). Persist signature and approval audit in this same
              // transaction as the intent to avoid either kind of orphan.
              if (serverSignature && evidence) await evidence.saveSignature({ ...serverSignature, transaction });
              await auditRequired(owner, "intent_created", "approved", created, serverSignature?.keyId, transaction);
            },
          });
        }
        catch (error) { throw asServiceError(error); }
        if (intent.mandateHash !== expectedHash) throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
        const result = publicIntent(intent);
        // v3.1: the owner approval display data, derived from the signed mandate (network, exact rail amount,
        // conversion and expiry, TPA fee vs network fee cap, maximum wallet debit).
        const approval = isBoundCheckoutMandate(mandate) ? { approval: tpaApprovalSummary(mandate) } : {};
        return serverSignature ? { ...result, ...approval, serverSignature: { keyId: serverSignature.keyId, algorithm: serverSignature.algorithm, signature: serverSignature.signature, valid: true } } : { ...result, ...approval };
      });
    },

    async authenticationOptions(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      return audited("authorization_options", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        // This preflight exists solely to derive the WebAuthn challenge. The
        // authoritative signature/hash/state check is repeated after the intent
        // row is locked inside startAuthorization below.
        const checked = await verifiedIntent(owner, value.intentId);
        const ceremonyId = nextId();
        let challenge: string;
        let bindingNonce: string | null = null;
        if (checked && evidence) {
          // The passkey signs clientDataJSON, which contains this challenge. Deriving it from the
          // mandate hash makes the human's signature commit to exactly this mandate.
          bindingNonce = nextChallenge();
          challenge = deriveTpaMandateChallenge(checked.intent.mandateHash, bindingNonce);
        } else {
          challenge = nextChallenge();
        }
        let created;
        try {
          created = await input.store.startAuthorization({
            ...binding(owner), ceremonyId, challenge, intentId: value.intentId, now,
            onIntentLocked: async (locked, transaction) => {
              await verifyLockedIntent(owner, locked, transaction);
              if (bindingNonce && evidence) {
                const expected = deriveTpaMandateChallenge(locked.mandateHash, bindingNonce);
                if (expected !== challenge) throw new TpaServiceError("challenge_unbound", "The passkey challenge is not bound to this mandate.");
                await evidence.saveChallengeBinding({ ceremonyId, userId: owner.principalId, intentId: locked.id, mandateHash: locked.mandateHash, bindingNonce, challenge, createdAtMs: now(), transaction });
              }
            },
          });
        }
        catch (error) { throw asServiceError(error); }
        if (!created.intent) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
        const options = await makeAuthenticationOptions({ challenge, rpID: authority.rpID, allowCredentials: created.credentialIds });
        return {
          ceremonyId: created.ceremonyId, options, mandate: created.intent.mandate, mandateHash: created.intent.mandateHash,
          ...(bindingNonce ? { challengeBinding: { scheme: "SHA-256(mandateHash || bindingNonce)" as const, bindingNonce }, serverSignature: checked?.signature ? { keyId: checked.signature.keyId, algorithm: checked.signature.algorithm, signature: checked.signature.signature } : null } : {}),
        };
      });
    },

    async authorize(context: TpaRequestContext, value: { intentId: string; ceremonyId: string; response: unknown; consent: true }) {
      return audited("authorize", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let ceremony;
        try { ceremony = await input.store.consumeAuthorizationCeremony({ ...binding(owner), ceremonyId: value.ceremonyId, intentId: value.intentId, now }); }
        catch (error) { return mapStoreError(error); }
        let response;
        try { response = parseAuthenticationResponse(value.response); }
        catch { throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted."); }
        if (response.response.userHandle !== undefined && response.response.userHandle !== Buffer.from(String(owner.principalId)).toString("base64url")) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
        let credential;
        try { credential = await input.store.getCredentialForAuthentication({ userId: owner.principalId, credentialId: response.id }); }
        catch (error) { return mapStoreError(error); }
        let verified;
        try { verified = await verifyAuthentication({ response, challenge: ceremony.challenge, origin: authority.origin, rpID: authority.rpID, credential: { id: credential.credentialId, publicKey: Buffer.from(credential.publicKeyBase64, "base64url"), counter: credential.counter, transports: JSON.parse(credential.transportsJson) } }); }
        catch { throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted."); }
        if (!verified.verified || !verified.authenticationInfo.userVerified || verified.authenticationInfo.credentialID !== credential.credentialId) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
        let intent;
        let lockedSignature: TpaStoredSignature | null = null;
        try {
          intent = await input.store.finalizeAuthorization({
            ...binding(owner), intentId: value.intentId, credentialId: credential.credentialId, newCounter: verified.authenticationInfo.newCounter, now,
            beforeFinalize: async (locked, transaction) => {
              lockedSignature = await verifyLockedIntent(owner, locked, transaction);
              if (evidence) {
                const bound = await evidence.getChallengeBinding({ userId: owner.principalId, ceremonyId: ceremony.id, transaction, forUpdate: true });
                let expected: string | null = null;
                try { expected = bound ? deriveTpaMandateChallenge(locked.mandateHash, bound.bindingNonce) : null; } catch { expected = null; }
                if (!bound || bound.intentId !== locked.id || bound.mandateHash !== locked.mandateHash || bound.challenge !== ceremony.challenge || expected !== ceremony.challenge) {
                  throw new TpaServiceError("challenge_unbound", "The passkey challenge is not bound to this mandate.");
                }
              }
            },
            afterFinalize: async (authorized, transaction) => {
              // `beforeFinalize` locked the same intent and signature row; reuse
              // that result rather than re-verifying unchanged evidence.
              await auditRequired(owner, "authorized", "approved", authorized, lockedSignature?.keyId, transaction);
            },
          });
        }
        catch (error) { throw asServiceError(error); }
        return { accepted: true as const, intent: publicIntent(intent) };
      });
    },

    /**
     * Single use of an authorized mandate. For checkout mandates the caller must
     * present the actual checkout; any difference from the signed mandate is
     * refused with code "terms_changed" and a specific `reason`.
     */
    async consume(context: TpaRequestContext, value: { intentId: string; consent: true; checkout?: TpaCheckoutInput; quoteId?: string }) {
      return audited("consume", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let intent;
        let lockedSignature: TpaStoredSignature | null = null;
        let checkoutMandate = false;
        try {
          intent = await input.store.consumeIntent({
            ...binding(owner), intentId: value.intentId, now,
            beforeConsume: async (locked, transaction) => {
              lockedSignature = await verifyLockedIntent(owner, locked, transaction);
              if (isCheckoutMandate(locked.mandate)) {
                checkoutMandate = true;
                if (value.checkout === undefined) throw new TpaServiceError("terms_changed", "The actual checkout must be presented and match the signed mandate.", "checkout_required");
                const difference = compareCheckoutToMandate(locked.mandate, value.checkout);
                if (difference) throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", difference);
                if (isBoundCheckoutMandate(locked.mandate)) {
                  const bound = locked.mandate;
                  // 3.1: the presented quote must be the signed one, and the fingerprint recomputed from what was
                  // presented must equal the signed fingerprint (same semantics as the field comparison above).
                  if (value.quoteId !== bound.quote.quoteId) throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", "quote_mismatch");
                  const presented = normalizeTpaCheckout(value.checkout);
                  const recomputed = checkoutFingerprint(boundFingerprintInput({ ...presented, currency: "USD", amountBaseUnits: presented.totalBaseUnits, quote: bound.quote }));
                  if (recomputed !== bound.checkoutFingerprint) throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", "fingerprint_mismatch");
                  const at = now();
                  if (at >= bound.quote.expires * 1_000 || at >= bound.paymentTarget.conversion.expires * 1_000) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.", "quote_expired");
                }
              } else if (value.checkout !== undefined) {
                const presented = value.checkout as Partial<TpaCheckoutInput>;
                if (presented.totalBaseUnits !== locked.mandate.amountBaseUnits || presented.recipient !== locked.mandate.recipient || presented.currency !== locked.mandate.currency) {
                  throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", "legacy_mismatch");
                }
              }
              await auditRequired(owner, "consume", "attempt", locked, lockedSignature?.keyId, transaction);
            },
            afterConsume: async (used, transaction) => {
              // `beforeConsume` locked the same intent and signature row.
              await auditRequired(owner, "consumed", "approved", used, lockedSignature?.keyId, transaction);
            },
          });
        }
        catch (error) { throw asServiceError(error); }
        return { consumed: true as const, intent: publicIntent(intent), ...(evidence ? { checkoutMatched: checkoutMandate } : {}), ...TPA_MODE };
      });
    },

    async revoke(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      return audited("revoke", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let intent;
        try { intent = await input.store.revokeIntent({ ...binding(owner), intentId: value.intentId, now }); }
        catch (error) { throw asServiceError(error); }
        await auditRevocationBestEffort(owner, "revoked", intent);
        return { revoked: true as const, intent: publicIntent(intent) };
      });
    },

    async revokeCredential(context: TpaRequestContext, value: { credentialIdHash: string; consent: true }) {
      return audited("revoke_credential", context, null, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let credential;
        try { credential = await input.store.revokeCredential({ userId: owner.principalId, credentialIdHash: value.credentialIdHash, now }); }
        catch (error) { return mapStoreError(error); }
        await auditRevocationBestEffort(owner, "credential_revoked", null);
        return { revoked: true as const, credential };
      });
    },

    /** Owner-scoped audit trail (no secrets). Requires the evidence store. */
    async auditLog(context: TpaRequestContext, value: { intentId?: string; limit?: number } = {}) {
      const owner = requireOwner(context);
      if (!evidence) return [];
      try { return await evidence.listAudit({ userId: owner.principalId, intentId: value.intentId, limit: value.limit }); }
      catch (error) { throw asServiceError(error); }
    },
  };
}

export type TpaService = ReturnType<typeof createTpaService>;
