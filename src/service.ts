import { createHash, randomBytes } from "node:crypto";
import { createTpaAuthority, hasTpaRequestOrigin, type OriginHeaders, type TpaAuthority, type TpaAuthorityConfig } from "./config.js";
import {
  TPA_CHECKOUT_LEDGER_DOMAIN, TPA_MODE, TPA_TTL_SECONDS, TpaCheckoutError, canonicalTpaMandate, compareCheckoutToMandate, isCheckoutMandate,
  normalizeTpaCheckout, tpaCheckoutIntentInput, tpaTransferInput, type TpaCheckoutInput, type TpaCheckoutIntentInput, type TpaCheckoutMandate,
  type TpaMandate, type TpaTransferInput,
} from "./domain.js";
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
  async function auditRequired(owner: TpaAuthenticatedOwner, action: string, outcome: "approved" | "attempt", intent: { id: string; mandateHash: string } | null, keyId?: string) {
    if (!evidence) return;
    try { await evidence.audit({ userId: owner.principalId, intentId: intent?.id ?? null, action, outcome, reasonCode: outcome === "attempt" ? "pending" : "ok", mandateHash: intent?.mandateHash ?? null, keyId: keyId ?? null, atMs: now() }); }
    catch { throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable."); }
  }

  /** Reads the intent and verifies its server signature. Null signer/evidence means legacy (unsigned) mode. */
  async function verifiedIntent(owner: TpaAuthenticatedOwner, intentId: string): Promise<{ intent: TpaIntentPublic; signature: TpaStoredSignature | null } | null> {
    if (!evidence) return null;
    const intent = await evidence.readIntent({ userId: owner.principalId, origin: authority.origin, intentId });
    if (!intent) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
    if (!signer) {
      if (isCheckoutMandate(intent.mandate)) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "signer_not_configured");
      return { intent, signature: null };
    }
    const signature = (await evidence.getSignatures({ userId: owner.principalId, intentIds: [intent.id] })).get(intent.id);
    if (!signature) {
      if (!isCheckoutMandate(intent.mandate) && input.legacyTransferMandates) return { intent, signature: null };
      throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "missing");
    }
    if (signature.mandateHash !== intent.mandateHash) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", "hash_mismatch");
    const failure = signer.verify(canonicalTpaMandate(intent.mandate), signature);
    if (failure) throw new TpaServiceError("mandate_signature_invalid", "The mandate's server signature could not be verified.", failure);
    return { intent, signature };
  }

  return {
    authority,
    mode: TPA_MODE,

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
          const created = await input.store.startRegistration({ ...binding(owner), ceremonyId, challenge, label: value.label.trim() });
          const options = await makeRegistrationOptions({ challenge, rpID: authority.rpID, userId: owner.principalId, userName: (input.ownerName ?? (identity => `owner-${identity.principalId}`))(owner), excludeCredentials: created.credentialIds });
          return { ceremonyId: created.ceremonyId, options };
        } catch (error) { return mapStoreError(error); }
      });
    },

    async registrationVerify(context: TpaRequestContext, value: { ceremonyId: string; response: unknown }) {
      return audited("registration_verify", context, null, async () => {
        const owner = requireMutationContext(context);
        let ceremony;
        try { ceremony = await input.store.consumeRegistrationCeremony({ ...binding(owner), ceremonyId: value.ceremonyId }); }
        catch (error) { return mapStoreError(error); }
        let response;
        try { response = parseRegistrationResponse(value.response); }
        catch { throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted."); }
        try {
          const verified = await verifyRegistration({ response, challenge: ceremony.challenge, origin: authority.origin, rpID: authority.rpID });
          if (!verified.verified || !verified.registrationInfo.userVerified) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
          const info = verified.registrationInfo;
          const credential = await input.store.saveVerifiedCredential({ ...binding(owner), ceremonyId: ceremony.id, credentialId: info.credential.id, publicKeyBase64: Buffer.from(info.credential.publicKey).toString("base64url"), counter: info.credential.counter, transports: response.response.transports ?? [], label: ceremony.label ?? "Authorization credential", deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp });
          await auditRequired(owner, "credential_registered", "approved", null);
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
    async createIntent(context: TpaRequestContext, value: TpaCheckoutIntentInput | TpaTransferInput) {
      return audited("create_intent", context, null, async () => {
        const owner = requireMutationContext(context);
        const isLegacy = !!value && typeof value === "object" && "amountBaseUnits" in value && !("merchant" in value);
        const issuedAt = Math.floor(now() / 1_000);
        let mandate: TpaMandate;
        if (isLegacy) {
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
          // Signed before the intent exists: an intent row can never be observed without its signature.
          await evidence.saveSignature(serverSignature);
        }
        let intent: TpaIntentPublic;
        try { intent = await input.store.createIntent({ ...binding(owner), id, mandate, now: now() }); }
        catch (error) { return mapStoreError(error); }
        if (intent.mandateHash !== expectedHash) throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
        await auditRequired(owner, "intent_created", "approved", intent, serverSignature?.keyId);
        const result = publicIntent(intent);
        return serverSignature ? { ...result, serverSignature: { keyId: serverSignature.keyId, algorithm: serverSignature.algorithm, signature: serverSignature.signature, valid: true } } : result;
      });
    },

    async authenticationOptions(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      return audited("authorization_options", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        const checked = await verifiedIntent(owner, value.intentId);
        const ceremonyId = nextId();
        let challenge: string;
        let bindingNonce: string | null = null;
        if (checked && evidence) {
          // The passkey signs clientDataJSON, which contains this challenge. Deriving it from the
          // mandate hash makes the human's signature commit to exactly this mandate.
          bindingNonce = nextChallenge();
          challenge = deriveTpaMandateChallenge(checked.intent.mandateHash, bindingNonce);
          await evidence.saveChallengeBinding({ ceremonyId, userId: owner.principalId, intentId: checked.intent.id, mandateHash: checked.intent.mandateHash, bindingNonce, challenge, createdAtMs: now() });
        } else {
          challenge = nextChallenge();
        }
        let created;
        try { created = await input.store.startAuthorization({ ...binding(owner), ceremonyId, challenge, intentId: value.intentId, now: now() }); }
        catch (error) { return mapStoreError(error); }
        if (!created.intent) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
        if (checked && created.intent.mandateHash !== checked.intent.mandateHash) throw new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.");
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
        try { ceremony = await input.store.consumeAuthorizationCeremony({ ...binding(owner), ceremonyId: value.ceremonyId, intentId: value.intentId, now: now() }); }
        catch (error) { return mapStoreError(error); }
        const checked = await verifiedIntent(owner, value.intentId);
        if (checked && evidence) {
          const bound = await evidence.getChallengeBinding({ userId: owner.principalId, ceremonyId: ceremony.id });
          let expected: string | null = null;
          try { expected = bound ? deriveTpaMandateChallenge(checked.intent.mandateHash, bound.bindingNonce) : null; } catch { expected = null; }
          if (!bound || bound.intentId !== checked.intent.id || bound.mandateHash !== checked.intent.mandateHash || bound.challenge !== ceremony.challenge || expected !== ceremony.challenge) {
            throw new TpaServiceError("challenge_unbound", "The passkey challenge is not bound to this mandate.");
          }
        }
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
        try { intent = await input.store.finalizeAuthorization({ ...binding(owner), intentId: value.intentId, credentialId: credential.credentialId, newCounter: verified.authenticationInfo.newCounter, now: now() }); }
        catch (error) { return mapStoreError(error); }
        if (checked && intent.mandateHash !== checked.intent.mandateHash) throw new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.");
        await auditRequired(owner, "authorized", "approved", intent, checked?.signature?.keyId);
        return { accepted: true as const, intent: publicIntent(intent) };
      });
    },

    /**
     * Single use of an authorized mandate. For checkout mandates the caller must
     * present the actual checkout; any difference from the signed mandate is
     * refused with code "terms_changed" and a specific `reason`.
     */
    async consume(context: TpaRequestContext, value: { intentId: string; consent: true; checkout?: TpaCheckoutInput }) {
      return audited("consume", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        const checked = await verifiedIntent(owner, value.intentId);
        if (checked) {
          if (isCheckoutMandate(checked.intent.mandate)) {
            if (value.checkout === undefined) throw new TpaServiceError("terms_changed", "The actual checkout must be presented and match the signed mandate.", "checkout_required");
            const difference = compareCheckoutToMandate(checked.intent.mandate, value.checkout);
            if (difference) throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", difference);
          } else if (value.checkout !== undefined) {
            const legacy = checked.intent.mandate;
            const presented = value.checkout as Partial<TpaCheckoutInput>;
            if (presented.totalBaseUnits !== legacy.amountBaseUnits || presented.recipient !== legacy.recipient || presented.currency !== legacy.currency) {
              throw new TpaServiceError("terms_changed", "The checkout does not match the mandate the owner approved.", "legacy_mismatch");
            }
          }
          await auditRequired(owner, "consume", "attempt", checked.intent, checked.signature?.keyId);
        }
        let intent;
        try { intent = await input.store.consumeIntent({ ...binding(owner), intentId: value.intentId, now: now() }); }
        catch (error) { return mapStoreError(error); }
        if (checked && intent.mandateHash !== checked.intent.mandateHash) throw new TpaServiceError("integrity", "Stored authorization evidence failed integrity verification.");
        await auditRequired(owner, "consumed", "approved", intent, checked?.signature?.keyId).catch(() => undefined);
        return { consumed: true as const, intent: publicIntent(intent), ...(checked ? { checkoutMatched: isCheckoutMandate(intent.mandate) } : {}), ...TPA_MODE };
      });
    },

    async revoke(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      return audited("revoke", context, value?.intentId, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let intent;
        try { intent = await input.store.revokeIntent({ ...binding(owner), intentId: value.intentId, now: now() }); }
        catch (error) { return mapStoreError(error); }
        await auditRequired(owner, "revoked", "approved", intent).catch(() => undefined);
        return { revoked: true as const, intent: publicIntent(intent) };
      });
    },

    async revokeCredential(context: TpaRequestContext, value: { credentialIdHash: string; consent: true }) {
      return audited("revoke_credential", context, null, async () => {
        const owner = requireMutationContext(context);
        if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
        let credential;
        try { credential = await input.store.revokeCredential({ userId: owner.principalId, credentialIdHash: value.credentialIdHash, now: now() }); }
        catch (error) { return mapStoreError(error); }
        await auditRequired(owner, "credential_revoked", "approved", null).catch(() => undefined);
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
