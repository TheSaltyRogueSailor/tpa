import { createHash, randomBytes } from "node:crypto";
import { createTpaAuthority, hasTpaRequestOrigin, type OriginHeaders, type TpaAuthority, type TpaAuthorityConfig } from "./config.js";
import { TPA_MODE, TPA_TTL_SECONDS, canonicalTpaMandate, tpaTransferInput, type TpaTransferInput } from "./domain.js";
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

export class TpaServiceError extends Error {
  constructor(readonly code: "forbidden" | "unauthenticated" | "unavailable" | "rate" | "ceremony" | "intent" | "credential" | "invalid", message: string) {
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

  return {
    authority,
    mode: TPA_MODE,

    async status(context: TpaRequestContext) {
      const base = { enabled: authority.enabled && authority.valid, configuredOrigin: authority.origin, rpID: authority.rpID, ...TPA_MODE };
      if (!context.owner || !authority.enabled || !authority.valid || !hasTpaRequestOrigin(context.headers, authority, true)) return { ...base, originMatches: false, credentials: [], intents: [] };
      const owner = requireOwner(context);
      try {
        const result = await input.store.tpaStatus(binding(owner));
        return { ...base, originMatches: true, ...result };
      } catch (error) { return mapStoreError(error); }
    },

    async registrationOptions(context: TpaRequestContext, value: { label: string; consent: true }) {
      const owner = requireMutationContext(context);
      if (typeof value.label !== "string" || value.label.trim().length < 1 || value.label.trim().length > 64 || value.consent !== true) throw new TpaServiceError("invalid", "A credential label and explicit consent are required.");
      const ceremonyId = nextId(); const challenge = nextChallenge();
      try {
        const created = await input.store.startRegistration({ ...binding(owner), ceremonyId, challenge, label: value.label.trim() });
        const options = await makeRegistrationOptions({ challenge, rpID: authority.rpID, userId: owner.principalId, userName: (input.ownerName ?? (identity => `owner-${identity.principalId}`))(owner), excludeCredentials: created.credentialIds });
        return { ceremonyId: created.ceremonyId, options };
      } catch (error) { return mapStoreError(error); }
    },

    async registrationVerify(context: TpaRequestContext, value: { ceremonyId: string; response: unknown }) {
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
        return { ceremonyId: ceremony.id, accepted: true as const, credential };
      } catch (error) {
        if (error instanceof TpaServiceError) throw error;
        return mapStoreError(error);
      }
    },

    async createIntent(context: TpaRequestContext, value: TpaTransferInput) {
      const owner = requireMutationContext(context);
      const transfer = tpaTransferInput.parse(value);
      validateRecipient(transfer.currency, transfer.recipient);
      const issuedAt = Math.floor(now() / 1_000);
      const mandate = {
        type: "TPA-mandate" as const, version: "2.0" as const, action: "transfer-authorization-pilot" as const,
        issuerUserId: owner.principalId, currency: transfer.currency, paymentNetwork: transfer.currency === "USD" ? "internal-usd-pilot" as const : "dogecoin-mainnet" as const,
        amountBaseUnits: transfer.amountBaseUnits, recipient: transfer.recipient, feeBaseUnits: "0" as const,
        nonce: nextId(), issuedAt, expires: issuedAt + TPA_TTL_SECONDS, scope: "single_use" as const,
        ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" as const,
      };
      const expectedHash = digest(canonicalTpaMandate(mandate));
      try {
        const intent = await input.store.createIntent({ ...binding(owner), id: nextId(), mandate, now: now() });
        if (intent.mandateHash !== expectedHash) throw new TpaServiceError("unavailable", "TPA authorization service is temporarily unavailable.");
        return publicIntent(intent);
      } catch (error) {
        if (error instanceof TpaServiceError) throw error;
        return mapStoreError(error);
      }
    },

    async authenticationOptions(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      const owner = requireMutationContext(context);
      if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
      const ceremonyId = nextId(); const challenge = nextChallenge();
      try {
        const created = await input.store.startAuthorization({ ...binding(owner), ceremonyId, challenge, intentId: value.intentId, now: now() });
        if (!created.intent) throw new TpaServiceError("intent", "The authorization intent is unavailable, expired, or no longer active.");
        const options = await makeAuthenticationOptions({ challenge, rpID: authority.rpID, allowCredentials: created.credentialIds });
        return { ceremonyId: created.ceremonyId, options, mandate: created.intent.mandate, mandateHash: created.intent.mandateHash };
      } catch (error) {
        if (error instanceof TpaServiceError) throw error;
        return mapStoreError(error);
      }
    },

    async authorize(context: TpaRequestContext, value: { intentId: string; ceremonyId: string; response: unknown; consent: true }) {
      const owner = requireMutationContext(context);
      if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
      let ceremony;
      try { ceremony = await input.store.consumeAuthorizationCeremony({ ...binding(owner), ceremonyId: value.ceremonyId, intentId: value.intentId, now: now() }); }
      catch (error) { return mapStoreError(error); }
      let response;
      try { response = parseAuthenticationResponse(value.response); }
      catch { throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted."); }
      if (response.response.userHandle !== undefined && response.response.userHandle !== Buffer.from(String(owner.principalId)).toString("base64url")) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
      try {
        const credential = await input.store.getCredentialForAuthentication({ userId: owner.principalId, credentialId: response.id });
        const verified = await verifyAuthentication({ response, challenge: ceremony.challenge, origin: authority.origin, rpID: authority.rpID, credential: { id: credential.credentialId, publicKey: Buffer.from(credential.publicKeyBase64, "base64url"), counter: credential.counter, transports: JSON.parse(credential.transportsJson) } });
        if (!verified.verified || !verified.authenticationInfo.userVerified || verified.authenticationInfo.credentialID !== credential.credentialId) throw new TpaServiceError("ceremony", "The authorization ceremony was not accepted.");
        const intent = await input.store.finalizeAuthorization({ ...binding(owner), intentId: value.intentId, credentialId: credential.credentialId, newCounter: verified.authenticationInfo.newCounter, now: now() });
        return { accepted: true as const, intent: publicIntent(intent) };
      } catch (error) {
        if (error instanceof TpaServiceError) throw error;
        return mapStoreError(error);
      }
    },

    async consume(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      const owner = requireMutationContext(context);
      if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
      try { return { consumed: true as const, intent: publicIntent(await input.store.consumeIntent({ ...binding(owner), intentId: value.intentId, now: now() })), ...TPA_MODE }; }
      catch (error) { return mapStoreError(error); }
    },

    async revoke(context: TpaRequestContext, value: { intentId: string; consent: true }) {
      const owner = requireMutationContext(context);
      if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
      try { return { revoked: true as const, intent: publicIntent(await input.store.revokeIntent({ ...binding(owner), intentId: value.intentId, now: now() })) }; }
      catch (error) { return mapStoreError(error); }
    },

    async revokeCredential(context: TpaRequestContext, value: { credentialIdHash: string; consent: true }) {
      const owner = requireMutationContext(context);
      if (value.consent !== true) throw new TpaServiceError("invalid", "Explicit consent is required.");
      try { return { revoked: true as const, credential: await input.store.revokeCredential({ userId: owner.principalId, credentialIdHash: value.credentialIdHash, now: now() }) }; }
      catch (error) { return mapStoreError(error); }
    },
  };
}

export type TpaService = ReturnType<typeof createTpaService>;
