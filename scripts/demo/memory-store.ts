/**
 * DEMO ONLY: in-memory persistence for the red-team demo (no MySQL, no network).
 *
 * The real `createTpaStore` (src/store.ts) and `createTpaEvidenceStore` (src/evidence.ts)
 * talk to MySQL through Drizzle, with MySQL-only SQL (row locks, JSON_EXTRACT). This file
 * re-implements the same state rules in memory so the demo can drive the REAL
 * `createTpaService`: real mandate canonicalization, real Ed25519 signatures, real WebAuthn
 * ES256 verification, real exact-match checks, real audit calls.
 *
 * Every rule below is ported from src/store.ts / src/evidence.ts:
 *   - ceremonies are one-use (burned before their binding is evaluated) and expire;
 *   - an intent is created "pending", becomes "authorized" only via finalizeAuthorization,
 *     and is consumed once ("authorized" -> "consumed"); pending, consumed, revoked or
 *     expired intents are refused with kind "intent";
 *   - duplicate mandate hashes and reused nonces are refused at creation;
 *   - stored mandates are integrity-checked (hash, expiry, TTL) on every read.
 * It must never be used outside the demo. `tamper` exposes the raw rows so the demo can
 * simulate an attacker who edits storage, exactly like the MySQL test suite does with UPDATE.
 */
import { createHash } from "node:crypto";
import { TPA_CEREMONY_TTL_MS, TPA_TTL_SECONDS, canonicalTpaMandate, tpaMandateSchema, type TpaMandate } from "../../src/domain.js";
import { TpaEvidenceError, type TpaAuditRecord, type TpaChallengeBinding, type TpaEvidenceStore, type TpaStoredSignature } from "../../src/evidence.js";
import { TpaStoreError, type TpaCredentialPublic, type TpaIntentPublic, type TpaStore } from "../../src/store.js";

const MAX_ACTIVE_CREDENTIALS = 3;
const MAX_NEW_CEREMONIES_PER_MINUTE = 10;
const MAX_INTENTS_PER_DAY = 100;
const DAY_MS = 86_400_000;
const HEX_64 = /^[a-f0-9]{64}$/;
const BASE64URL_ID = /^[A-Za-z0-9_-]{1,1364}$/;
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

type CredentialRow = { credentialIdHash: string; credentialId: string; publicKeyBase64: string; counter: number; transportsJson: string; label: string; deviceType: string; backedUp: boolean; createdAtMs: number; revokedAtMs: number | null; userId: number };
type CeremonyRow = { id: string; userId: number; sessionHash: string; origin: string; kind: "registration" | "authorization"; challenge: string; intentId: string | null; label: string | null; expiresAtMs: number; createdAtMs: number; consumedAtMs: number | null; completedAtMs: number | null; registeredCredentialIdHash: string | null };
export type IntentRow = { id: string; userId: number; sessionHash: string; origin: string; mandateJson: string; mandateHash: string; state: TpaIntentPublic["state"]; authorizedCredentialIdHash: string | null; createdAtMs: number; expiresAtMs: number; authorizedAtMs: number | null; consumedAtMs: number | null; revokedAtMs: number | null };

export function createMemoryTpaPersistence(options: { ownerIds: number[] }) {
  const owners = new Set(options.ownerIds);
  const credentials = new Map<string, CredentialRow>();
  const ceremonies = new Map<string, CeremonyRow>();
  const intents = new Map<string, IntentRow>();
  const signatures = new Map<string, TpaStoredSignature>();
  const bindings = new Map<string, TpaChallengeBinding>();
  const audit: TpaAuditRecord[] = [];

  const nowMs = (value?: number) => { const now = value ?? Date.now(); if (!Number.isSafeInteger(now) || now < 0) throw new TpaStoreError("unavailable"); return now; };
  const lockOwner = (userId: number) => { if (!owners.has(userId)) throw new TpaStoreError("unavailable"); };
  const assertBound = (userId: number, sessionHash: string, origin: string) => { if (!Number.isSafeInteger(userId) || userId < 1 || !HEX_64.test(sessionHash) || origin.length > 255) throw new TpaStoreError("unavailable"); };
  const assertId = (value: string) => { if (!HEX_64.test(value)) throw new TpaStoreError("unavailable"); };
  const activeCredentials = (userId: number) => [...credentials.values()].filter(c => c.userId === userId && c.revokedAtMs === null);

  function intentFromRow(row: IntentRow): TpaIntentPublic {
    let mandate: TpaMandate;
    try { mandate = tpaMandateSchema.parse(JSON.parse(row.mandateJson)); } catch { throw new TpaStoreError("integrity"); }
    if (sha256(canonicalTpaMandate(mandate)) !== row.mandateHash || row.expiresAtMs !== mandate.expires * 1000 || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) throw new TpaStoreError("integrity");
    return { id: row.id, mandate, mandateHash: row.mandateHash, state: row.state, createdAtMs: row.createdAtMs, expiresAtMs: row.expiresAtMs, authorizedAtMs: row.authorizedAtMs, consumedAtMs: row.consumedAtMs, revokedAtMs: row.revokedAtMs, authorizedCredentialIdHash: row.authorizedCredentialIdHash };
  }
  function assertBoundIntent(row: IntentRow | undefined, userId: number, sessionHash: string, origin: string) {
    if (!row || row.userId !== userId || row.sessionHash !== sessionHash || row.origin !== origin) throw new TpaStoreError("intent");
    return intentFromRow(row);
  }
  function assertLive(intent: TpaIntentPublic, now: number, expected: "pending" | "authorized") {
    if (intent.state !== expected || intent.expiresAtMs <= now) throw new TpaStoreError("intent");
  }
  function assertMandateTimeBounds(mandate: TpaMandate, current: number) {
    const expiresAtMs = mandate.expires * 1000;
    if (!Number.isSafeInteger(expiresAtMs) || mandate.issuedAt > Math.floor(current / 1000) || expiresAtMs <= current || expiresAtMs > current + TPA_TTL_SECONDS * 1000 || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) throw new TpaStoreError("intent");
    return expiresAtMs;
  }

  function createCeremony(input: { userId: number; sessionHash: string; origin: string; id: string; challenge: string; kind: CeremonyRow["kind"]; intentId?: string; label?: string; now?: number }) {
    assertBound(input.userId, input.sessionHash, input.origin);
    assertId(input.id);
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(input.challenge) || (input.label !== undefined && (input.label.length < 1 || input.label.length > 64))) throw new TpaStoreError("unavailable");
    lockOwner(input.userId);
    const current = nowMs(input.now);
    const recent = [...ceremonies.values()].filter(c => c.userId === input.userId && c.createdAtMs > current - 60_000).length;
    if (recent >= MAX_NEW_CEREMONIES_PER_MINUTE) throw new TpaStoreError("rate");
    const active = activeCredentials(input.userId);
    let intent: TpaIntentPublic | undefined;
    if (input.kind === "registration") {
      if (active.length >= MAX_ACTIVE_CREDENTIALS) throw new TpaStoreError("credential");
    } else {
      if (!input.intentId) throw new TpaStoreError("unavailable");
      intent = assertBoundIntent(intents.get(input.intentId), input.userId, input.sessionHash, input.origin);
      assertLive(intent, current, "pending");
      if (active.length === 0) throw new TpaStoreError("credential");
    }
    if (ceremonies.has(input.id)) throw new TpaStoreError("unavailable");
    const expiresAtMs = current + TPA_CEREMONY_TTL_MS;
    ceremonies.set(input.id, { id: input.id, userId: input.userId, sessionHash: input.sessionHash, origin: input.origin, kind: input.kind, challenge: input.challenge, intentId: input.intentId ?? null, label: input.label ?? null, expiresAtMs, createdAtMs: current, consumedAtMs: null, completedAtMs: null, registeredCredentialIdHash: null });
    return { ceremonyId: input.id, expiresAtMs, credentialIds: active.map(c => ({ id: c.credentialId, transports: JSON.parse(c.transportsJson) as string[] })), intent };
  }

  function consumeCeremony(input: { userId: number; sessionHash: string; origin: string; ceremonyId: string; kind: CeremonyRow["kind"]; intentId?: string; now?: number }) {
    assertBound(input.userId, input.sessionHash, input.origin);
    assertId(input.ceremonyId);
    lockOwner(input.userId);
    const row = ceremonies.get(input.ceremonyId);
    if (!row || row.userId !== input.userId) throw new TpaStoreError("ceremony");
    // Burn first: a bad assertion or the wrong ceremony can never be retried.
    if (row.consumedAtMs !== null) throw new TpaStoreError("ceremony");
    row.consumedAtMs = nowMs(input.now);
    if (row.kind !== input.kind || row.sessionHash !== input.sessionHash || row.origin !== input.origin || row.expiresAtMs <= nowMs(input.now) || (input.intentId !== undefined && row.intentId !== input.intentId)) throw new TpaStoreError("ceremony");
    return { ...row };
  }

  const store: TpaStore = {
    startRegistration: async input => createCeremony({ ...input, id: input.ceremonyId, kind: "registration" }),
    startAuthorization: async input => createCeremony({ ...input, id: input.ceremonyId, kind: "authorization" }),
    consumeRegistrationCeremony: async input => consumeCeremony({ ...input, kind: "registration" }),
    consumeAuthorizationCeremony: async input => consumeCeremony({ ...input, kind: "authorization", intentId: input.intentId }),
    getCredentialForAuthentication: async input => {
      if (!BASE64URL_ID.test(input.credentialId)) throw new TpaStoreError("credential");
      const row = credentials.get(sha256(input.credentialId));
      if (!row || row.userId !== input.userId || row.credentialId !== input.credentialId || row.revokedAtMs !== null) throw new TpaStoreError("credential");
      return { ...row };
    },
    saveVerifiedCredential: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      assertId(input.ceremonyId);
      if (!BASE64URL_ID.test(input.credentialId) || !BASE64URL_ID.test(input.publicKeyBase64) || !Number.isSafeInteger(input.counter) || input.counter < 0 || input.label.length < 1 || input.label.length > 64 || input.deviceType.length > 32 || input.transports.length > 8) throw new TpaStoreError("credential");
      lockOwner(input.userId);
      const digest = sha256(input.credentialId);
      const ceremony = ceremonies.get(input.ceremonyId);
      if (!ceremony || ceremony.userId !== input.userId || ceremony.kind !== "registration") throw new TpaStoreError("ceremony");
      if (activeCredentials(input.userId).length >= MAX_ACTIVE_CREDENTIALS || credentials.has(digest)) throw new TpaStoreError("credential");
      const current = nowMs(input.now);
      if (ceremony.consumedAtMs == null || ceremony.completedAtMs !== null || ceremony.registeredCredentialIdHash !== null || ceremony.sessionHash !== input.sessionHash || ceremony.origin !== input.origin || ceremony.label !== input.label || ceremony.expiresAtMs <= current) throw new TpaStoreError("ceremony");
      ceremony.completedAtMs = current;
      ceremony.registeredCredentialIdHash = digest;
      credentials.set(digest, { credentialIdHash: digest, userId: input.userId, credentialId: input.credentialId, publicKeyBase64: input.publicKeyBase64, counter: input.counter, transportsJson: JSON.stringify(input.transports), label: input.label, deviceType: input.deviceType, backedUp: input.backedUp, createdAtMs: current, revokedAtMs: null });
      return { credentialIdHash: digest, label: input.label, createdAtMs: current, revokedAtMs: null };
    },
    createIntent: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      assertId(input.id);
      let mandate: TpaMandate;
      try { mandate = tpaMandateSchema.parse(input.mandate); } catch { throw new TpaStoreError("intent"); }
      const mandateHash = sha256(canonicalTpaMandate(mandate));
      const current = nowMs(input.now);
      if (mandate.issuerUserId !== input.userId) throw new TpaStoreError("intent");
      const expiresAtMs = assertMandateTimeBounds(mandate, current);
      lockOwner(input.userId);
      const mine = [...intents.values()].filter(row => row.userId === input.userId);
      // Same mandate, or a reused one-time nonce: refused.
      if (mine.some(row => row.mandateHash === mandateHash)) throw new TpaStoreError("intent");
      if (mine.some(row => (JSON.parse(row.mandateJson) as { nonce?: string }).nonce === mandate.nonce)) throw new TpaStoreError("intent");
      if (mine.filter(row => row.createdAtMs > current - DAY_MS).length >= MAX_INTENTS_PER_DAY) throw new TpaStoreError("rate");
      if (intents.has(input.id)) throw new TpaStoreError("unavailable");
      intents.set(input.id, { id: input.id, userId: input.userId, sessionHash: input.sessionHash, origin: input.origin, mandateJson: JSON.stringify(mandate), mandateHash, state: "pending", authorizedCredentialIdHash: null, createdAtMs: current, expiresAtMs, authorizedAtMs: null, consumedAtMs: null, revokedAtMs: null });
      return { id: input.id, mandate, mandateHash, state: "pending", createdAtMs: current, expiresAtMs, authorizedAtMs: null, consumedAtMs: null, revokedAtMs: null, authorizedCredentialIdHash: null };
    },
    finalizeAuthorization: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      assertId(input.intentId);
      if (!BASE64URL_ID.test(input.credentialId) || !Number.isSafeInteger(input.newCounter) || input.newCounter < 0) throw new TpaStoreError("credential");
      const credentialHash = sha256(input.credentialId);
      lockOwner(input.userId);
      const row = intents.get(input.intentId);
      const intent = assertBoundIntent(row, input.userId, input.sessionHash, input.origin);
      const credential = credentials.get(credentialHash);
      const current = nowMs(input.now);
      assertLive(intent, current, "pending");
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null || credential.credentialId !== input.credentialId || ((input.newCounter > 0 || credential.counter > 0) && input.newCounter <= credential.counter)) throw new TpaStoreError("credential");
      credential.counter = input.newCounter;
      Object.assign(row!, { state: "authorized", authorizedCredentialIdHash: credentialHash, authorizedAtMs: current });
      return { ...intent, state: "authorized", authorizedCredentialIdHash: credentialHash, authorizedAtMs: current };
    },
    consumeIntent: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      assertId(input.intentId);
      lockOwner(input.userId);
      const row = intents.get(input.intentId);
      const intent = assertBoundIntent(row, input.userId, input.sessionHash, input.origin);
      // Pending, consumed or revoked: an ordinary refusal ("intent").
      if (intent.state !== "authorized") throw new TpaStoreError("intent");
      if (!intent.authorizedCredentialIdHash) throw new TpaStoreError("integrity");
      const credential = credentials.get(intent.authorizedCredentialIdHash);
      const current = nowMs(input.now);
      assertLive(intent, current, "authorized");
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null) throw new TpaStoreError("credential");
      Object.assign(row!, { state: "consumed", consumedAtMs: current });
      return { ...intent, state: "consumed", consumedAtMs: current };
    },
    revokeIntent: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      assertId(input.intentId);
      lockOwner(input.userId);
      const row = intents.get(input.intentId);
      if (!row || row.userId !== input.userId || row.origin !== input.origin) throw new TpaStoreError("intent");
      const intent = intentFromRow(row);
      const current = nowMs(input.now);
      if (intent.state === "consumed" || intent.state === "revoked") throw new TpaStoreError("intent");
      Object.assign(row, { state: "revoked", revokedAtMs: current });
      return { ...intent, state: "revoked", revokedAtMs: current };
    },
    revokeCredential: async input => {
      if (!HEX_64.test(input.credentialIdHash)) throw new TpaStoreError("credential");
      lockOwner(input.userId);
      const credential = credentials.get(input.credentialIdHash);
      const current = nowMs(input.now);
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null) throw new TpaStoreError("credential");
      credential.revokedAtMs = current;
      return { credentialIdHash: credential.credentialIdHash, label: credential.label, createdAtMs: credential.createdAtMs, revokedAtMs: current } satisfies TpaCredentialPublic;
    },
    tpaStatus: async input => {
      assertBound(input.userId, input.sessionHash, input.origin);
      lockOwner(input.userId);
      const creds = [...credentials.values()].filter(c => c.userId === input.userId).map(c => ({ credentialIdHash: c.credentialIdHash, label: c.label, createdAtMs: c.createdAtMs, revokedAtMs: c.revokedAtMs }));
      const rows = [...intents.values()].filter(r => r.userId === input.userId && r.origin === input.origin).sort((a, b) => b.createdAtMs - a.createdAtMs).slice(0, 30);
      return { credentials: creds, intents: rows.map(intentFromRow) };
    },
  };

  const evidence: TpaEvidenceStore = {
    readIntent: async input => {
      if (!HEX_64.test(input.intentId)) return null;
      const row = intents.get(input.intentId);
      if (!row || row.userId !== input.userId || row.origin !== input.origin) return null;
      let mandate: TpaMandate;
      try { mandate = tpaMandateSchema.parse(JSON.parse(row.mandateJson)); } catch { throw new TpaEvidenceError("integrity"); }
      if (sha256(canonicalTpaMandate(mandate)) !== row.mandateHash || row.expiresAtMs !== mandate.expires * 1000 || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS || mandate.issuerUserId !== input.userId) throw new TpaEvidenceError("integrity");
      return { id: row.id, mandate, mandateHash: row.mandateHash, state: row.state, createdAtMs: row.createdAtMs, expiresAtMs: row.expiresAtMs, authorizedAtMs: row.authorizedAtMs, consumedAtMs: row.consumedAtMs, revokedAtMs: row.revokedAtMs, authorizedCredentialIdHash: row.authorizedCredentialIdHash };
    },
    saveSignature: async input => { signatures.set(input.intentId, { ...input }); },
    getSignatures: async input => new Map(input.intentIds.filter(id => HEX_64.test(id)).map(id => signatures.get(id)).filter((s): s is TpaStoredSignature => !!s && s.userId === input.userId).map(s => [s.intentId, { ...s }])),
    saveChallengeBinding: async input => { bindings.set(input.ceremonyId, { ...input }); },
    getChallengeBinding: async input => { const b = bindings.get(input.ceremonyId); return b && b.userId === input.userId ? { ...b } : null; },
    audit: async event => {
      audit.push({ id: audit.length + 1, userId: event.userId, intentId: event.intentId && HEX_64.test(event.intentId) ? event.intentId : null, action: event.action.slice(0, 32), outcome: event.outcome, reasonCode: event.reasonCode.slice(0, 48), mandateHash: event.mandateHash ?? null, keyId: event.keyId ?? null, atMs: event.atMs });
    },
    listAudit: async input => audit.filter(a => a.userId === input.userId && (!input.intentId || a.intentId === input.intentId)).sort((a, b) => b.id - a.id).slice(0, Math.min(Math.max(input.limit ?? 100, 1), 500)).map(a => ({ ...a })),
  };

  /** Raw row access so the demo can play an attacker who edits storage. */
  const tamper = { intents, signatures, bindings, ceremonies };
  /** Every secret-bearing value held in storage, used to prove the audit log leaks none of them. */
  const secretValues = () => [...signatures.values()].map(s => s.signature).concat([...bindings.values()].flatMap(b => [b.challenge, b.bindingNonce]), [...ceremonies.values()].flatMap(c => [c.challenge, c.sessionHash]), [...credentials.values()].flatMap(c => [c.publicKeyBase64, c.credentialId]));
  return { store, evidence, tamper, secretValues, allAudit: () => audit.map(a => ({ ...a })) };
}
