import { createHash } from "node:crypto";
import { and, asc, desc, eq, gt, isNull, ne, sql } from "drizzle-orm";
import { tpaCeremonies, tpaCredentials, tpaIntents } from "./schema.js";
import type { TpaHostAdapter } from "./host/contracts.js";
import { TPA_CEREMONY_TTL_MS, TPA_TTL_SECONDS, canonicalTpaMandate, isCheckoutMandate, tpaMandateSchema, type TpaMandate } from "./domain.js";

const MAX_ACTIVE_CREDENTIALS = 3;
const MAX_NEW_CEREMONIES_PER_MINUTE = 10;
const MAX_INTENTS_PER_DAY = 100;
const DAY_MS = 86_400_000;
const HEX_64 = /^[a-f0-9]{64}$/;
const ID_64 = /^[a-f0-9]{64}$/;
const BASE64URL_ID = /^[A-Za-z0-9_-]{1,1364}$/;

type Tx = any;
type StoreInput = { host: TpaHostAdapter };
type CeremonyKind = "registration" | "authorization";
type TrustedNow = number | (() => number);

export class TpaStoreError extends Error {
  constructor(readonly kind: "unavailable" | "rate" | "ceremony" | "intent" | "credential" | "integrity") {
    super(kind);
  }
}

export type TpaCredentialPublic = {
  credentialIdHash: string;
  label: string;
  createdAtMs: number;
  revokedAtMs: number | null;
};

export type TpaIntentPublic = {
  id: string;
  mandate: TpaMandate;
  mandateHash: string;
  state: "pending" | "authorized" | "consumed" | "revoked";
  createdAtMs: number;
  expiresAtMs: number;
  authorizedAtMs: number | null;
  consumedAtMs: number | null;
  revokedAtMs: number | null;
  authorizedCredentialIdHash: string | null;
};

/**
 * A callback executed inside the store transaction after the owner and intent
 * row are locked. It is intentionally generic: evidence persistence can share
 * the exact SQL transaction without the lifecycle store importing it.
 */
export type TpaIntentLifecycleHook = (intent: TpaIntentPublic, transaction: unknown) => Promise<void>;

/** A callback committed with a newly registered credential. */
export type TpaCredentialLifecycleHook = (credential: TpaCredentialPublic, transaction: unknown) => Promise<void>;

class TpaStoreHookError extends Error {
  constructor(readonly original: unknown) { super("lifecycle hook refused"); }
}

async function invokeIntentHook(hook: TpaIntentLifecycleHook | undefined, intent: TpaIntentPublic, transaction: Tx): Promise<void> {
  if (!hook) return;
  try { await hook(intent, transaction); }
  catch (error) { throw new TpaStoreHookError(error); }
}

async function invokeCredentialHook(hook: TpaCredentialLifecycleHook | undefined, credential: TpaCredentialPublic, transaction: Tx): Promise<void> {
  if (!hook) return;
  try { await hook(credential, transaction); }
  catch (error) { throw new TpaStoreHookError(error); }
}

type CredentialPrivate = {
  credentialIdHash: string;
  credentialId: string;
  publicKeyBase64: string;
  counter: number;
  transportsJson: string;
  label: string;
  deviceType: string;
  backedUp: boolean;
  createdAtMs: number;
  revokedAtMs: number | null;
  userId: number;
};

type Ceremony = {
  id: string;
  userId: number;
  sessionHash: string;
  origin: string;
  kind: CeremonyKind;
  challenge: string;
  intentId: string | null;
  label: string | null;
  expiresAtMs: number;
  consumedAtMs: number | null;
  completedAtMs: number | null;
  registeredCredentialIdHash: string | null;
};

function affectedRows(result: unknown): number {
  const first = Array.isArray(result) ? result[0] : result;
  const value = (first as { affectedRows?: unknown } | undefined)?.affectedRows;
  return typeof value === "number" ? value : Number(value ?? 0);
}

function nowMs(value?: TrustedNow): number {
  const now = typeof value === "function" ? value() : value ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new TpaStoreError("unavailable");
  return now;
}

/**
 * Apply the trusted server clock to values that are otherwise only structured input.
 * The route currently generates these values itself; this is a storage-layer backstop
 * for callers that might bypass that route in the future.
 */
function assertMandateTimeBounds(mandate: TpaMandate, current: number): number {
  const expiresAtMs = mandate.expires * 1_000;
  const currentSeconds = Math.floor(current / 1_000);
  if (!Number.isSafeInteger(expiresAtMs)
    || mandate.issuedAt > currentSeconds
    || expiresAtMs <= current
    || expiresAtMs > current + TPA_TTL_SECONDS * 1_000
    || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) {
    throw new TpaStoreError("intent");
  }
  return expiresAtMs;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertBound(userId: number, sessionHash: string, origin: string): void {
  if (!Number.isSafeInteger(userId) || userId < 1 || !HEX_64.test(sessionHash) || origin.length > 255) throw new TpaStoreError("unavailable");
}

function assertId(value: string): void {
  if (!ID_64.test(value)) throw new TpaStoreError("unavailable");
}

async function database(host: TpaHostAdapter) {
  const db = await host.getDb();
  if (!db) throw new TpaStoreError("unavailable");
  return db;
}

async function lockOwner(host: TpaHostAdapter, tx: Tx, userId: number): Promise<void> {
  try { await host.assertOwnerForUpdate(tx, userId); }
  catch { throw new TpaStoreError("unavailable"); }
}

function credentialFromRow(row: any): CredentialPrivate {
  if (!row || !HEX_64.test(row.credentialIdHash) || !BASE64URL_ID.test(row.credentialId) || !BASE64URL_ID.test(row.publicKeyBase64) || !Number.isSafeInteger(Number(row.counter))) {
    throw new TpaStoreError("integrity");
  }
  return {
    credentialIdHash: row.credentialIdHash,
    credentialId: row.credentialId,
    publicKeyBase64: row.publicKeyBase64,
    counter: Number(row.counter),
    transportsJson: typeof row.transportsJson === "string" ? row.transportsJson : "[]",
    label: String(row.label),
    deviceType: String(row.deviceType),
    backedUp: !!row.backedUp,
    createdAtMs: Number(row.createdAtMs),
    revokedAtMs: row.revokedAtMs == null ? null : Number(row.revokedAtMs),
    userId: Number(row.userId),
  };
}

function credentialFields() {
  return {
    credentialIdHash: tpaCredentials.credentialIdHash,
    credentialId: tpaCredentials.credentialId,
    publicKeyBase64: tpaCredentials.publicKeyBase64,
    counter: tpaCredentials.counter,
    transportsJson: tpaCredentials.transportsJson,
    label: tpaCredentials.label,
    deviceType: tpaCredentials.deviceType,
    backedUp: tpaCredentials.backedUp,
    createdAtMs: tpaCredentials.createdAtMs,
    revokedAtMs: tpaCredentials.revokedAtMs,
    userId: tpaCredentials.userId,
  };
}

function ceremonyFields() {
  return {
    id: tpaCeremonies.id,
    userId: tpaCeremonies.userId,
    sessionHash: tpaCeremonies.sessionHash,
    origin: tpaCeremonies.origin,
    kind: tpaCeremonies.kind,
    challenge: tpaCeremonies.challenge,
    intentId: tpaCeremonies.intentId,
    label: tpaCeremonies.label,
    expiresAtMs: tpaCeremonies.expiresAtMs,
    consumedAtMs: tpaCeremonies.consumedAtMs,
    completedAtMs: tpaCeremonies.completedAtMs,
    registeredCredentialIdHash: tpaCeremonies.registeredCredentialIdHash,
  };
}

function ceremonyFromRow(row: any): Ceremony {
  if (!row || !ID_64.test(row.id) || !HEX_64.test(row.sessionHash) || !["registration", "authorization"].includes(row.kind) || typeof row.challenge !== "string"
    || !Number.isSafeInteger(Number(row.expiresAtMs))
    || (row.completedAtMs == null) !== (row.registeredCredentialIdHash == null)
    || (row.completedAtMs != null && (!Number.isSafeInteger(Number(row.completedAtMs)) || !HEX_64.test(row.registeredCredentialIdHash)))) {
    throw new TpaStoreError("integrity");
  }
  return {
    id: row.id,
    userId: Number(row.userId),
    sessionHash: row.sessionHash,
    origin: row.origin,
    kind: row.kind,
    challenge: row.challenge,
    intentId: row.intentId,
    label: row.label,
    expiresAtMs: Number(row.expiresAtMs),
    consumedAtMs: row.consumedAtMs == null ? null : Number(row.consumedAtMs),
    completedAtMs: row.completedAtMs == null ? null : Number(row.completedAtMs),
    registeredCredentialIdHash: row.registeredCredentialIdHash ?? null,
  };
}

function parseTransports(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length > 8 || parsed.some(item => typeof item !== "string" || item.length > 32)) throw new Error();
    return parsed;
  } catch {
    throw new TpaStoreError("integrity");
  }
}

function intentFromRow(row: any): TpaIntentPublic {
  if (!row || !ID_64.test(row.id) || !HEX_64.test(row.sessionHash) || !HEX_64.test(row.mandateHash) || !["pending", "authorized", "consumed", "revoked"].includes(row.state)) {
    throw new TpaStoreError("integrity");
  }
  let mandate: TpaMandate;
  try {
    mandate = tpaMandateSchema.parse(JSON.parse(row.mandateJson));
  } catch {
    throw new TpaStoreError("integrity");
  }
  const canonical = canonicalTpaMandate(mandate);
  if (sha256(canonical) !== row.mandateHash || Number(row.expiresAtMs) !== mandate.expires * 1000 || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS) {
    throw new TpaStoreError("integrity");
  }
  return {
    id: row.id,
    mandate,
    mandateHash: row.mandateHash,
    state: row.state,
    createdAtMs: Number(row.createdAtMs),
    expiresAtMs: Number(row.expiresAtMs),
    authorizedAtMs: row.authorizedAtMs == null ? null : Number(row.authorizedAtMs),
    consumedAtMs: row.consumedAtMs == null ? null : Number(row.consumedAtMs),
    revokedAtMs: row.revokedAtMs == null ? null : Number(row.revokedAtMs),
    authorizedCredentialIdHash: row.authorizedCredentialIdHash ?? null,
  };
}

function intentFields() {
  return {
    id: tpaIntents.id,
    userId: tpaIntents.userId,
    sessionHash: tpaIntents.sessionHash,
    origin: tpaIntents.origin,
    mandateJson: tpaIntents.mandateJson,
    mandateHash: tpaIntents.mandateHash,
    state: tpaIntents.state,
    authorizedCredentialIdHash: tpaIntents.authorizedCredentialIdHash,
    createdAtMs: tpaIntents.createdAtMs,
    expiresAtMs: tpaIntents.expiresAtMs,
    authorizedAtMs: tpaIntents.authorizedAtMs,
    consumedAtMs: tpaIntents.consumedAtMs,
    revokedAtMs: tpaIntents.revokedAtMs,
  };
}

async function lockedIntent(tx: Tx, intentId: string): Promise<any | null> {
  const [row] = await tx.select(intentFields()).from(tpaIntents).where(eq(tpaIntents.id, intentId)).limit(1).for("update");
  return row ?? null;
}

async function lockedCredential(tx: Tx, credentialHash: string): Promise<CredentialPrivate | null> {
  const [row] = await tx.select(credentialFields()).from(tpaCredentials).where(eq(tpaCredentials.credentialIdHash, credentialHash)).limit(1).for("update");
  return row ? credentialFromRow(row) : null;
}

function assertBoundIntent(intentRow: any, userId: number, sessionHash: string, origin: string): TpaIntentPublic {
  if (!intentRow || intentRow.userId !== userId || intentRow.sessionHash !== sessionHash || intentRow.origin !== origin) throw new TpaStoreError("intent");
  return intentFromRow(intentRow);
}

/** Status and revocation recover owner data after a legitimate session rotation. */
function assertOwnerOriginIntent(intentRow: any, userId: number, origin: string): TpaIntentPublic {
  if (!intentRow || intentRow.userId !== userId || intentRow.origin !== origin) throw new TpaStoreError("intent");
  return intentFromRow(intentRow);
}

function assertLive(intent: TpaIntentPublic, now: number, expected: "pending" | "authorized"): void {
  // Expiry equality is expired; issuance has an integer-second mandate lifetime.
  if (intent.state !== expected || intent.expiresAtMs <= now) throw new TpaStoreError("intent");
}

async function consumeCeremony(input: StoreInput & {
  userId: number;
  sessionHash: string;
  origin: string;
  ceremonyId: string;
  kind: CeremonyKind;
  intentId?: string;
  now?: TrustedNow;
}): Promise<Ceremony> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.ceremonyId);
  try {
    const db = await database(input.host);
    const result = await db.transaction(async (tx: Tx): Promise<Ceremony | null> => {
      await lockOwner(input.host, tx, input.userId);
      const [row] = await tx.select(ceremonyFields()).from(tpaCeremonies)
        .where(and(eq(tpaCeremonies.id, input.ceremonyId), eq(tpaCeremonies.userId, input.userId))).limit(1).for("update");
      if (!row) throw new TpaStoreError("ceremony");
      // Burn an owned one-use ceremony before evaluating its binding. This makes a bad
      // assertion, stale session, or wrong ceremony type non-replayable.
      const currentAfterLock = nowMs(input.now);
      const burn = await tx.update(tpaCeremonies).set({ consumedAtMs: currentAfterLock }).where(and(
        eq(tpaCeremonies.id, input.ceremonyId),
        eq(tpaCeremonies.userId, input.userId),
        isNull(tpaCeremonies.consumedAtMs),
      ));
      if (affectedRows(burn) !== 1) throw new TpaStoreError("ceremony");
      let ceremony: Ceremony;
      try { ceremony = ceremonyFromRow(row); } catch { return null; }
      if (ceremony.kind !== input.kind || ceremony.sessionHash !== input.sessionHash || ceremony.origin !== input.origin || ceremony.expiresAtMs <= nowMs(input.now) || (input.intentId !== undefined && ceremony.intentId !== input.intentId)) {
        return null;
      }
      return ceremony;
    });
    if (!result) throw new TpaStoreError("ceremony");
    return result;
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

async function createCeremony(input: StoreInput & {
  userId: number;
  sessionHash: string;
  origin: string;
  id: string;
  challenge: string;
  kind: CeremonyKind;
  intentId?: string;
  label?: string;
  now?: TrustedNow;
  /** Authorization-only work committed with the new ceremony and locked intent. */
  onIntentLocked?: TpaIntentLifecycleHook;
}): Promise<{ ceremonyId: string; expiresAtMs: number; credentialIds: Array<{ id: string; transports: string[] }>; intent?: TpaIntentPublic }> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.id);
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(input.challenge) || (input.label !== undefined && (input.label.length < 1 || input.label.length > 64))) throw new TpaStoreError("unavailable");
  const current = nowMs(input.now);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const currentAfterOwnerLock = nowMs(input.now);
      const [countRow] = await tx.select({ count: sql<number>`COUNT(*)` }).from(tpaCeremonies).where(and(
        eq(tpaCeremonies.userId, input.userId),
        gt(tpaCeremonies.createdAtMs, currentAfterOwnerLock - 60_000),
      ));
      if (Number(countRow?.count ?? 0) >= MAX_NEW_CEREMONIES_PER_MINUTE) throw new TpaStoreError("rate");
      const credentialRows = await tx.select(credentialFields()).from(tpaCredentials).where(and(
        eq(tpaCredentials.userId, input.userId),
        isNull(tpaCredentials.revokedAtMs),
      ));
      const active = credentialRows.map(credentialFromRow);
      let intent: TpaIntentPublic | undefined;
      if (input.kind === "registration") {
        if (active.length >= MAX_ACTIVE_CREDENTIALS) throw new TpaStoreError("credential");
      } else {
        if (!input.intentId) throw new TpaStoreError("unavailable");
        const intentRow = await lockedIntent(tx, input.intentId);
        intent = assertBoundIntent(intentRow, input.userId, input.sessionHash, input.origin);
        // The intent row is another lock point; its usable state is evaluated only
        // after that wait, rather than at transaction entry.
        assertLive(intent, nowMs(input.now), "pending");
        if (active.length === 0) throw new TpaStoreError("credential");
        // Checkout mandates have no trusted unsigned lifecycle. Callers outside
        // the service must supply the hook that verifies evidence and persists
        // the ceremony-to-mandate challenge binding in this transaction.
        if (isCheckoutMandate(intent.mandate) && !input.onIntentLocked) throw new TpaStoreError("integrity");
      }
      const currentAfterLocks = nowMs(input.now);
      const expiresAtMs = currentAfterLocks + TPA_CEREMONY_TTL_MS;
      await tx.insert(tpaCeremonies).values({
        id: input.id,
        userId: input.userId,
        sessionHash: input.sessionHash,
        origin: input.origin,
        kind: input.kind,
        challenge: input.challenge,
        intentId: input.intentId ?? null,
        label: input.label ?? null,
        expiresAtMs,
        createdAtMs: currentAfterLocks,
      });
      // The intent remains locked after lockedIntent(); binding persistence and
      // signature verification therefore share this ceremony transaction.
      if (intent) await invokeIntentHook(input.onIntentLocked, intent, tx);
      // Evidence hooks can await I/O. Re-sample the trusted clock before commit
      // so an expired intent cannot leave an orphaned ceremony or binding.
      const currentBeforeCommit = nowMs(input.now);
      if (intent) assertLive(intent, currentBeforeCommit, "pending");
      if (expiresAtMs <= currentBeforeCommit) throw new TpaStoreError("ceremony");
      return {
        ceremonyId: input.id,
        expiresAtMs,
        credentialIds: active.map((credential: CredentialPrivate) => ({ id: credential.credentialId, transports: parseTransports(credential.transportsJson) })),
        intent,
      };
    });
  } catch (error) {
    if (error instanceof TpaStoreHookError) throw error.original;
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function startRegistration(input: StoreInput & {
  userId: number; sessionHash: string; origin: string; ceremonyId: string; challenge: string; label: string; now?: TrustedNow;
}) {
  return createCeremony({ ...input, id: input.ceremonyId, kind: "registration" });
}

export async function startAuthorization(input: StoreInput & {
  userId: number; sessionHash: string; origin: string; ceremonyId: string; challenge: string; intentId: string; now?: TrustedNow; onIntentLocked?: TpaIntentLifecycleHook;
}) {
  return createCeremony({ ...input, id: input.ceremonyId, kind: "authorization" });
}

export async function getCredentialForAuthentication(input: StoreInput & { userId: number; credentialId: string }): Promise<CredentialPrivate> {
  if (!BASE64URL_ID.test(input.credentialId)) throw new TpaStoreError("credential");
  const digest = sha256(input.credentialId);
  try {
    const db = await database(input.host);
    const [row] = await db.select(credentialFields()).from(tpaCredentials).where(and(
      eq(tpaCredentials.credentialIdHash, digest),
      eq(tpaCredentials.userId, input.userId),
      eq(tpaCredentials.credentialId, input.credentialId),
      isNull(tpaCredentials.revokedAtMs),
    )).limit(1);
    if (!row) throw new TpaStoreError("credential");
    return credentialFromRow(row);
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function consumeRegistrationCeremony(input: StoreInput & { userId: number; sessionHash: string; origin: string; ceremonyId: string; now?: TrustedNow }) {
  return consumeCeremony({ ...input, kind: "registration" });
}

export async function consumeAuthorizationCeremony(input: StoreInput & { userId: number; sessionHash: string; origin: string; ceremonyId: string; intentId: string; now?: TrustedNow }) {
  return consumeCeremony({ ...input, kind: "authorization", intentId: input.intentId });
}

export async function saveVerifiedCredential(input: StoreInput & {
  userId: number;
  sessionHash: string;
  origin: string;
  ceremonyId: string;
  credentialId: string;
  publicKeyBase64: string;
  counter: number;
  transports: string[];
  label: string;
  deviceType: string;
  backedUp: boolean;
  now?: TrustedNow;
  afterSave?: TpaCredentialLifecycleHook;
}): Promise<TpaCredentialPublic> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.ceremonyId);
  if (!BASE64URL_ID.test(input.credentialId) || !BASE64URL_ID.test(input.publicKeyBase64) || !Number.isSafeInteger(input.counter) || input.counter < 0 || input.label.length < 1 || input.label.length > 64 || input.deviceType.length > 32 || input.transports.length > 8) throw new TpaStoreError("credential");
  const digest = sha256(input.credentialId);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      // Registration verification burns before cryptographic verification in the
      // route. Completion below is an independent, transactional one-time claim for
      // this helper, so a previously burned ceremony cannot persist two credentials.
      const [ceremonyRow] = await tx.select(ceremonyFields()).from(tpaCeremonies).where(and(
        eq(tpaCeremonies.id, input.ceremonyId), eq(tpaCeremonies.userId, input.userId), eq(tpaCeremonies.kind, "registration"),
      )).limit(1).for("update");
      let ceremony: Ceremony;
      try { ceremony = ceremonyFromRow(ceremonyRow); } catch { throw new TpaStoreError("ceremony"); }
      const [countRow] = await tx.select({ count: sql<number>`COUNT(*)` }).from(tpaCredentials).where(and(
        eq(tpaCredentials.userId, input.userId), isNull(tpaCredentials.revokedAtMs),
      ));
      if (Number(countRow?.count ?? 0) >= MAX_ACTIVE_CREDENTIALS) throw new TpaStoreError("credential");
      const exists = await lockedCredential(tx, digest);
      if (exists) throw new TpaStoreError("credential");
      // Bind every field established before verification and sample time only after
      // all row locks. A lock wait cannot turn an accepted ceremony into a late save.
      const current = nowMs(input.now);
      if (ceremony.consumedAtMs == null
        || ceremony.completedAtMs !== null
        || ceremony.registeredCredentialIdHash !== null
        || ceremony.sessionHash !== input.sessionHash
        || ceremony.origin !== input.origin
        || ceremony.label !== input.label
        || ceremony.expiresAtMs <= current) throw new TpaStoreError("ceremony");
      const claimed = await tx.update(tpaCeremonies).set({
        completedAtMs: current,
        registeredCredentialIdHash: digest,
      }).where(and(
        eq(tpaCeremonies.id, input.ceremonyId),
        eq(tpaCeremonies.userId, input.userId),
        eq(tpaCeremonies.kind, "registration"),
        isNull(tpaCeremonies.completedAtMs),
        isNull(tpaCeremonies.registeredCredentialIdHash),
      ));
      if (affectedRows(claimed) !== 1) throw new TpaStoreError("ceremony");
      await tx.insert(tpaCredentials).values({
        credentialIdHash: digest,
        userId: input.userId,
        credentialId: input.credentialId,
        publicKeyBase64: input.publicKeyBase64,
        counter: input.counter,
        transportsJson: JSON.stringify(input.transports),
        label: input.label,
        deviceType: input.deviceType,
        backedUp: input.backedUp,
        createdAtMs: current,
      });
      const saved = { credentialIdHash: digest, label: input.label, createdAtMs: current, revokedAtMs: null };
      // Credential evidence is complete only when its approval audit commits in
      // the same transaction. A hook failure rolls back both the credential and
      // the ceremony completion claim.
      await invokeCredentialHook(input.afterSave, saved, tx);
      if (ceremony.expiresAtMs <= nowMs(input.now)) throw new TpaStoreError("ceremony");
      return saved;
    });
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function createIntent(input: StoreInput & {
  userId: number; sessionHash: string; origin: string; id: string; mandate: TpaMandate; now?: TrustedNow; afterCreate?: TpaIntentLifecycleHook;
}): Promise<TpaIntentPublic> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.id);
  let mandate: TpaMandate;
  try { mandate = tpaMandateSchema.parse(input.mandate); } catch { throw new TpaStoreError("intent"); }
  const canonical = canonicalTpaMandate(mandate);
  const mandateHash = sha256(canonical);
  const current = nowMs(input.now);
  if (mandate.issuerUserId !== input.userId) throw new TpaStoreError("intent");
  // Version 3 checkout intents must not be created through an unsigned raw
  // lifecycle path. The service hook atomically saves the server signature and
  // its creation audit. Legacy v2 remains intentionally available to the
  // explicit compatibility mode in the service.
  if (isCheckoutMandate(mandate) && !input.afterCreate) throw new TpaStoreError("integrity");
  const expiresAtMs = assertMandateTimeBounds(mandate, current);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      // The owner row serializes creation for this user. Check both the canonical
      // identity and the nonce separately: a changed mandate must not resurrect a
      // server-issued nonce. The database unique index on (userId, mandateHash) is
      // a second line of defense for writers outside this store.
      const [sameMandate] = await tx.select({ id: tpaIntents.id }).from(tpaIntents).where(and(
        eq(tpaIntents.userId, input.userId), eq(tpaIntents.mandateHash, mandateHash),
      )).limit(1).for("update");
      if (sameMandate) throw new TpaStoreError("intent");
      const [sameNonce] = await tx.select({ id: tpaIntents.id }).from(tpaIntents).where(and(
        eq(tpaIntents.userId, input.userId),
        sql`JSON_UNQUOTE(JSON_EXTRACT(${tpaIntents.mandateJson}, '$.nonce')) = ${mandate.nonce}`,
      )).limit(1).for("update");
      if (sameNonce) throw new TpaStoreError("intent");
      const [countRow] = await tx.select({ count: sql<number>`COUNT(*)` }).from(tpaIntents).where(and(
        eq(tpaIntents.userId, input.userId), gt(tpaIntents.createdAtMs, nowMs(input.now) - DAY_MS),
      ));
      // Do not use the pre-lock time: transaction/row-lock waits can consume the
      // entire bounded lifetime before the insert is eligible to commit.
      const currentAfterLocks = nowMs(input.now);
      const expiresAtMsAfterLocks = assertMandateTimeBounds(mandate, currentAfterLocks);
      if (Number(countRow?.count ?? 0) >= MAX_INTENTS_PER_DAY) throw new TpaStoreError("rate");
      await tx.insert(tpaIntents).values({
        id: input.id,
        userId: input.userId,
        sessionHash: input.sessionHash,
        origin: input.origin,
        mandateJson: JSON.stringify(mandate),
        mandateHash,
        state: "pending",
        createdAtMs: currentAfterLocks,
        expiresAtMs: expiresAtMsAfterLocks,
      });
      const created = {
        id: input.id, mandate, mandateHash, state: "pending" as const, createdAtMs: currentAfterLocks,
        expiresAtMs: expiresAtMsAfterLocks, authorizedAtMs: null, consumedAtMs: null, revokedAtMs: null, authorizedCredentialIdHash: null,
      };
      // A signature and its durable creation audit must commit with the row; a
      // refusal here rolls the insert back and leaves neither orphan behind.
      await invokeIntentHook(input.afterCreate, created, tx);
      assertMandateTimeBounds(mandate, nowMs(input.now));
      return created;
    });
  } catch (error) {
    if (error instanceof TpaStoreHookError) throw error.original;
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function finalizeAuthorization(input: StoreInput & {
  userId: number;
  sessionHash: string;
  origin: string;
  intentId: string;
  credentialId: string;
  newCounter: number;
  now?: TrustedNow;
  beforeFinalize?: TpaIntentLifecycleHook;
  afterFinalize?: TpaIntentLifecycleHook;
}): Promise<TpaIntentPublic> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.intentId);
  if (!BASE64URL_ID.test(input.credentialId) || !Number.isSafeInteger(input.newCounter) || input.newCounter < 0) throw new TpaStoreError("credential");
  const credentialHash = sha256(input.credentialId);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const intentRow = await lockedIntent(tx, input.intentId);
      const intent = assertBoundIntent(intentRow, input.userId, input.sessionHash, input.origin);
      const credential = await lockedCredential(tx, credentialHash);
      const current = nowMs(input.now);
      assertLive(intent, current, "pending");
      // Some authenticators permanently report zero; preserve that standards-compatible
      // case, but once either side has a nonzero counter every assertion must advance it.
      // This check is repeated under the credential row lock, after signature verification.
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null || credential.credentialId !== input.credentialId || ((input.newCounter > 0 || credential.counter > 0) && input.newCounter <= credential.counter)) {
        throw new TpaStoreError("credential");
      }
      if (isCheckoutMandate(intent.mandate) && (!input.beforeFinalize || !input.afterFinalize)) throw new TpaStoreError("integrity");
      // Evidence verification uses this locked, authoritative pending snapshot;
      // no stale pre-transaction read can approve a modified mandate.
      await invokeIntentHook(input.beforeFinalize, intent, tx);
      const currentBeforeTransition = nowMs(input.now);
      assertLive(intent, currentBeforeTransition, "pending");
      const counter = await tx.update(tpaCredentials).set({ counter: input.newCounter }).where(and(
        eq(tpaCredentials.credentialIdHash, credentialHash), eq(tpaCredentials.userId, input.userId), isNull(tpaCredentials.revokedAtMs),
      ));
      if (affectedRows(counter) !== 1 && input.newCounter !== credential.counter) throw new TpaStoreError("credential");
      const authorization = await tx.update(tpaIntents).set({
        state: "authorized", authorizedCredentialIdHash: credentialHash, authorizedAtMs: currentBeforeTransition,
      }).where(and(
        eq(tpaIntents.id, input.intentId), eq(tpaIntents.userId, input.userId), eq(tpaIntents.sessionHash, input.sessionHash), eq(tpaIntents.origin, input.origin),
        eq(tpaIntents.state, "pending"), gt(tpaIntents.expiresAtMs, currentBeforeTransition),
      ));
      if (affectedRows(authorization) !== 1) throw new TpaStoreError("intent");
      const authorized = { ...intent, state: "authorized" as const, authorizedCredentialIdHash: credentialHash, authorizedAtMs: currentBeforeTransition };
      // Fail closed before commit if the durable approval trail cannot be written.
      await invokeIntentHook(input.afterFinalize, authorized, tx);
      if (intent.expiresAtMs <= nowMs(input.now)) throw new TpaStoreError("intent");
      return authorized;
    });
  } catch (error) {
    if (error instanceof TpaStoreHookError) throw error.original;
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function consumeIntent(input: StoreInput & {
  userId: number; sessionHash: string; origin: string; intentId: string; now?: TrustedNow;
  beforeConsume?: TpaIntentLifecycleHook;
  afterConsume?: TpaIntentLifecycleHook;
}): Promise<TpaIntentPublic> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.intentId);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const intentRow = await lockedIntent(tx, input.intentId);
      const intent = assertBoundIntent(intentRow, input.userId, input.sessionHash, input.origin);
      // A pending, consumed, or revoked intent is an ordinary refusal, not a data-integrity fault.
      // Only an "authorized" row without its credential binding is an integrity fault.
      if (intent.state !== "authorized") throw new TpaStoreError("intent");
      if (!intent.authorizedCredentialIdHash) throw new TpaStoreError("integrity");
      const credential = await lockedCredential(tx, intent.authorizedCredentialIdHash);
      const current = nowMs(input.now);
      assertLive(intent, current, "authorized");
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null) throw new TpaStoreError("credential");
      if (isCheckoutMandate(intent.mandate) && (!input.beforeConsume || !input.afterConsume)) throw new TpaStoreError("integrity");
      // Verify signature/hash/checkout and record the use attempt while this
      // authorized intent is locked, before any state transition can commit.
      await invokeIntentHook(input.beforeConsume, intent, tx);
      const currentBeforeTransition = nowMs(input.now);
      assertLive(intent, currentBeforeTransition, "authorized");
      const consumed = await tx.update(tpaIntents).set({ state: "consumed", consumedAtMs: currentBeforeTransition }).where(and(
        eq(tpaIntents.id, input.intentId), eq(tpaIntents.userId, input.userId), eq(tpaIntents.sessionHash, input.sessionHash), eq(tpaIntents.origin, input.origin),
        eq(tpaIntents.state, "authorized"), gt(tpaIntents.expiresAtMs, currentBeforeTransition), eq(tpaIntents.authorizedCredentialIdHash, intent.authorizedCredentialIdHash),
      ));
      if (affectedRows(consumed) !== 1) throw new TpaStoreError("intent");
      const used = { ...intent, state: "consumed" as const, consumedAtMs: currentBeforeTransition };
      await invokeIntentHook(input.afterConsume, used, tx);
      if (intent.expiresAtMs <= nowMs(input.now)) throw new TpaStoreError("intent");
      return used;
    });
  } catch (error) {
    if (error instanceof TpaStoreHookError) throw error.original;
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function revokeIntent(input: StoreInput & {
  userId: number; sessionHash: string; origin: string; intentId: string; now?: TrustedNow;
  afterRevoke?: TpaIntentLifecycleHook;
}): Promise<TpaIntentPublic> {
  assertBound(input.userId, input.sessionHash, input.origin);
  assertId(input.intentId);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const intentRow = await lockedIntent(tx, input.intentId);
      // Revocation is an owner recovery action. Unlike authorize/consume, it need
      // not be trapped in the original login session, but it remains same-origin.
      const intent = assertOwnerOriginIntent(intentRow, input.userId, input.origin);
      const current = nowMs(input.now);
      if (intent.state === "consumed" || intent.state === "revoked") throw new TpaStoreError("intent");
      const revoked = await tx.update(tpaIntents).set({ state: "revoked", revokedAtMs: current }).where(and(
        eq(tpaIntents.id, input.intentId), eq(tpaIntents.userId, input.userId), eq(tpaIntents.origin, input.origin),
        ne(tpaIntents.state, "consumed"), ne(tpaIntents.state, "revoked"),
      ));
      if (affectedRows(revoked) !== 1) throw new TpaStoreError("intent");
      const revokedIntent = { ...intent, state: "revoked" as const, revokedAtMs: current };
      // Revocation remains available without signature verification or a required
      // audit hook: incident containment must not depend on audit availability.
      // A caller may still supply an atomic hook for a stricter deployment.
      await invokeIntentHook(input.afterRevoke, revokedIntent, tx);
      return revokedIntent;
    });
  } catch (error) {
    if (error instanceof TpaStoreHookError) throw error.original;
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function revokeCredential(input: StoreInput & { userId: number; credentialIdHash: string; now?: TrustedNow }): Promise<TpaCredentialPublic> {
  if (!HEX_64.test(input.credentialIdHash)) throw new TpaStoreError("credential");
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const credential = await lockedCredential(tx, input.credentialIdHash);
      const current = nowMs(input.now);
      if (!credential || credential.userId !== input.userId || credential.revokedAtMs !== null) throw new TpaStoreError("credential");
      const revoked = await tx.update(tpaCredentials).set({ revokedAtMs: current }).where(and(
        eq(tpaCredentials.credentialIdHash, input.credentialIdHash), eq(tpaCredentials.userId, input.userId), isNull(tpaCredentials.revokedAtMs),
      ));
      if (affectedRows(revoked) !== 1) throw new TpaStoreError("credential");
      return { credentialIdHash: credential.credentialIdHash, label: credential.label, createdAtMs: credential.createdAtMs, revokedAtMs: current };
    });
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

/**
 * Direct exact-session lookup for service preflight only. This deliberately is
 * not the status listing: a mandate outside its display pagination window must
 * still be found (and then evaluated under locks by the transition itself).
 */
export async function readIntent(input: StoreInput & { userId: number; sessionHash: string; origin: string; intentId: string }): Promise<TpaIntentPublic | null> {
  assertBound(input.userId, input.sessionHash, input.origin);
  if (!ID_64.test(input.intentId)) return null;
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      await lockOwner(input.host, tx, input.userId);
      const [row] = await tx.select(intentFields()).from(tpaIntents).where(and(
        eq(tpaIntents.id, input.intentId),
        eq(tpaIntents.userId, input.userId),
        eq(tpaIntents.sessionHash, input.sessionHash),
        eq(tpaIntents.origin, input.origin),
      )).limit(1);
      return row ? assertBoundIntent(row, input.userId, input.sessionHash, input.origin) : null;
    });
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}

export async function tpaStatus(input: StoreInput & { userId: number; sessionHash: string; origin: string }): Promise<{ credentials: TpaCredentialPublic[]; intents: TpaIntentPublic[] }> {
  assertBound(input.userId, input.sessionHash, input.origin);
  try {
    const db = await database(input.host);
    return await db.transaction(async (tx: Tx) => {
      // Retain the store's defense-in-depth owner guard even though the router also
      // authenticates the current session before reaching this read.
      await lockOwner(input.host, tx, input.userId);
      const [credentialRows, intentRows] = await Promise.all([
        tx.select({ credentialIdHash: tpaCredentials.credentialIdHash, label: tpaCredentials.label, createdAtMs: tpaCredentials.createdAtMs, revokedAtMs: tpaCredentials.revokedAtMs }).from(tpaCredentials).where(eq(tpaCredentials.userId, input.userId)).orderBy(asc(tpaCredentials.revokedAtMs), desc(tpaCredentials.createdAtMs)).limit(32),
        tx.select(intentFields()).from(tpaIntents).where(and(eq(tpaIntents.userId, input.userId), eq(tpaIntents.origin, input.origin))).orderBy(desc(tpaIntents.createdAtMs)).limit(30),
      ]);
      const credentials = credentialRows.map((row: any) => ({ credentialIdHash: String(row.credentialIdHash), label: String(row.label), createdAtMs: Number(row.createdAtMs), revokedAtMs: row.revokedAtMs == null ? null : Number(row.revokedAtMs) }));
      const intents = intentRows.map(intentFromRow);
      return { credentials, intents };
    });
  } catch (error) {
    if (error instanceof TpaStoreError) throw error;
    throw new TpaStoreError("unavailable");
  }
}


/** Binds the persistence operations to one explicit host adapter; no global database or auth singleton is used. */
export function createTpaStore(host: TpaHostAdapter) {
  return {
    startRegistration: (input: Omit<Parameters<typeof startRegistration>[0], "host">) => startRegistration({ ...input, host }),
    startAuthorization: (input: Omit<Parameters<typeof startAuthorization>[0], "host">) => startAuthorization({ ...input, host }),
    getCredentialForAuthentication: (input: Omit<Parameters<typeof getCredentialForAuthentication>[0], "host">) => getCredentialForAuthentication({ ...input, host }),
    consumeRegistrationCeremony: (input: Omit<Parameters<typeof consumeRegistrationCeremony>[0], "host">) => consumeRegistrationCeremony({ ...input, host }),
    consumeAuthorizationCeremony: (input: Omit<Parameters<typeof consumeAuthorizationCeremony>[0], "host">) => consumeAuthorizationCeremony({ ...input, host }),
    saveVerifiedCredential: (input: Omit<Parameters<typeof saveVerifiedCredential>[0], "host">) => saveVerifiedCredential({ ...input, host }),
    createIntent: (input: Omit<Parameters<typeof createIntent>[0], "host">) => createIntent({ ...input, host }),
    finalizeAuthorization: (input: Omit<Parameters<typeof finalizeAuthorization>[0], "host">) => finalizeAuthorization({ ...input, host }),
    consumeIntent: (input: Omit<Parameters<typeof consumeIntent>[0], "host">) => consumeIntent({ ...input, host }),
    revokeIntent: (input: Omit<Parameters<typeof revokeIntent>[0], "host">) => revokeIntent({ ...input, host }),
    revokeCredential: (input: Omit<Parameters<typeof revokeCredential>[0], "host">) => revokeCredential({ ...input, host }),
    readIntent: (input: Omit<Parameters<typeof readIntent>[0], "host">) => readIntent({ ...input, host }),
    tpaStatus: (input: Omit<Parameters<typeof tpaStatus>[0], "host">) => tpaStatus({ ...input, host }),
  };
}

export type TpaStore = ReturnType<typeof createTpaStore>;
