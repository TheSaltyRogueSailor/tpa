import { createHash } from "node:crypto";
import { and, desc, eq, inArray } from "drizzle-orm";
import { TPA_TTL_SECONDS, canonicalTpaMandate, tpaMandateSchema } from "./domain.js";
import type { TpaHostAdapter } from "./host/contracts.js";
import { tpaAuditEvents, tpaChallengeBindings, tpaIntents, tpaMandateSignatures } from "./schema.js";
import type { TpaIntentPublic } from "./store.js";

/**
 * Hardening evidence persistence (migration 0001): server mandate signatures,
 * passkey challenge bindings, and the approval/refusal audit trail. Kept outside
 * the generated lifecycle store so scripts/sync-lifecycle-store.mjs cannot drop it.
 */
export class TpaEvidenceError extends Error {
  constructor(readonly kind: "unavailable" | "integrity") { super(kind); }
}

export type TpaStoredSignature = { intentId: string; userId: number; mandateHash: string; keyId: string; algorithm: string; signature: string; createdAtMs: number };
export type TpaChallengeBinding = { ceremonyId: string; userId: number; intentId: string; mandateHash: string; bindingNonce: string; challenge: string; createdAtMs: number };
export type TpaAuditOutcome = "approved" | "refused" | "attempt";
export type TpaAuditEvent = { userId: number | null; intentId: string | null; action: string; outcome: TpaAuditOutcome; reasonCode: string; mandateHash?: string | null; keyId?: string | null; atMs: number };
export type TpaAuditRecord = TpaAuditEvent & { id: number };

const HEX_64 = /^[a-f0-9]{64}$/;
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

/** challenge = base64url(SHA-256(mandateHash bytes || bindingNonce bytes)); both inputs are 32 bytes. */
export function deriveTpaMandateChallenge(mandateHash: string, bindingNonce: string): string {
  const nonce = Buffer.from(bindingNonce, "base64url");
  if (!HEX_64.test(mandateHash) || nonce.length !== 32 || nonce.toString("base64url") !== bindingNonce) throw new TpaEvidenceError("integrity");
  return createHash("sha256").update(Buffer.concat([Buffer.from(mandateHash, "hex"), nonce])).digest("base64url");
}

export function createTpaEvidenceStore(host: TpaHostAdapter) {
  async function db(): Promise<any> {
    const database = await host.getDb();
    if (!database) throw new TpaEvidenceError("unavailable");
    return database;
  }
  async function connection(transaction?: unknown): Promise<any> { return transaction ?? db(); }
  async function run<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch (error) { if (error instanceof TpaEvidenceError) throw error; throw new TpaEvidenceError("unavailable"); }
  }

  return {
    /** Read-only, integrity-checked intent for pre-checks. Owner and origin bound; null when absent. */
    readIntent: (input: { userId: number; origin: string; intentId: string; transaction?: unknown; forUpdate?: boolean }) => run(async (): Promise<TpaIntentPublic | null> => {
      if (!HEX_64.test(input.intentId)) return null;
      const query = (await connection(input.transaction)).select().from(tpaIntents).where(and(eq(tpaIntents.id, input.intentId), eq(tpaIntents.userId, input.userId), eq(tpaIntents.origin, input.origin))).limit(1);
      const [row] = input.forUpdate ? await query.for("update") : await query;
      if (!row) return null;
      let mandate;
      try { mandate = tpaMandateSchema.parse(JSON.parse(row.mandateJson)); } catch { throw new TpaEvidenceError("integrity"); }
      if (sha256(canonicalTpaMandate(mandate)) !== row.mandateHash || Number(row.expiresAtMs) !== mandate.expires * 1000 || mandate.expires - mandate.issuedAt > TPA_TTL_SECONDS || mandate.issuerUserId !== input.userId) {
        throw new TpaEvidenceError("integrity");
      }
      return {
        id: row.id, mandate, mandateHash: row.mandateHash, state: row.state, createdAtMs: Number(row.createdAtMs), expiresAtMs: Number(row.expiresAtMs),
        authorizedAtMs: row.authorizedAtMs == null ? null : Number(row.authorizedAtMs), consumedAtMs: row.consumedAtMs == null ? null : Number(row.consumedAtMs),
        revokedAtMs: row.revokedAtMs == null ? null : Number(row.revokedAtMs), authorizedCredentialIdHash: row.authorizedCredentialIdHash ?? null,
      };
    }),

    saveSignature: (input: TpaStoredSignature & { transaction?: unknown }) => run(async () => {
      const { transaction, ...signature } = input;
      await (await connection(transaction)).insert(tpaMandateSignatures).values(signature);
    }),

    getSignatures: (input: { userId: number; intentIds: string[]; transaction?: unknown; forUpdate?: boolean }) => run(async (): Promise<Map<string, TpaStoredSignature>> => {
      const ids = input.intentIds.filter(id => HEX_64.test(id));
      if (ids.length === 0) return new Map();
      const query = (await connection(input.transaction)).select().from(tpaMandateSignatures).where(and(eq(tpaMandateSignatures.userId, input.userId), inArray(tpaMandateSignatures.intentId, ids)));
      const rows = input.forUpdate ? await query.for("update") : await query;
      return new Map(rows.map((row: any) => [row.intentId, { ...row, userId: Number(row.userId), createdAtMs: Number(row.createdAtMs) }]));
    }),

    saveChallengeBinding: (input: TpaChallengeBinding & { transaction?: unknown }) => run(async () => {
      const { transaction, ...binding } = input;
      await (await connection(transaction)).insert(tpaChallengeBindings).values(binding);
    }),

    getChallengeBinding: (input: { userId: number; ceremonyId: string; transaction?: unknown; forUpdate?: boolean }) => run(async (): Promise<TpaChallengeBinding | null> => {
      if (!HEX_64.test(input.ceremonyId)) return null;
      const query = (await connection(input.transaction)).select().from(tpaChallengeBindings).where(and(eq(tpaChallengeBindings.ceremonyId, input.ceremonyId), eq(tpaChallengeBindings.userId, input.userId))).limit(1);
      const [row] = input.forUpdate ? await query.for("update") : await query;
      return row ? { ...row, userId: Number(row.userId), createdAtMs: Number(row.createdAtMs) } : null;
    }),

    audit: (event: TpaAuditEvent & { transaction?: unknown }) => run(async () => {
      const { transaction, ...auditEvent } = event;
      await (await connection(transaction)).insert(tpaAuditEvents).values({
        userId: auditEvent.userId, intentId: auditEvent.intentId && HEX_64.test(auditEvent.intentId) ? auditEvent.intentId : null, action: auditEvent.action.slice(0, 32),
        outcome: auditEvent.outcome, reasonCode: auditEvent.reasonCode.slice(0, 48), mandateHash: auditEvent.mandateHash ?? null, keyId: auditEvent.keyId ?? null, atMs: auditEvent.atMs,
      });
    }),

    listAudit: (input: { userId: number; intentId?: string; limit?: number }) => run(async (): Promise<TpaAuditRecord[]> => {
      const condition = input.intentId ? and(eq(tpaAuditEvents.userId, input.userId), eq(tpaAuditEvents.intentId, input.intentId)) : eq(tpaAuditEvents.userId, input.userId);
      const rows = await (await db()).select().from(tpaAuditEvents).where(condition).orderBy(desc(tpaAuditEvents.id)).limit(Math.min(Math.max(input.limit ?? 100, 1), 500));
      return rows.map((row: any) => ({ ...row, id: Number(row.id), userId: row.userId == null ? null : Number(row.userId), atMs: Number(row.atMs) }));
    }),
  };
}

export type TpaEvidenceStore = ReturnType<typeof createTpaEvidenceStore>;
