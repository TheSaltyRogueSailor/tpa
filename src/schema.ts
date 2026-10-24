import { bigint, boolean, index, mysqlEnum, mysqlTable, text, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

/**
 * TPA tables intentionally contain only authorization evidence. `userId` is an
 * opaque principal key owned by the integrating host; this package declares no
 * social, wallet, balance, payment, or identity tables.
 */
export const tpaPrincipals = mysqlTable("tpa_principals", {
  id: bigint("id", { mode: "number" }).primaryKey(),
  isOwner: boolean("isOwner").notNull().default(false),
  enabled: boolean("enabled").notNull().default(true),
});

export const tpaCredentials = mysqlTable("tpa_credentials", {
  credentialIdHash: varchar("credentialIdHash", { length: 64 }).primaryKey(),
  userId: bigint("userId", { mode: "number" }).notNull(),
  credentialId: text("credentialId").notNull(),
  publicKeyBase64: text("publicKeyBase64").notNull(),
  counter: bigint("counter", { mode: "number" }).notNull(),
  transportsJson: text("transportsJson").notNull(),
  label: varchar("label", { length: 64 }).notNull(),
  deviceType: varchar("deviceType", { length: 32 }).notNull(),
  backedUp: boolean("backedUp").notNull(),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
  revokedAtMs: bigint("revokedAtMs", { mode: "number" }),
}, table => ({
  userIndex: index("tpa_credential_user_idx").on(table.userId),
}));

export const tpaIntents = mysqlTable("tpa_intents", {
  id: varchar("id", { length: 64 }).primaryKey(),
  userId: bigint("userId", { mode: "number" }).notNull(),
  sessionHash: varchar("sessionHash", { length: 64 }).notNull(),
  origin: varchar("origin", { length: 255 }).notNull(),
  mandateJson: text("mandateJson").notNull(),
  mandateHash: varchar("mandateHash", { length: 64 }).notNull(),
  state: mysqlEnum("state", ["pending", "authorized", "consumed", "revoked"]).notNull().default("pending"),
  authorizedCredentialIdHash: varchar("authorizedCredentialIdHash", { length: 64 }),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
  expiresAtMs: bigint("expiresAtMs", { mode: "number" }).notNull(),
  authorizedAtMs: bigint("authorizedAtMs", { mode: "number" }),
  consumedAtMs: bigint("consumedAtMs", { mode: "number" }),
  revokedAtMs: bigint("revokedAtMs", { mode: "number" }),
}, table => ({
  userCreatedIndex: index("tpa_intent_user_created_idx").on(table.userId, table.createdAtMs),
  userMandateUnique: uniqueIndex("tpa_intent_user_mandate_unique").on(table.userId, table.mandateHash),
}));

export const tpaCeremonies = mysqlTable("tpa_ceremonies", {
  id: varchar("id", { length: 64 }).primaryKey(),
  userId: bigint("userId", { mode: "number" }).notNull(),
  sessionHash: varchar("sessionHash", { length: 64 }).notNull(),
  origin: varchar("origin", { length: 255 }).notNull(),
  kind: mysqlEnum("kind", ["registration", "authorization"]).notNull(),
  challenge: varchar("challenge", { length: 128 }).notNull(),
  intentId: varchar("intentId", { length: 64 }),
  label: varchar("label", { length: 64 }),
  expiresAtMs: bigint("expiresAtMs", { mode: "number" }).notNull(),
  consumedAtMs: bigint("consumedAtMs", { mode: "number" }),
  completedAtMs: bigint("completedAtMs", { mode: "number" }),
  registeredCredentialIdHash: varchar("registeredCredentialIdHash", { length: 64 }),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
}, table => ({
  userCreatedIndex: index("tpa_ceremony_user_created_idx").on(table.userId, table.createdAtMs),
}));

/** Server Ed25519 signature over each intent's canonical mandate (migration 0001). */
export const tpaMandateSignatures = mysqlTable("tpa_mandate_signatures", {
  intentId: varchar("intentId", { length: 64 }).primaryKey(),
  userId: bigint("userId", { mode: "number" }).notNull(),
  mandateHash: varchar("mandateHash", { length: 64 }).notNull(),
  keyId: varchar("keyId", { length: 64 }).notNull(),
  algorithm: varchar("algorithm", { length: 16 }).notNull(),
  signature: varchar("signature", { length: 128 }).notNull(),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
});

/** Binds each authorization ceremony's WebAuthn challenge to a mandate: challenge = SHA-256(mandateHash || bindingNonce). */
export const tpaChallengeBindings = mysqlTable("tpa_challenge_bindings", {
  ceremonyId: varchar("ceremonyId", { length: 64 }).primaryKey(),
  userId: bigint("userId", { mode: "number" }).notNull(),
  intentId: varchar("intentId", { length: 64 }).notNull(),
  mandateHash: varchar("mandateHash", { length: 64 }).notNull(),
  bindingNonce: varchar("bindingNonce", { length: 64 }).notNull(),
  challenge: varchar("challenge", { length: 128 }).notNull(),
  createdAtMs: bigint("createdAtMs", { mode: "number" }).notNull(),
}, table => ({
  intentIndex: index("tpa_challenge_binding_intent_idx").on(table.intentId),
}));

/** Append-only approval/refusal audit trail. Holds no session hashes, challenges, keys or signatures. */
export const tpaAuditEvents = mysqlTable("tpa_audit_events", {
  id: bigint("id", { mode: "number" }).autoincrement().primaryKey(),
  userId: bigint("userId", { mode: "number" }),
  intentId: varchar("intentId", { length: 64 }),
  action: varchar("action", { length: 32 }).notNull(),
  outcome: mysqlEnum("outcome", ["approved", "refused", "attempt"]).notNull(),
  reasonCode: varchar("reasonCode", { length: 48 }).notNull(),
  mandateHash: varchar("mandateHash", { length: 64 }),
  keyId: varchar("keyId", { length: 64 }),
  atMs: bigint("atMs", { mode: "number" }).notNull(),
}, table => ({
  userTimeIndex: index("tpa_audit_user_time_idx").on(table.userId, table.atMs),
  intentIndex: index("tpa_audit_intent_idx").on(table.intentId),
}));

export const tpaSchema = { tpaPrincipals, tpaCredentials, tpaIntents, tpaCeremonies, tpaMandateSignatures, tpaChallengeBindings, tpaAuditEvents };
