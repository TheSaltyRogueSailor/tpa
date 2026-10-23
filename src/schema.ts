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

export const tpaSchema = { tpaPrincipals, tpaCredentials, tpaIntents, tpaCeremonies };
