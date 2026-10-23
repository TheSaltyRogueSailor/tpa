-- Standalone TPA authorization-pilot schema. Apply only to a dedicated MySQL schema.
-- It stores no wallet keys, biometric templates, payment tokens, balances, or chain authority.

CREATE TABLE IF NOT EXISTS tpa_principals (
  id BIGINT NOT NULL,
  isOwner BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tpa_credentials (
  credentialIdHash VARCHAR(64) NOT NULL,
  userId BIGINT NOT NULL,
  credentialId TEXT NOT NULL,
  publicKeyBase64 TEXT NOT NULL,
  counter BIGINT NOT NULL,
  transportsJson TEXT NOT NULL,
  label VARCHAR(64) NOT NULL,
  deviceType VARCHAR(32) NOT NULL,
  backedUp BOOLEAN NOT NULL,
  createdAtMs BIGINT NOT NULL,
  revokedAtMs BIGINT NULL,
  PRIMARY KEY (credentialIdHash),
  KEY tpa_credential_user_idx (userId)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tpa_intents (
  id VARCHAR(64) NOT NULL,
  userId BIGINT NOT NULL,
  sessionHash VARCHAR(64) NOT NULL,
  origin VARCHAR(255) NOT NULL,
  mandateJson TEXT NOT NULL,
  mandateHash VARCHAR(64) NOT NULL,
  state ENUM('pending', 'authorized', 'consumed', 'revoked') NOT NULL DEFAULT 'pending',
  authorizedCredentialIdHash VARCHAR(64) NULL,
  createdAtMs BIGINT NOT NULL,
  expiresAtMs BIGINT NOT NULL,
  authorizedAtMs BIGINT NULL,
  consumedAtMs BIGINT NULL,
  revokedAtMs BIGINT NULL,
  PRIMARY KEY (id),
  KEY tpa_intent_user_created_idx (userId, createdAtMs),
  UNIQUE KEY tpa_intent_user_mandate_unique (userId, mandateHash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tpa_ceremonies (
  id VARCHAR(64) NOT NULL,
  userId BIGINT NOT NULL,
  sessionHash VARCHAR(64) NOT NULL,
  origin VARCHAR(255) NOT NULL,
  kind ENUM('registration', 'authorization') NOT NULL,
  challenge VARCHAR(128) NOT NULL,
  intentId VARCHAR(64) NULL,
  label VARCHAR(64) NULL,
  expiresAtMs BIGINT NOT NULL,
  consumedAtMs BIGINT NULL,
  completedAtMs BIGINT NULL,
  registeredCredentialIdHash VARCHAR(64) NULL,
  createdAtMs BIGINT NOT NULL,
  PRIMARY KEY (id),
  KEY tpa_ceremony_user_created_idx (userId, createdAtMs)
) ENGINE=InnoDB;
