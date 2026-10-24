-- Mandate hardening: server signatures, passkey challenge binding, audit trail.
-- Additive only; apply after 0000_tpa_standalone.sql in a reviewed migration job.
-- Existing 2.0 intents remain readable; checkout (3.0) intents require these tables.

CREATE TABLE IF NOT EXISTS tpa_mandate_signatures (
  intentId VARCHAR(64) NOT NULL,
  userId BIGINT NOT NULL,
  mandateHash VARCHAR(64) NOT NULL,
  keyId VARCHAR(64) NOT NULL,
  algorithm VARCHAR(16) NOT NULL,
  signature VARCHAR(128) NOT NULL,
  createdAtMs BIGINT NOT NULL,
  PRIMARY KEY (intentId)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tpa_challenge_bindings (
  ceremonyId VARCHAR(64) NOT NULL,
  userId BIGINT NOT NULL,
  intentId VARCHAR(64) NOT NULL,
  mandateHash VARCHAR(64) NOT NULL,
  bindingNonce VARCHAR(64) NOT NULL,
  challenge VARCHAR(128) NOT NULL,
  createdAtMs BIGINT NOT NULL,
  PRIMARY KEY (ceremonyId),
  KEY tpa_challenge_binding_intent_idx (intentId)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tpa_audit_events (
  id BIGINT NOT NULL AUTO_INCREMENT,
  userId BIGINT NULL,
  intentId VARCHAR(64) NULL,
  action VARCHAR(32) NOT NULL,
  outcome ENUM('approved', 'refused', 'attempt') NOT NULL,
  reasonCode VARCHAR(48) NOT NULL,
  mandateHash VARCHAR(64) NULL,
  keyId VARCHAR(64) NULL,
  atMs BIGINT NOT NULL,
  PRIMARY KEY (id),
  KEY tpa_audit_user_time_idx (userId, atMs),
  KEY tpa_audit_intent_idx (intentId)
) ENGINE=InnoDB;
