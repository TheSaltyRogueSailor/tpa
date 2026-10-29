-- Payment dispatch reservations: one row per consumed TPA intent, written before any rail signs.
-- Additive only; apply after 0001_tpa_mandate_hardening.sql. See src/dispatch.ts for the state machine.

CREATE TABLE IF NOT EXISTS tpa_payment_dispatches (
  intentId VARCHAR(64) NOT NULL,
  mandateHash VARCHAR(64) NOT NULL,
  checkoutId VARCHAR(128) NOT NULL,
  rail VARCHAR(32) NOT NULL,
  merchantId VARCHAR(128) NOT NULL,
  currency VARCHAR(8) NOT NULL,
  amountBaseUnits VARCHAR(40) NOT NULL,
  payee VARCHAR(128) NOT NULL,
  railAmount VARCHAR(80) NOT NULL,
  status ENUM('reserved','sent','succeeded') NOT NULL,
  txHash VARCHAR(128) NULL,
  reference VARCHAR(128) NULL,
  resultJson TEXT NULL,
  createdAtMs BIGINT NOT NULL,
  updatedAtMs BIGINT NOT NULL,
  PRIMARY KEY (intentId),
  UNIQUE KEY tpa_dispatch_reference_idx (reference)
) ENGINE=InnoDB;
