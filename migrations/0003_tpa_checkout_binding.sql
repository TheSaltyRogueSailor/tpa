-- TPA v3.1 checkout binding: the dispatch row keeps the signed checkout fingerprint, the signed payment target hash
-- and the immutable snapshot it may execute or reconcile against. Additive only; apply after 0002.
-- All three columns are NULL on rows written before 3.1 (legacy rows). No backfill: legacy rows are never given
-- v3.1 hashes; they are readable only through the separately labelled historical read-only path.

ALTER TABLE tpa_payment_dispatches
  ADD COLUMN checkoutFingerprint CHAR(64) NULL,
  ADD COLUMN paymentTargetHash CHAR(64) NULL,
  ADD COLUMN snapshotJson TEXT NULL;
