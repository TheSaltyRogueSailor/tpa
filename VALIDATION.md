# TPA-only source checkpoint — 2026-10-23

This private source handoff contains the isolated authorization library and the independently locked local attestation ledger. It excludes DingDong's unrelated application source, data, host authentication credentials, financial records and operational accounts. It is not a public sale offer or an assignment of rights.

The standalone library was installed with its own dependency tree, not a symlink to DingDong's dependencies. Frozen installation with lifecycle scripts disabled passed. `pnpm check`, `pnpm test` and `pnpm build` passed: **25 tests across five files**, including eight persisted-lifecycle simulations, explicit host-identity/origin denial, trusted-clock replay checks, completion/rollback and recovery behavior, real synthetic P-256 WebAuthn registrations/assertions, HTTP body limits/parser errors, no-store headers and disabled-by-default activation. The produced library entry point is `dist/index.js` with type declarations; generated output is rebuilt, not committed.

`pnpm audit --prod --json` and the complete `pnpm audit --json` both returned zero known advisories on this release's pinned package tree. Runtime `qs` is patched to 6.16.0. Development tooling is pinned to Vitest 4.1.12 and Vite 8.3.5; the actual compatible peer is declared directly so an older auto-installed Vite cannot persist. This is the result as of the check, not a guarantee against future vulnerabilities.

The copied `ledger/` source was installed independently with its frozen lockfile and scripts disabled, then passed **20 in-memory EVM tests** and its independent complete compiler/toolchain audit with zero advisories. Exact custom-error selector/argument assertions and role grant/revoke/rotation/recovery are included. There is no external blockchain operation, private-key configuration, fund transfer or deployment script. Optional Ganache native µWS absence uses its documented JavaScript fallback.

Tests ran locally on Node 22.13.0 and pnpm 10.18.0. Use a maintained Node 22 LTS with current security patches for any later controlled staging. The included GitHub workflow uses commit-pinned official actions, read-only repository permissions and no credentials for banking, wallet or production deployment. A committed workflow is not a claim that a remote CI run has passed; inspect GitHub Actions for its actual result.

A five-area review of the parent TPA implementation informed trusted-time/post-lock expiry, nonce/hash replay, one-time registration completion, session-rotation recovery, encoded private-document and stale-review fixes. The parent implementation passed 560 non-SMTP application tests across 100 files, types, build, frozen installation and production audit. Its external SMTP authentication test remains explicitly excluded. That parent result does not replace the artifact-specific standalone checks above.

## Mandate hardening validation (2026-10-24, local branch lumi/mandate-hardening)

`pnpm check`, `pnpm build` and `pnpm test` passed with **100 tests across 8 files**. That includes the opt-in database suites, which were run against a disposable local MariaDB 11.8 schema (`TPA_TEST_DATABASE_URL`). Without a database, 31 tests run and 69 are skipped. The ledger still passes its **20 tests**. The new database suites cover:

- exact checkout matching (items added, swapped, removed, re-priced, or changed in quantity; shipping; tax; total; merchant; payee);
- Ed25519 mandate signatures (tampered, missing, unknown key id, impostor key under a known id, rotation, consistent database rewrite);
- binding of the passkey challenge to the mandate;
- audit rows for approvals and refusals.

These are local results and were not run on MySQL 8 or in remote CI.

## Remaining acceptance requirements

The integrating host must supply and validate real authenticated sessions, owner designation, bans/disablement, session revocation, transactional principal locks and exact HTTPS/RP configuration. Real device/browser-origin staging, real MySQL concurrent-operation/restart acceptance, backup/restore drills, independent penetration/security review and purchaser legal/IP review remain required. Local tests are not bank certification, independent face liveness or proof of assets/settlement. No perfect-code or guaranteed-fraud-prevention claim is made.

TPA is authorization evidence only: no payment execution, custody, conversion, independent liveness, host identity-proofing, automatic monitoring or on-chain submission is included. The immutable canonical ledger-domain string is preserved as provenance and does not connect to DingDong or to a deployed Rootstock contract.

## Reviewed external sources

- https://github.com/vitest-dev/vitest/security/advisories/GHSA-qxg6-89mg-rqv8 — maintainer's patched mocker 4.1.12 release.
- https://github.com/advisories/GHSA-x5fp-wj9c-mxmx — patched qs 6.16.0 array-limit advisory.
- https://github.com/advisories/GHSA-4mjr-xmp4-gh2g — patched qs 6.16.0 constructor/isBuffer advisory.
- https://dev.rootstock.io/developers/quickstart/hardhat/ — local ledger compiler EVM target reference.
