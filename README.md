# TPA Authorization Pilot: standalone library

This is a reusable, framework-neutral **authorization-evidence pilot**. It creates canonical single-use checkout mandates (mandate version 3.0, plus the 3.1 bound checkout mandate used by TPA Shopper) that bind the merchant, line items, shipping, tax and total, signs each one with a server Ed25519 key, binds the passkey/WebAuthn challenge to that exact mandate for a host-authenticated owner, refuses use unless the checkout presented at consume matches exactly, records approvals and refusals in an audit log, and persists credential, intent and evidence state with MySQL row locking. It is not a payment service, bank integration, custody system, blockchain signing service, wallet, transfer executor, settlement engine, identity proofing service, or independent liveness system.

`TPA_MODE` is intentionally explicit: `paymentExecution: false`, `onChainSubmission: false`, `independentLiveness: "not-configured"`, and `identityClaim: "registered-credential-control"`.

The independently tested source checkpoint is documented in [VALIDATION.md](VALIDATION.md); see [SECURITY.md](SECURITY.md) for remaining banking/security acceptance requirements. No deployment or financial action is included. `.github/workflows/verify.yml` reproduces library and local-ledger checks with read-only repository permissions.

## Package contents

| Path | Purpose |
| --- | --- |
| `src/domain.ts` | Immutable mandate schemas (3.1 bound checkout, 3.0 checkout and legacy 2.0 transfer), canonicalization, checkout comparison, exact base-unit helpers, and explicit pilot boundary. |
| `src/binding.ts` | v3.1 checkout fingerprint and payment target hashes (`TPA-CHECKOUT-FP/3.1`, `TPA-PAYMENT-TARGET/3.1`). |
| `src/approval.ts` | Display data for the owner approval of a 3.1 mandate: network, exact amount, conversion and its expiry, TPA fee, network fee asset and cap, maximum wallet debit. |
| `src/dispatch.ts` | Payment dispatch reservation state machine and its MySQL store (`tpa_payment_dispatches`). |
| `src/config.ts` | Exact HTTPS origin and RP ID authority; fails closed when either is absent or inconsistent. |
| `src/signing.ts` | Ed25519 mandate signer/verifier with key ids for rotation; loads keys from environment. |
| `src/evidence.ts` | Signature, passkey challenge binding, and audit-log persistence; challenge derivation. |
| `src/webauthn.ts` | Bounded WebAuthn request parsers plus registration/authentication options and verification wrappers. |
| `src/store.ts` | MySQL/Drizzle persistence with owner locks, ceremony burn/claim, intent replay defenses, counters, session/origin bindings, and recovery rules. |
| `src/host/contracts.ts` | Required host database and owner-authorization contract. |
| `src/host/minimal-owner.ts` | Working adapter for the included minimal `tpa_principals` table. |
| `src/service.ts` | Framework-neutral service that accepts only caller-provided, host-authenticated owner identity. |
| `src/http/express.ts` | Working bounded Express router factory that requires a host identity resolver. |
| `src/schema.ts`, `migrations/0000_tpa_standalone.sql` | Base data schema: minimal principal contract, credentials, intents, and ceremonies. |
| `migrations/0001_tpa_mandate_hardening.sql` | Adds the mandate signature, challenge binding, and audit event tables. Apply after `0000`. |
| `migrations/0002_tpa_payment_dispatches.sql`, `migrations/0003_tpa_checkout_binding.sql` | Payment dispatch reservations, then the v3.1 binding columns. Additive only; apply in order after `0001`. |
| `client-reference/tpa-client.ts` | Optional compile-tested browser reference using SimpleWebAuthn without a social application UI. |
| `examples/express-host.ts` | Reference host mount showing explicit configuration and host-session seam. It intentionally does not start a server. |
| `scripts/generate-mandate-signing-key.mjs` | Generates an Ed25519 mandate signing key into a 0600 file and prints only the key id and public key. |
| `scripts/sync-lifecycle-store.mjs` | Reusable, fail-closed source transform for a final lifecycle-store refresh. |
| `scripts/redteam-demo.ts`, `scripts/demo/` | Local in-memory red-team demo (see below). |
| `tests/` | Offline synthetic lifecycle, policy, review, and host-boundary tests, plus opt-in database suites for mandate hardening and Proof of Permission refusals. |

The `ledger/` directory is included as an independently locked compiler and local-EVM test package. Its source is part of this TPA-only repository but not part of the authorization library's runtime build. It has no deployment, wallet, signing-key or external-chain path. See `ledger/README.md` and run its installation/test commands separately.

## Requirements

Use Node.js 22 or later, pnpm 10.18.0, MySQL 8/InnoDB, and an HTTPS origin on which the WebAuthn RP ID exactly matches the origin hostname. Keep the deployment database and its migrations under the operator's normal change-control process. Do not apply the migration to a DingDong database or an unrelated application database without review.

The supplied `.npmrc` sets `ignore-scripts=true`. Install deterministically with:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
pnpm test
pnpm build
pnpm audit --prod
```

None of these commands starts a server. `pnpm test` connects to a database only when `TPA_TEST_DATABASE_URL` is set (see [Running the tests](#running-the-tests)); without it the database suites are skipped. Installation and the audit contact the package registry; the other application tests use synthetic fixtures and loopback HTTP only. A nonzero audit result must be investigated rather than bypassed. The checked-in lockfile and `qs` security override preserve the reviewed dependency set.

## Configure deliberately

Copy `.env.example` to an operator-managed deployment secret/configuration system. The file contains placeholders only. A live host integration needs these values:

```dotenv
TPA_ORIGIN=https://tpa.example.invalid
TPA_RP_ID=tpa.example.invalid
TPA_AUTHORIZATION_ENABLED=false
TPA_DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/DATABASE
NODE_ENV=production
TPA_MANDATE_SIGNING_KEY_ID=tpa-example-key-id
TPA_MANDATE_SIGNING_KEY=REPLACE_WITH_BASE64_PKCS8_ED25519_PRIVATE_KEY_FROM_SECRET_MANAGER
TPA_MANDATE_VERIFY_KEYS=
```

| Variable | Required | Meaning |
| --- | --- | --- |
| `TPA_ORIGIN` | Yes | Exact HTTPS origin of the WebAuthn relying party. |
| `TPA_RP_ID` | Yes | WebAuthn RP ID; must exactly equal the hostname of `TPA_ORIGIN`. |
| `TPA_AUTHORIZATION_ENABLED` | Yes | Only the exact value `true` enables authorization. |
| `TPA_DATABASE_URL` | Yes | MySQL connection string, supplied only through a secret manager. |
| `NODE_ENV` | Yes | Keep `production`. Only `development` permits an explicitly configured `https://localhost` authority. |
| `TPA_MANDATE_SIGNING_KEY_ID` | Yes | Id of the active Ed25519 mandate signing key. |
| `TPA_MANDATE_SIGNING_KEY` | Yes | Ed25519 private key as base64 PKCS#8 DER (or PKCS#8 PEM). Keep it in a secret manager. |
| `TPA_MANDATE_VERIFY_KEYS` | No | Retired public keys still accepted during rotation, as `keyId=base64SpkiDer`, comma separated. May be empty. |

Without `TPA_MANDATE_SIGNING_KEY_ID` and `TPA_MANDATE_SIGNING_KEY`, checkout mandates are refused (fail closed), and `examples/express-host.ts` refuses to mount.

Generate a signing key for a new key id with:

```sh
node scripts/generate-mandate-signing-key.mjs <keyId> /secure/path/key.b64
```

The script refuses to overwrite an existing file, writes the base64 PKCS#8 private key to that file with mode 0600, and prints only `TPA_MANDATE_SIGNING_KEY_ID=<keyId>` and the public key (the `keyId=...` value to add to `TPA_MANDATE_VERIFY_KEYS` after a later rotation). Load the private key into the secret manager as `TPA_MANDATE_SIGNING_KEY`, then delete the file. Never commit it; `.gitignore` excludes `*.pem`, `*.key` and `*.b64` files as a safety net.

Authorization remains disabled unless the operator explicitly sets the exact activation value `true` after staging approval. The service fails closed when `TPA_ORIGIN` is absent or not an exact HTTPS origin or when `TPA_RP_ID` does not exactly equal its hostname. Configuration is never inferred from `Host`, `X-Forwarded-Host`, a query string, or browser input. An explicit `https://localhost` authority is permitted only when the integrator deliberately sets `localDevelopment: true`.

## Integrate a real host

The host owns authentication, session issuance, session revocation, principal enablement/ban rules, and designation of the one allowed owner. The package does **not** contain an authentication system and will not promote arbitrary callers to owner status.

1. Apply `migrations/0000_tpa_standalone.sql` and then `migrations/0001_tpa_mandate_hardening.sql` to a dedicated MySQL schema in a reviewed migration job. If using the provided minimal owner adapter, create the allowed owner explicitly in `tpa_principals`; do not expose a public endpoint that changes `isOwner`.
2. Build a `TpaHostAdapter`. `getDb()` returns the host's Drizzle database. `assertOwnerForUpdate(transaction, userId)` must, within the supplied transaction, lock the host principal and reject absent, disabled, banned, revoked, or non-owner principals. `createMinimalOwnerAdapter()` is complete for the supplied `tpa_principals` contract; hosts with their own user table should implement an equivalent adapter.
3. After the host's server-side session middleware authenticates its HTTP-only credential, resolve an identity as `{ principalId, sessionHash, owner: true }`. The `sessionHash` must be a SHA-256-style lowercase 64-hex binding generated by the host from a valid current session. Never accept it from request query/body input. Returning `undefined` for revoked, banned, expired, or non-owner sessions is required.
4. Construct `createTpaStore(hostAdapter)`, load the signer with `tpaMandateSignerFromEnv()`, then `createTpaService({ store, authority, signer, evidence: createTpaEvidenceStore(hostAdapter) })`. Mount `createTpaExpressRouter(service, resolveAuthenticatedOwner)` before a host-wide generic JSON parser. The included `examples/express-host.ts` uses the working minimal owner adapter and the host-provided actual authenticated-session resolver. It does not contain placeholder authentication or grant anyone privileges.
5. Terminate HTTPS at the configured origin, configure the exact RP ID, protect administrative operations, and log security-relevant host decisions without logging cookies, raw WebAuthn assertions, credential public keys, or mandate recipient data unnecessarily.

A condensed complete construction looks like this:

```ts
const authority = createTpaAuthority({ enabled: process.env.TPA_AUTHORIZATION_ENABLED === "true", origin: process.env.TPA_ORIGIN, rpID: process.env.TPA_RP_ID });
const store = createTpaStore(hostAdapter); // hostAdapter performs locked current-owner check
const signer = tpaMandateSignerFromEnv(process.env); // Ed25519 key from the secret manager; undefined means checkout mandates are refused
const service = createTpaService({ store, authority, signer, evidence: createTpaEvidenceStore(hostAdapter) });
app.use("/tpa-api", createTpaExpressRouter(service, async request => {
  const session = await hostReadCurrentSession(request); // host validates cookie/signature/revocation/expiry
  const principal = session && await hostReadCurrentPrincipal(session.principalId); // host checks owner + enabled + ban
  if (!session || !principal?.isOwner || !principal.enabled || principal.banned) return undefined;
  return { principalId: principal.id, sessionHash: hostSha256(session.id), owner: true };
}));
```

The code block documents the host seam; it is not an authentication substitute. Neither the service nor Express router supports identity in a query parameter, JSON body, or client-supplied header.

## Lifecycle and security behavior

Registration and authorization ceremonies are short-lived, one-use server records. A ceremony is burned before browser payload parsing or signature verification so malformed or mismatched attempts cannot be replayed. Registration completion uses a second conditional claim before persisting a credential. Intents bind canonical mandate hash, owner, exact origin, and original session. Authorization and consume require the original session; status and revoke allow only the same owner and exact origin after a legitimate session rotation.

The store takes the host owner lock first, then rechecks trusted time after lock waits. Intent creation rejects a repeated canonical mandate and a reused nonce. It accepts authenticator counters that remain `0` for standards-compatible authenticators, but once either old or new counter is nonzero it requires advancement. The service validates WebAuthn user verification, exact challenge, exact origin, exact RP ID, user-handle binding when supplied, and bounded browser payload shapes.

A returned `authorized` or `consumed` intent is authorization evidence only. It does not debit an account, move money, sign a chain transaction, contact a payment processor, validate balances, establish legal consent, or prove a real-world identity.

## Checkout mandate hardening (mandate version 3.0)

New intents are checkout mandates. Besides owner, currency, payee account, nonce and a 300 second expiry, the canonical mandate binds:

- the merchant id and display name;
- the line items as `[sku, qty, unitPriceBaseUnits]`, sorted by SKU, one line per SKU;
- the shipping method and shipping cost;
- the subtotal, the tax and the total, where subtotal = sum(qty x unit price) and total = subtotal + shipping + tax.

All money is an integer count of base units (cents for USD) carried as a string. Floats, exponents and inconsistent totals are refused.

- **Server signature.** The server signs `TPA-MANDATE-SIG/1\n<keyId>\n<canonical mandate>` with an Ed25519 key that is loaded from `TPA_MANDATE_SIGNING_KEY`. The key id comes from `TPA_MANDATE_SIGNING_KEY_ID`. Retired public keys go in `TPA_MANDATE_VERIFY_KEYS` to support rotation. The signature is checked on status reads, before the passkey step, after it, and at consume. A missing or unknown-key signature, or one that does not verify, is refused with `mandate_signature_invalid`. Create a key with `node scripts/generate-mandate-signing-key.mjs <keyId> <output-file>` and keep it in a secret manager. No real key is committed.
- **Passkey bound to the mandate.** The WebAuthn challenge is `base64url(SHA-256(mandateHash || bindingNonce))`, using a fresh 32-byte nonce per ceremony. The server re-derives the challenge before it accepts an assertion. Any other challenge is refused with `challenge_unbound`. The browser reference recomputes the challenge before it asks the passkey.
- **Exact match at use time.** `consume` must receive the actual `checkout`. Any difference in merchant, payee, currency, items, shipping, tax or total is refused with `terms_changed` (HTTP 409) and a specific `reason`, such as `items_mismatch`. A refused attempt does not use up the authorization.
- **Audit log.** `tpa_audit_events` records approvals (`intent_created`, `authorized`, `consumed`, `revoked`, credential changes), consume attempts, and every refusal. Each row holds a reason code and a timestamp. It holds no session hashes, challenges, nonces, signatures or keys. The owner can read it with `service.auditLog()` / `GET /audit`.
- **Migration.** Apply `migrations/0001_tpa_mandate_hardening.sql` after `0000`. It only adds tables.
- **Legacy.** The 2.0 amount-and-recipient transfer mandate is refused unless `legacyTransferMandates: true`.

## Bound checkout mandates and payment dispatch (mandate version 3.1)

TPA Shopper issues 3.1 mandates. A 3.1 mandate carries everything in 3.0 plus the trusted server quote (merchant, quote id, quote expiry), the frozen payment target (rail, network, payee, exact rail amount, conversion id, rate and conversion expiry) and two hashes over them. The mandate expiry is never later than the quote or the conversion expiry.

What the owner approves. `createIntent` returns `approval`, built by `tpaApprovalSummary(mandate)` from the signed mandate only. It lists the network, the exact amount on the rail, the conversion and when it expires, the TPA fee, the network fee asset and cap, and the maximum wallet debit (rail amount plus the network fee cap). A host must show these values before the passkey step. In the demo the approval is a synthetic passkey, not a human review screen.

Fees. `feeBaseUnits` is always `"0"`. It means a zero TPA or platform fee. It does not cover network (gas) fees, which are separate. On Metal, gas is paid in USDZ and is capped per payment at `METAL_FEE_CAP_BASE_UNITS` = 1,000,000 USDZ base units, which is 0.000000000001 USDZ (USDZ has 18 decimals). It is not 1,000,000 USDZ.

Conversion. The conversion id `usd-usdz-par` (1 USD = 1 USDZ) is a demo and testnet assumption. It is not a market quote, a redemption promise or proof of reserves. `usd-usd-identity` means no conversion.

Expiry. Mandate, quote and conversion expiry are decisions made by the trusted server when it authorizes and submits a payment. They are not deadlines enforced by the chain: a transaction that was already broadcast can still confirm later.

Dispatch. Every payment goes through one dispatch row per consumed intent (`shopper/payments.ts`, `src/dispatch.ts`). The ledger uses two separate checks:

- **Signed proof** (read-only): the intent is consumed and its signed mandate, hashes and checkout still match. Recovery and reconcile of an existing row need only this, so a recorded payment still reconciles after the intent is revoked or has expired.
- **Fresh execution gate**: the signed proof plus not revoked and not past the approval, quote or conversion expiry. It runs before the row is reserved, again immediately before the signer is called (after preparation such as gas estimation), and once more after the transaction id is durably recorded and immediately before the send, with nothing awaited between that last check and the send.

If the gate fails before signing, nothing is signed and the reservation is released. If it fails after the transaction id is recorded, that transaction is never sent and the row stays read-only: it is never re-signed and never resent, and a retry only reconciles. A row whose outcome is unknown is handled the same way. The live Metal client refuses (`metal_unguarded`) to sign without both hooks.

Limits of the mocks. The mock Metal client checks the fee cap and the payer balance but does not debit gas or record the gas actually used. The Airwallex rail is a mock by default (`createMockAiriAdapter`, a fixture destination, no provider call); the real Airi CLI adapter (`createAiriCliAdapter`) is opt-in with `AIRI_LIVE=1` and has only been tested against recorded CLI output (see "Live Airi mode"). The Airwallex sandbox adapter exists but is disabled and has never been run. The synthetic owner user 1 exists only in the demo rig; a host supplies its own owner identity.

## Running the tests

Library tests (Vitest):

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
```

Without a database, 223 tests run across 23 files and 104 are skipped. The database suites (mandate hardening, Proof of Permission refusals, store lifecycle, the v3.1 SQL lifecycle and the dispatch store) run against the real service, real MySQL store and real WebAuthn verification when both variables point at disposable MySQL or MariaDB schemas:

```sh
TPA_TEST_DATABASE_URL='mysql://USER:PASS@127.0.0.1:3306/tpa_test' \
TPA_DISPATCH_TEST_DATABASE_URL='mysql://USER:PASS@127.0.0.1:3306/tpa_dispatch_test' pnpm test
```

The suites drop and recreate their tables in those schemas, so never point them at a shared or production database. With both set, all **308 library tests across 22 files** pass (verified locally on a throwaway MySQL 9.7.4 server on 2026-10-29, at c467042; the 19 offline Airi CLI tests added since need no database and were not part of that run).

Ledger tests (local in-memory EVM, no database):

```sh
cd ledger
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
```

The ledger passes **20 tests**. `.github/workflows/verify.yml` runs both sets without a database, so CI runs the 223 offline library tests and the 20 ledger tests.

## Red-team demo (local, in memory)

```
pnpm install --frozen-lockfile
pnpm demo                 # colored terminal output (FORCE_COLOR=1 pnpm demo if your shell sets NO_COLOR)
pnpm demo:html            # also writes examples/redteam-demo.html for screen recording
pnpm demo:animated        # writes examples/redteam-demo.json and the auto-playing examples/redteam-demo-animated.html
pnpm demo:video           # records that page to artifacts/tpa-demo.mp4 (1920x1080, H.264, yuv420p)
```

The animated page embeds the JSON from the same run, so it only ever shows real outcomes and reason codes. It is self-contained (no network or CDN). `scripts/record-demo-video.mjs` needs no npm packages: it drives the system Chrome/Chromium headless over the DevTools protocol, steps the page clock frame by frame (`window.__tpa.render(ms)`) and pipes the frames into `ffmpeg`, so the video is smooth however slow capture is. Set `CHROME_PATH` if Chrome is not in a standard location; `ffmpeg` must be on `PATH`.

`scripts/redteam-demo.ts` drives the real `createTpaService` with a real Ed25519 signer (key generated in memory, never printed) and the synthetic WebAuthn authenticator from `tests/support/authenticator.ts`. It needs no database and no network. Persistence is a demo-only in-memory port of the store and evidence rules (`scripts/demo/memory-store.ts`); production uses the MySQL store. It runs one legit checkout (allowed) and then blocks these five attack types, printing each reason code and the audit log:

1. changed terms at checkout (`terms_changed:merchant_mismatch`, `terms_changed:items_mismatch`, `terms_changed:checkout_total_inconsistent`)
2. replay of a consumed mandate (`intent`)
3. forged signature or tampered stored mandate (`mandate_signature_invalid:bad_signature`, `mandate_signature_invalid:hash_mismatch`)
4. no passkey approval (`intent`), a passkey signature made for a different mandate (`ceremony`), or a passkey prompt not bound to the mandate (`challenge_unbound`)
5. expired or revoked mandate (`intent`)

It exits non-zero if any case does not behave as expected. TPA does not claim to stop every fraud; it blocks these attack types for the checkout it is shown.

## Browser reference

`client-reference/tpa-client.ts` uses `@simplewebauthn/browser` and same-origin cookie credentials. It sends no user identity. Before authorize, consume, or revoke it reloads status and uses `assertFreshTpaReview()` to reject changes to reviewed mandate evidence. A host may build its own UI; the library supplies no UI website.

## Final lifecycle source refresh

If the source lifecycle implementation changes before export/release, run the transform **from this package root** after reviewing the upstream diff:

```sh
node scripts/sync-lifecycle-store.mjs /absolute/path/to/server/tpa/store.ts
pnpm check && pnpm test && pnpm build
```

The script reads its input and only writes `src/store.ts`. It replaces DingDong's schema/database/owner imports with the standalone schema and explicit `TpaHostAdapter`; it fails if expected source markers or isolation checks are absent. Confirm after every refresh that `src/store.ts` contains no `../../` import, `getDb` import, or `isPersonalWalletOwner` reference. Do not substitute an older store file: lifecycle tests cover the post-lock clock checks, nonce/hash replay prevention, and registration completion claim.

## Hackathon

TPA is being built for the [Airwallex Agentic Banking Hackathon](https://airwallex.hackerearth.com/) as the approval layer of the "TPA Shopping Agent" idea: a shopping agent whose checkout is refused unless the shopper's passkey approved those exact terms. The library in `src/` does not call any Airwallex API; it supplies the signed, passkey-bound mandate and the exact-match check at consume. The hackathon app is in `shopper/` (below) and is not part of the published library.

## TPA Shopper (Kit 09: Approval-Bound Shopping Agent)

TPA Shopper is an AI shopping agent that can only spend what its owner approved, exactly once, at exactly the merchant, items, shipping, tax and total the owner saw. It follows [Kit 09 in the Airwallex builder guide](https://airwallexdev.com/guide): the shopper gives a need and a budget, the agent builds a cart, asks for approval of the exact terms, and asks again (here: refuses) when anything drifts. Kit 09 has no public starter repo; it runs on Airi CLI (`@airwallex/airi-cli`). The demo uses a mock Airi adapter by default; the real Airi CLI adapter is opt-in (see "Live Airi mode").

### Run the demo

```sh
pnpm install --frozen-lockfile
pnpm demo:shopper            # full run, about 3 seconds
pnpm demo:shopper -- --slow  # paced output for screen recording
pnpm test                    # includes tests/shopper.tap.test.ts and tests/shopper.flow.test.ts
```

Requirements: Node 20+ and pnpm. No database, no API keys, no network beyond a merchant server on 127.0.0.1 with a random port. On first run the agent's TAP key is generated at `.shopper-keys/tap-agent-ed25519.pem` (gitignored, mode 600; override with `TPA_SHOPPER_AGENT_KEY`). The TPA mandate key is generated in memory per run unless `TPA_MANDATE_SIGNING_KEY_ID` and `TPA_MANDATE_SIGNING_KEY` are set.

### What the demo shows

| Scenario | Expected | Stopped by |
| --- | --- | --- |
| 1. Agent buys a coffee setup within a $120 budget, owner approves with passkey, paid via the Airwallex mock (mock Airi, no provider call), order number returned | PAID | |
| 2. Same flow paid in USDZ on Metal (mock by default, chain 63825; real alta-testnet transfer with `METAL_LIVE=1`) | PAID | |
| A. Merchant raises a price after approval | BLOCKED | TPA `terms_changed:items_mismatch` |
| B. Checkout page injects an extra $49.99 protection plan | BLOCKED | TPA `terms_changed:items_mismatch` |
| C. Lookalike merchant id (`harbor-supp1y`) at payment time | BLOCKED | TPA `terms_changed:merchant_mismatch` |
| D. Agent tries to pay without the owner's passkey approval | BLOCKED | TPA `intent` |
| E. Attacker replays a captured agent checkout request; unsigned bot hits checkout | BLOCKED | Merchant TAP check `nonce_replayed`, `not_signed` |

Each blocked case moves no money (the payment adapters refuse to run without a TPA consume receipt) and leaves an audit entry; the demo prints the audit log for case B.

### How it fits together

```
shopper intent + budget
  -> agent browses merchant          (Visa TAP, tag agent-browser-auth)
  -> agent plans cart within budget  (shopper/agent.ts, amounts in code)
  -> merchant quote                  (items, shipping, tax, total)
  -> TPA mandate 3.1, Ed25519 signed (src/service.ts createIntent; returns the approval summary)
  -> owner passkey approval          (WebAuthn challenge bound to the mandate hash)
  -> agent checkout at merchant      (Visa TAP, tag agent-payer-auth + agenticPaymentContainer
                                      carrying the TPA mandate hash, same nonce and key)
  -> merchant returns payment request
  -> TPA exact-match consume         (single use; any drift is refused with a reason code)
  -> payment rail                    (Airwallex or Metal adapter, needs the consume receipt)
  -> merchant order number           (TAP signed)
```

Files: `shopper/tap.ts` (TAP signer and merchant verifier), `shopper/merchant.ts` (demo merchant with attack modes), `shopper/agent.ts` (planner), `shopper/payments.ts` (rails), `shopper/airi.ts` (Airi CLI wrapper), `shopper/flow.ts` (orchestration), `scripts/shopper-demo.ts` (CLI).

### Visa Trusted Agent Protocol details

Implemented from the [Visa TAP merchant specification](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications) and the [visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol) reference code (cdn-proxy verifier, commit 16d59bd), on top of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421):

- Every agent request carries `Signature-Input: sig2=("@authority" "@path");created=...;expires=...;keyid="...";alg="ed25519";nonce="...";tag="..."` and `Signature: sig2=:<base64>:`.
- `tag` is `agent-browser-auth` for catalog and quote, `agent-payer-auth` for checkout and completion. The merchant enforces the right tag per endpoint.
- The merchant applies the spec's verification steps: block when the tag or any required field (`created`, `expires`, `keyid`, `alg`, `nonce`, `tag`, `@authority`, `@path`) is missing, when `created` is in the future or `expires` is in the past, when the two are more than 8 minutes apart, when the nonce was seen in the last 8 minutes, when the key is not in the key directory, or when the signature fails.
- Checkout bodies carry an `agenticPaymentContainer` (`nonce`, `kid`, `alg`, payment fields, `signature`) signed with the same key, with the same nonce as the message signature; its base is the fields in received order except `signature`, as the spec describes. We put the TPA mandate hash and checkout id in it, which links the Visa agent identity to the owner's TPA approval.
- `keyid` is the RFC 7638 JWK thumbprint of the agent's Ed25519 key, the same shape as the keyids in Visa's examples. The key directory is a local stand-in for the scheme's Public Keys Retrieval Service.
- Base string follows RFC 9421 section 2.5 (quoted component names, `"@signature-params"` line last). The spec's Python sample prints unquoted component names; the Visa cdn-proxy and RFC 9421 both quote them, and we follow those.
- Not yet implemented: the Agentic Consumer Recognition Object (Visa ID token) and real key retrieval from Visa's well-known URL; both need Visa Intelligent Commerce onboarding.

### Prize mapping

| Prize | What targets it |
| --- | --- |
| Founder's Choice, Judges Choice | Working Kit 09 flow: approval bound to the exact cart, re-approval required on any drift, single use, audit trail, five attack classes blocked live |
| Visa Award | Visa TAP agent signatures and payment container (`shopper/tap.ts`), verified merchant side, plus the Airwallex payment adapter |
| Metal Award | USDZ payment rail on Metal behind `MetalClient` (`shopper/payments.ts`), real alta-testnet transfers in `shopper/metal.ts` with `METAL_LIVE=1`; the TPA mandate hash is kept in the payment result next to the tx hash (a MIP20 `transfer` has no memo field) |

### What is mocked and how to make it real

| Piece | Today | To make it real |
| --- | --- | --- |
| Airwallex Kit 09 payment (Airi CLI) | Default: `createMockAiriAdapter` (simulated mandate, one-time credential and result report; idempotent per TPA intent). Opt-in: `createAiriCliAdapter` over `shopper/airi.ts` with `AIRI_LIVE=1`, tested only against recorded / documented CLI output | See "Live Airi mode" below. A first real run needs an agent-enabled card in Airi, a real merchant checkout to submit the one-time card to, and Raul's approval in Airi for that exact payment. |
| Airwallex sandbox REST | `createAirwallexSandboxAdapter` written (login, `pa/payment_intents/create`, `confirm`) but disabled and never run | Sandbox account at sandbox.airwallex.com, set `AWX_CLIENT_ID`, `AWX_API_KEY` and `AWX_TEST_CARD_NUMBER` (the sandbox test card from the guide). Verify field names with the Airwallex docs MCP before relying on it. |
| Metal USDZ | Default: `createMockMetalClient` (in-memory USDZ, 18 decimals, chain 63825, token `0x000000000000000000000000000000000000b5d5`, instant finality). Live: `createMetalTestnetClient` in `shopper/metal.ts` | Implemented; see "Live Metal mode" below. Fund the payer from the Metal faucet, then run with `METAL_LIVE=1`. |
| Visa key directory | Local map of trusted agent keys | Visa Intelligent Commerce onboarding and the Visa-hosted well-known key URL. |
| Merchant | Local demo merchant with a synthetic catalog | Kit 09 targets real merchant sites through browser automation; the TAP and TPA checks stay the same. |
| Passkey | Synthetic authenticator with real P-256 keys and real WebAuthn verification. The demo owner (user 1) is synthetic and exists only in the demo rig. | Use `client-reference/tpa-client.ts` in a browser with a real platform authenticator. |
| TPA store | Demo in-memory port (`scripts/demo/memory-store.ts`) | The MySQL store in `src/store.ts`. |

### Live Airi mode (Airwallex Kit 09, opt-in)

The Airwallex rail is mocked unless you opt in. Nothing falls back silently: with `AIRI_LIVE=1` the rig refuses to start (`airi_misconfigured`) unless it is given a live config, and without the flag no `airi-cli` command runs at all. Tests always use recorded CLI output (`tests/airi.cli.test.ts`, `tests/fixtures/airi/`); no test creates a mandate or fetches a credential.

Flow (`shopper/payments.ts` `createAiriCliAdapter`, CLI wrapper in `shopper/airi.ts`, per `airi-cli` 0.1.0-beta.3 `--help` and its bundled `airi-get-credential` skill), after all TPA checks and the TPA consume:

1. Preflight, nothing recorded: the signed target must be `airwallex:airi-card` paying `awx-airi-merchant:<the signed merchant id>`, the merchant must be in the server-side Airi merchant directory (https URL + country), `airi-cli auth whoami` must report signed in, and `AIRI_PAYMENT_METHOD_ID` must still be listed by `airi-cli payment-methods list`.
2. Fresh TPA gate, then `airi-cli mandate create --source --payment-method-id --merchant-name --merchant-url --merchant-country --total-amount --currency --item ... --description` for exactly the signed merchant, items (plus shipping and tax lines) and total. This pushes a passkey approval to the Airi account owner; `onApprovalRequested` gets the `passkey_url` and order summary to show them.
3. The mandate id is recorded in the dispatch ledger before anything else (the "sent" marker). From then on a retry only reconciles (`airi-cli mandate list --status COMPLETED`); it never creates a second mandate or fetches the credential again. If the TPA gate fails here the mandate is cancelled (`mandate cancel`, status `DENIED`).
4. `airi-cli mandate get-credential --mandate-id <id> --file <fresh 0700 dir>/credential.json` blocks until the owner approves (default 300 s; a timeout cancels the mandate). The credential stays in that 0600 file: the adapter never reads it, the injected `submitCheckout` receives only the path, and the directory is deleted as soon as checkout returns or throws.
5. `airi-cli mandate result --result SUCCEEDED|CANCELLED|DECLINED` is always reported. Only `SUCCEEDED` settles the dispatch (`mode: "live"`, reference = mandate id, card shown as brand + last 4 only). If the checkout step crashes the outcome is unknown: nothing is reported or retried, the row stays read-only for manual reconcile.

Configuration: `AIRI_LIVE=1`, `AIRI_PAYMENT_METHOD_ID` (from `pnpm airi:preflight`), optional `AIRI_SOURCE` (default `TPA Shopper`, must match the `--client-name` used at login) and `AIRI_CLI_BIN`; plus `createShopperRig({ airi: { merchants: { <merchantId>: { url, country } }, submitCheckout, onApprovalRequested } })`. The local demo merchant cannot take a card, so a live run needs a real merchant checkout and a `submitCheckout` that fills its card form from the file. Live runs persist the dispatch journal to `artifacts/airi-dispatch-journal.json` (gitignored).

Sign-in is a human step: `airi-cli auth login --client-name "TPA Shopper"` prints a verification URL and code; the owner approves it while `airi-cli auth poll` runs. The app never runs `auth login` or `auth logout` and never reads the CLI's session file. `pnpm airi:preflight` is read-only: it prints the session expiry and each payment method as id + brand + last 4.

Known gaps: payment method and mandate-list field spellings beyond those in the CLI docs (`paymentMethodId`, `mandate_id`, `passkey_url`, `mandateId`, `status`) are parsed tolerantly and must be checked against the first real responses; a crash between `mandate create` and recording its id leaves an unapproved mandate in Airi (no money moves; the owner can deny it).

### Live Metal mode (alta-testnet)

The Metal rail is mocked unless you opt in. With `METAL_LIVE=1` and credentials present, `pnpm demo:shopper` pays scenario 2 with a real `*USDZ` transfer on Metal Testnet (chain `63825`, `0xf951`), after the same TPA checks: Proof of Person (owner passkey), Presence (Visa TAP-signed agent requests) and Permission (exact-match mandate consume). If the flag or any credential is missing, the rig silently falls back to the mock, and the demo prints why. Tests always use the mock (`createShopperRig({ metal: "mock" })`).

What the live client does (`shopper/metal.ts`, per docs.metalntwx.com):

1. Checks `eth_chainId == 63825`, `MIP20Factory(0x...0f4c).isMIP20(USDZ)` and `USDZ.decimals() == 18`.
2. Estimates gas, refuses if it exceeds the fee cap (1,000,000 USDZ base units), checks the payer holds amount plus gas (gas is paid in USDZ at 1 base unit per gas), runs the fresh execution gate again, and signs a `0x7f` MIP20 transaction with `@metalntwx/metal-ts` `signMip20Contract` (`transfer(merchant, amount)`, `gasToken` = USDZ).
3. Broadcasts, waits for the receipt, requires `status = success` and a matching `Transfer(payer, merchant, amount)` log from USDZ (anything else, e.g. a ReceivePolicy quarantine, is refused).
4. Waits until `consensus_status.finalized.number >= receipt.blockNumber` and the canonical block hash matches, then returns the tx hash.

The tx hash is recorded in the dispatch row before the send, and the fresh execution gate runs once more after that record. Transfers are serialized per payer, and on a lost response the error carries the tx hash so it is checked rather than resent.

Setup (secrets stay in gitignored, `chmod 600` files and are never printed; errors are masked):

```bash
# .env.metal         METAL_RPC_URL=https://rpc-testnet.metalntwx.com/v1/<endpoint-id>   (the URL is the credential)
#                    METAL_API_KEY=...   (optional, only used to mask output)
# .env.metal-wallet  METAL_PAYER_KEY=0x...  METAL_PAYER_ADDRESS=0x...   (throwaway testnet key)
# Fund METAL_PAYER_ADDRESS at the Metal faucet with currency *USDZ (tops up to 100 USDZ).
METAL_LIVE=1 pnpm demo:shopper
```

Optional env: `METAL_MERCHANT_ADDRESS` (recipient; can also live in the gitignored `.env.metal-demo` as a non-secret default, otherwise the demo merchant placeholder address is used, where funds are unrecoverable), `METAL_DEMO_BUDGET_CENTS` (budget for the live Metal scenario, default `5000`, because the 100 USDZ faucet top-up is less than the $113 demo cart). Values in the process environment override the files. 1 cent = 10^16 USDZ base units.

## Scope exclusions and operator decisions

This package intentionally omits all DingDong application material, social UI, user records, payment pages, custodial wallet code, signing keys, provider accounts, secret values, bank/payment integrations, monitoring agents, and deployment automation. The one exception is the optional TPA Shopper Metal rail: with `METAL_LIVE=1` and locally supplied, gitignored credentials, `shopper/metal.ts` submits a real `*USDZ` transfer on Metal Testnet (alta-testnet, chain 63825) after the TPA checks pass. Without the flag, every payment rail, Metal included, is a mock and nothing is submitted to any chain. No keys or RPC credentials ship with the package. The schema has no foreign keys to host users because a host may use any principal store; the minimum principal table is included solely as a runnable contract option.

Before a pilot deployment, operators still need an independent security review, privacy/legal review, WebAuthn RP/origin deployment review, database backup/recovery plan, session/revocation implementation review, logging/retention policy, incident response plan, and a separate design for any later payment or ledger system. Nothing here makes claims of bank certification, production readiness, guaranteed fraud prevention, or compliance.

## Rights and notices

The package is `private: true` and `UNLICENSED`; it grants no license by itself. It does not change the original source repository's license. See `THIRD_PARTY_NOTICES.md` for extraction provenance, pinned third-party dependencies, and the unresolved source-rights caveat.
