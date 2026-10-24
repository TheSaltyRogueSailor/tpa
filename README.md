# TPA Authorization Pilot — standalone library

This is a reusable, framework-neutral **authorization-evidence pilot**. It creates canonical single-use transfer-authorization mandates, binds a passkey/WebAuthn ceremony to a host-authenticated owner, and persists credential and intent state with MySQL row locking. It is not a payment service, bank integration, custody system, blockchain signing service, wallet, transfer executor, settlement engine, identity proofing service, or independent liveness system.

`TPA_MODE` is intentionally explicit: `paymentExecution: false`, `onChainSubmission: false`, `independentLiveness: "not-configured"`, and `identityClaim: "registered-credential-control"`.

The independently tested source checkpoint is documented in [VALIDATION.md](VALIDATION.md); see [SECURITY.md](SECURITY.md) for remaining banking/security acceptance requirements. No deployment or financial action is included. `.github/workflows/verify.yml` reproduces library and local-ledger checks with read-only repository permissions.

## Package contents

| Path | Purpose |
| --- | --- |
| `src/domain.ts` | Immutable mandate schema, canonicalization, exact base-unit helpers, and explicit pilot boundary. |
| `src/signing.ts` | Ed25519 mandate signer/verifier with key ids for rotation; loads keys from environment. |
| `src/evidence.ts` | Signature, passkey challenge binding, and audit-log persistence; challenge derivation. |
| `src/webauthn.ts` | Bounded WebAuthn request parsers plus registration/authentication options and verification wrappers. |
| `src/store.ts` | MySQL/Drizzle persistence with owner locks, ceremony burn/claim, intent replay defenses, counters, session/origin bindings, and recovery rules. |
| `src/host/contracts.ts` | Required host database and owner-authorization contract. |
| `src/host/minimal-owner.ts` | Working adapter for the included minimal `tpa_principals` table. |
| `src/service.ts` | Framework-neutral service that accepts only caller-provided, host-authenticated owner identity. |
| `src/http/express.ts` | Working bounded Express router factory that requires a host identity resolver. |
| `src/schema.ts`, `migrations/0000_tpa_standalone.sql` | The only extracted data schema: minimal principal contract, credentials, intents, and ceremonies. |
| `client-reference/tpa-client.ts` | Optional compile-tested browser reference using SimpleWebAuthn without a social application UI. |
| `examples/express-host.ts` | Reference host mount showing explicit configuration and host-session seam. It intentionally does not start a server. |
| `scripts/sync-lifecycle-store.mjs` | Reusable, fail-closed source transform for a final lifecycle-store refresh. |
| `tests/` | Offline synthetic lifecycle, policy, review, and host-boundary tests. |

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

None of these commands starts a server or connects to a database. Installation and the audit contact the package registry; application tests use synthetic fixtures and loopback HTTP only. A nonzero audit result must be investigated rather than bypassed. The checked-in lockfile and `qs` security override preserve the reviewed dependency set.

## Configure deliberately

Copy `.env.example` to an operator-managed deployment secret/configuration system. The file contains placeholders only. All four items are required for a live host integration:

```dotenv
TPA_ORIGIN=https://tpa.example.invalid
TPA_RP_ID=tpa.example.invalid
TPA_AUTHORIZATION_ENABLED=false
TPA_DATABASE_URL=mysql://USER:PASSWORD@HOST:3306/DATABASE
```

Authorization remains disabled unless the operator explicitly sets the exact activation value `true` after staging approval. The service fails closed when `TPA_ORIGIN` is absent or not an exact HTTPS origin or when `TPA_RP_ID` does not exactly equal its hostname. Configuration is never inferred from `Host`, `X-Forwarded-Host`, a query string, or browser input. An explicit `https://localhost` authority is permitted only when the integrator deliberately sets `localDevelopment: true`.

## Integrate a real host

The host owns authentication, session issuance, session revocation, principal enablement/ban rules, and designation of the one allowed owner. The package does **not** contain an authentication system and will not promote arbitrary callers to owner status.

1. Apply `migrations/0000_tpa_standalone.sql` to a dedicated MySQL schema in a reviewed migration job. If using the provided minimal owner adapter, create the allowed owner explicitly in `tpa_principals`; do not expose a public endpoint that changes `isOwner`.
2. Build a `TpaHostAdapter`. `getDb()` returns the host's Drizzle database. `assertOwnerForUpdate(transaction, userId)` must, within the supplied transaction, lock the host principal and reject absent, disabled, banned, revoked, or non-owner principals. `createMinimalOwnerAdapter()` is complete for the supplied `tpa_principals` contract; hosts with their own user table should implement an equivalent adapter.
3. After the host's server-side session middleware authenticates its HTTP-only credential, resolve an identity as `{ principalId, sessionHash, owner: true }`. The `sessionHash` must be a SHA-256-style lowercase 64-hex binding generated by the host from a valid current session. Never accept it from request query/body input. Returning `undefined` for revoked, banned, expired, or non-owner sessions is required.
4. Construct `createTpaStore(hostAdapter)`, then `createTpaService({ store, authority })`. Mount `createTpaExpressRouter(service, resolveAuthenticatedOwner)` before a host-wide generic JSON parser. The included `examples/express-host.ts` uses the working minimal owner adapter and the host-provided actual authenticated-session resolver. It does not contain placeholder authentication or grant anyone privileges.
5. Terminate HTTPS at the configured origin, configure the exact RP ID, protect administrative operations, and log security-relevant host decisions without logging cookies, raw WebAuthn assertions, credential public keys, or mandate recipient data unnecessarily.

A condensed complete construction looks like this:

```ts
const authority = createTpaAuthority({ enabled: process.env.TPA_AUTHORIZATION_ENABLED === "true", origin: process.env.TPA_ORIGIN, rpID: process.env.TPA_RP_ID });
const store = createTpaStore(hostAdapter); // hostAdapter performs locked current-owner check
const service = createTpaService({ store, authority });
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

## Red-team demo (local, in memory)

```
pnpm install --frozen-lockfile
pnpm demo                 # colored terminal output (FORCE_COLOR=1 pnpm demo if your shell sets NO_COLOR)
pnpm demo:html            # also writes examples/redteam-demo.html for screen recording
```

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

## Scope exclusions and operator decisions

This package intentionally omits all DingDong application material, social UI, user records, payment pages, wallet code, blockchain client code, signing keys, provider accounts, secret values, bank/payment integrations, transfer execution, monitoring agents, and deployment automation. The schema has no foreign keys to host users because a host may use any principal store; the minimum principal table is included solely as a runnable contract option.

Before a pilot deployment, operators still need an independent security review, privacy/legal review, WebAuthn RP/origin deployment review, database backup/recovery plan, session/revocation implementation review, logging/retention policy, incident response plan, and a separate design for any later payment or ledger system. Nothing here makes claims of bank certification, production readiness, guaranteed fraud prevention, or compliance.

## Rights and notices

The package is `private: true` and `UNLICENSED`; it grants no license by itself. It does not change the original source repository's license. See `THIRD_PARTY_NOTICES.md` for extraction provenance, pinned third-party dependencies, and the unresolved source-rights caveat.
