# Third-party notices and provenance

This repository is a standalone extraction of TPA-specific concepts and implementation prepared on 2026-10-23. It is not a copy of the DingDong application and intentionally does not include its social application, UI, wallet, payment, user-account, provider, or secret material.

## Extraction provenance

The initial implementation was mechanically adapted from the following scoped paths in the source workspace, with DingDong imports replaced by explicit host contracts: `server/tpa/store.ts`, `server/tpa/webauthn.ts`, `server/tpa/config.ts`, `shared/tpa.ts`, `server/routers/tpa.ts`, `server/tpaTransport.ts`, and the TPA table declarations in `drizzle/schema.ts`. The standalone store was refreshed from the final lifecycle source via `scripts/sync-lifecycle-store.mjs`.

The immutable `ledgerDomain` string remains `dingdong-tpa/rootstock-testnet/attestation-v2` because it is part of already-defined signed/canonical mandate evidence. This string does not grant access to a ledger, wallet, chain, DingDong system, or payment service.

The root source workspace reported MIT in its package manifest. This standalone package deliberately uses `UNLICENSED`. No commercial right, assignment, or relicensing conclusion is made here. A seller, buyer, and qualified counsel must resolve provenance and distribution rights before any transfer or publication.

## Runtime dependencies

| Package | Pinned version | Declared upstream license/source |
| --- | ---: | --- |
| `@simplewebauthn/browser` | 14.0.0 | MIT; SimpleWebAuthn |
| `@simplewebauthn/server` | 14.0.3 | MIT; SimpleWebAuthn |
| `drizzle-orm` | 0.45.2 | Apache-2.0; Drizzle Team |
| `express` | 4.22.2 | MIT; OpenJS Foundation contributors |
| `mysql2` | 3.24.3 | MIT; Sidorares |
| `zod` | 4.1.12 | MIT; Colin McDonnell and contributors |

Development-only dependencies are listed with exact versions in `package.json`. Read each installed package's distributed license text before redistribution.

## Excluded materials

No network keys, private keys, seed phrases, biometric templates, wallet signing, payment provider credentials, bank records, social accounts, end-user records, host login cookies, deployment values, or real database data are included. The separately locked `ledger/` source package is included for local server-attestation tests only. Its `UNLICENSED` package metadata and third-party OpenZeppelin/compiler/test-tool dependencies are independent of this library. Neither package contains a live-chain deployment path.
