# TPA security boundary

This package is a default-disabled authorization pilot. It must not be represented as independently certified bank software, three independent authentication factors, independent camera liveness, asset proof, custody or settlement. A trusted host's current session and owner-policy implementation are part of the security boundary, not included authentication infrastructure.

Do not put real credentials, cookies, private keys, recovery phrases, database dumps, WebAuthn assertions or customer mandates into this repository, issue reports, test fixtures or CI. The provided database configuration is a placeholder only. Configure actual values through the purchaser's secret-management process after staging approval.

Send security findings privately to the repository owner through the agreed due-diligence channel; do not publish customer data or exploit details in public discussions. Use synthetic reproductions and sanitized logs. Review `VALIDATION.md` for actual local test results and remaining acceptance work, and `THIRD_PARTY_NOTICES.md` before licensing or distributing source.

The included workflow tests code only, with read-only repository permissions and no deployment secrets. It does not run or monitor production accounts, make payments, connect a wallet or broadcast transactions. No production service is deployed by this repository.

Before any later production financial use, require independent review, real-device exact-origin staging, host-session and revocation acceptance, database concurrency/restart/recovery tests, incident response, change control and role/key governance. Any payment or chain adapter needs its own separately authorized design, validation and reconciliation policy.
