Recorded / documented `airi-cli` (0.1.0-beta.3) JSON outputs used by `tests/airi.cli.test.ts`. All ids, names and
card digits here are FAKE test values; no real account data, tokens or card numbers.

- `whoami.json`, `payment-methods-empty.json`, `mandate-list-empty.json`: shape recorded from the real CLI on
  2026-10-31 (read-only calls), with identifying values replaced.
- The rest follow the CLI's `--help`, README and bundled `airi-get-credential` skill: `mandate create` returns
  `mandate_id` + `passkey_url`; `get-credential --file` prints only `{"status":"saved","tokenType","tokenExpiration"}`;
  `mandate cancel` prints `{"status":"ok"}`; `mandate list` returns `{items, hasMore, page, size}` with `mandateId`,
  `status`, `createdAt`. Field names not shown verbatim in those docs (payment method brand/last4 spelling, list
  totals) are parsed tolerantly in `shopper/airi.ts` and must be re-checked against the first real response.
