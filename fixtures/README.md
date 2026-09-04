# Fixtures

Synthetic instance files that exercise the wire contracts in `schemas/`.
All data is fabricated for tests and documentation — no real accounts,
balances, or personal information, ever.

Layout:

- `events/` — normalized audit events per scenario (approved, denied,
  flagged, frozen, policy change, authorization change) plus the observed
  hooks compliance events they derive from (in `observed-hooks-event.json`).
- `records/` — persisted audit records.
- `transactions/` — transaction framing metadata.
- `correlation/` — policy-decision and enforcement-result references,
  including deliberately invalid negatives.
- `integrity/` — integrity manifests: `valid/` conforms; `tampered/` and
  `corrupted/` are detectably malformed at the *shape* level (bad digest
  algorithm / bad hex). Content-level tamper detection (digest mismatch
  against recomputed values) is exercised by the integrity crate's tests,
  not by fixtures, because only recomputation can catch it.
- `evidence/`, `reports/`, `authorization/`, `auditors/`,
  `investigations/`, `cursors/` — the remaining artifact contracts.

`scripts/check-schema.sh` (or `python3 scripts/check_schemas.py`) validates
every listed fixture against its schema in CI.
