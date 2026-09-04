# Contributing to safeguard-audit

`safeguard-audit` is the **VERIFY** layer of the Safeguard compliance stack
for Stellar Confidential Tokens. It records and verifies what happened to
compliance-protected operations. Before contributing, read
`README.md` and `docs/architecture.md` — especially the **boundaries**:
this repository must never become a policy engine, an enforcement layer, a
wallet, or a generic blockchain explorer.

## Code of conduct

Behave per `CODE_OF_CONDUCT.md`. This is security- and privacy-sensitive
infrastructure; treat reviewers' time and users' data with care.

## Getting started

```sh
cargo test --workspace        # unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python3 -m pip install jsonschema   # needed for strict schema checks
bash scripts/check-schema.sh        # validate schemas + fixtures
```

## What makes a good change

1. **One improvement, one commit.** Each commit is a coherent, tested,
   valuable unit — a crate, a subsystem, a suite, a document — never a
   bundle of unrelated edits.
2. **No placeholder code.** Every file has a purpose. If a module is not
   implemented yet, it is not created yet.
3. **Boundaries hold.** Enforcement decisions belong to `safeguard-hooks`;
   policy definition to `safeguard-policy`. Audit code records and verifies
   — it never denies, freezes, or screens.
4. **No fake security.** Never commit fake verification, fake decryption,
   or authorization that always succeeds. Test-only components are clearly
   labeled as mocks and never presented as security boundaries.
5. **Privacy is structural.** No amounts, balances, ciphertexts, view keys,
   or credentials in records, logs, errors, fixtures, or examples. Fixtures
   are synthetic only.

## Contribution areas

See `docs/contributing.md` for the full area map (events, indexing,
storage, integrity, authorization, privacy, investigation, reporting,
Soroban adapters, security, performance, documentation). Each area lists
what a good first change looks like and what tests it must carry.

## Testing expectations

* Logic changes carry unit tests in the crate.
* Cross-crate behavior carries integration tests.
* Security/privacy behavior carries explicit negative tests (unauthorized,
  out-of-scope, tampered, malformed).
* New wire shapes update the matching `schemas/*.schema.json` and a
  fixture; the schema checker must pass.

## Commit style

Subject lines are imperative and specific ("Add safeguard-storage: the
EventStore interface"). Bodies explain the *why*, name the files touched,
and note what changed in tests and docs. Commits are authored by the
contributor — no bot co-author trailers.

## Security issues

Do **not** open a public issue for a vulnerability. Follow
`SECURITY.md`'s disclosure policy.
