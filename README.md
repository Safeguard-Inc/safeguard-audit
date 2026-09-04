# Safeguard Audit

**VERIFY layer of the Safeguard compliance stack for Stellar Confidential Tokens.**

Safeguard is a three-polyrepo system built around a DEFINE → ENFORCE → VERIFY pipeline:

```
                    SAFEGUARD
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
     DEFINE         ENFORCE       VERIFY
          │            │            │
          ▼            ▼            ▼
safeguard-policy  safeguard-hooks  safeguard-audit
          │            │            │
          │            │            │
          └───────┬────┴───────┬────┘
                  │            │
             Policy API    Audit Events
                  │            │
                  ▼            ▼
             Decision     Evidence
```

| Polyrepo            | Concern      | Question answered |
| ------------------- | ------------ | ----------------- |
| `safeguard-policy`  | Define       | "What should happen?" |
| `safeguard-hooks`   | Enforce      | "Make it happen." |
| **`safeguard-audit`** | **Verify** | **"What happened?"** |

This repository is the **audit and verification layer**. It records and
verifies what actually happened to compliance-protected token operations:

> Observe → Record → Authorize → Investigate → Verify → Report

An authorized auditor or compliance operator can answer: which
compliance-controlled operation occurred, on which token, between which
accounts; whether it was approved or denied; which policy version produced
the decision; which hook processed it; when it happened; what the
transaction/event identifiers were; whether the record was altered; whether
the evidence package is intact; what the compliance report says — and every
one of those answers is reproducible from the same sources.

This is a **developer-preview** stack. Confidential Tokens on Stellar are a
developer preview available on Testnet; do not treat this repository as
production financial infrastructure.

## What this repository does *not* do

The boundaries are load-bearing. `safeguard-audit` must never become:

- a **policy engine** — `safeguard-policy` DEFINES policy; audit references
  policy versions historically and never re-evaluates them,
- an **enforcement layer** — `safeguard-hooks` ENFORCES; audit records the
  denials it is told about or reconstructs from authoritative metadata, but
  never denies, freezes, or blocks anything itself,
- a wallet, identity provider, KYC/sanctions engine, or generic blockchain
  explorer/dashboard — and never a place where confidential balances,
  transfer amounts, or view-key material are persisted by default.

The one idea: **Safeguard does not only block bad operations — it makes
protected operations traceable, accountable, verifiable, investigable,
reproducible, and privacy-aware.**

## Honest event surface

Per-operation *approvals* are never emitted on-chain by the enforcement
layer (any contract can invoke the hook surface — an approval event would
be spoofable), and *denials* cannot be emitted (a revert discards its
events). `safeguard-audit` therefore distinguishes structurally:

- **observed** events — state transitions the hooks contract really emits
  (freeze/unfreeze, bind/unbind, configuration changes), and
- **derived** events — transfer outcomes, sanctions flags, and audit-layer
  activity reconstructed by authorized processes, each carrying derivation
  info naming what it was derived from and how.

The provenance model makes the difference visible on every record.

## Repository layout

```text
crates/
  audit-core/        Provider-neutral domain model: events, records, integrity,
                     authorization, investigations, evidence, reports, privacy
  audit-events/      Semantic events: observed hooks state events + derived events,
                     projecting onto the normalized envelope
  storage/           EventStore contract: query model, position keys, write batches
  memory-store/      In-memory EventStore for tests/fixtures/dev (non-durable)
  event-normalizer/  Deterministic parse-validate-classify pipeline per scheme
  event-indexer/     Checkpointed, idempotent ingestion; cursors and replay
  integrity/         Canonical hashing, chained digests, manifests, verification
  authorization/     Role matrix, scope containment, credentials, access log
  investigation/     Case store + lifecycle service; findings, notes, closure
schemas/             17 JSON Schemas for the wire contracts (checked in CI)
fixtures/            Synthetic schema-valid instances for every contract
interfaces/          Planned: cross-repo protocol references (events to/from hooks)
scripts/             check-schema.sh / check_schemas.py validation tooling
docs/                Architecture, model, and operations documentation
.github/             CI + security workflows and the PR template
```

**Layout notes.** The spec module tree lands phase by phase and any
consolidation is recorded in `docs/architecture.md` — the same
interfaces-as-cross-repo-protocol discipline the sibling repos follow.

## Status: Phases 1-4 complete

Implemented, tested, and pushed to `main`:

- **Phase 1 — Domain foundation.** `audit-core` (deterministic ids, UTC
  timestamps with injectable clocks, cursor pagination, correlation
  references, data classification, the 18-kind `AuditEvent` envelope with
  observed/derived provenance, append-only `AuditRecord` with correction
  links, integrity/report/investigation/evidence/authorization/retention
  models, canonical serialization), `audit-events` (deterministic event
  identity, semantic events), `storage` + `memory-store` (append-only
  `EventStore` with idempotent dedup, atomic batches, deterministic
  ordering), 17 schemas + fixtures + strict checker, governance and CI.
- **Phase 2 — Event pipeline & integrity.** `EventSource` boundary,
  `event-normalizer` (strict per-scheme parse → validate → classify),
  `event-indexer` (checkpointed idempotent `run_once`, cursors, bounded
  replay), `integrity` (canonical record digests, chained scheme,
  manifests, verification, tamper location), executable
  `test-vectors/normalization`, end-to-end pipeline tests and invariants,
  `ingest-event`/`verify-record` examples.
- **Phase 3 — Authorization.** `authorization` crate: role matrix,
  per-identity permission sets, scope containment, expiring credentials,
  the auditor registry, the authorizer, and store-backed audit-access
  logging with full attribution (auditor/time/classification). Scenario
  and invariant suites, `test-vectors/authorization`, decision fixtures,
  the `authorize-access` example.
- **Phase 4 — Investigation.** `investigation` crate: `CaseStore` +
  in-memory store, the `CaseService` workflow (open, assign, transition,
  link records, findings, notes, close with reason, admin reopen), and
  lifecycle event projection with explicit step kinds and sequence
  identity. End-to-end denial-to-closed scenarios, lifecycle vector
  corpus, closed/escalated fixtures, the `create-investigation` example.

Phases 5+ are defined in `docs/architecture.md`.

## Development

```sh
cargo test --workspace              # unit tests across the workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python3 -m pip install jsonschema   # strict schema validation (CI installs it)
bash scripts/check-schema.sh        # validate schemas + fixtures
```

Everything runs on stable Rust; the toolchain is pinned in
`rust-toolchain.toml`.

## Integrity, privacy, and security model

* **Integrity**: records carry canonical digests (chained or standalone);
  tampering is detected by recomputation; evidence packages ship with
  manifests so exports can be independently verified. This is tamper
  *evidence* over locally stored records — anchoring to the ledger via the
  optional on-chain registry is a separate later-phase component.
* **Privacy**: every field is classifiable (public → operational →
  confidential → restricted → highly-restricted); records carry a
  field-level classification table; redaction, export filtering, safe
  logging, and decryption authorization build on it. Protected data is
  never persisted or logged by default.
* **Authorization**: access is explicit, role-based, scope-bounded, and
  itself recorded as audit-access events — the audit trail audits its own
  access, once, with no infinite recursion.
* **Security**: see `SECURITY.md` for the sensitive-data list and
  disclosure process, and `docs/threat-model.md` for the full model.

## Contributing

See `CONTRIBUTING.md` and `docs/contributing.md`. The contribution areas —
events, indexing, storage, integrity, authorization, privacy,
investigation, reporting, Soroban adapters, security, performance,
documentation — are defined so contributors can work independently on
well-bounded components.

## License

MIT — see `LICENSE`.
