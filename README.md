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
schemas/             17 JSON Schemas for the wire contracts (checked in CI)
fixtures/            Synthetic schema-valid instances for every contract
interfaces/          Planned: cross-repo protocol references (events to/from hooks)
scripts/             check-schema.sh / check_schemas.py validation tooling
docs/                Architecture, model, and operations documentation
.github/             CI + security workflows and the PR template
```

**Layout notes.** Phase 1 implements the domain foundation only; the
remaining spec surface (normalizer, indexer, integrity hashing, service
crates, Soroban/RPC/simulator adapters, the optional audit-registry
contract, the CLI) lands in later phases and is mapped in
`docs/architecture.md`, which also records any consolidation between the
spec module tree and its real home — the same discipline the sibling
repos follow.

## Status: Phase 1 complete (domain foundation)

Phase 1 — the domain foundation — is implemented, tested, and pushed:

- `audit-core`: the full vocabulary — deterministic identifiers, UTC
  timestamps with injectable clocks, cursor pagination, correlation
  references, data classification, the normalized 18-kind `AuditEvent`
  envelope with observed/derived provenance, the append-only
  `AuditRecord` with correction links, integrity/report/investigation/
  evidence/authorization/retention models, canonical serialization.
- `audit-events`: deterministic event identity (never arrival time) and
  the semantic events that project onto the envelope.
- `storage` + `memory-store`: the append-only `EventStore` contract with
  idempotent dedup, atomic batches, deterministic ordering, stable cursor
  paging — and its in-memory implementation (tests/fixtures/dev only).
- `schemas/` + `fixtures/` + `scripts/check_schemas.py`: 17 wire-contract
  schemas, synthetic instances, and a strict checker gating them in CI.
- Governance and CI: CONTRIBUTING/SECURITY/CODE_OF_CONDUCT/CHANGELOG, the
  fmt·clippy·tests·schemas gate, and weekly dependency audits.

Phases 2+ are defined in `docs/architecture.md`.

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
