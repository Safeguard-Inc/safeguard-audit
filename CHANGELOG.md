# Changelog

All notable changes to `safeguard-audit` are recorded here. This repository
follows the phase plan in `docs/architecture.md`; each phase lands as a
series of tested commits.

## [Unreleased]

### Phase 1 — Domain foundation (complete)

The provider-neutral vocabulary, persistence contract, and wire contracts
of the audit layer:

- **Workspace bootstrap** — Cargo workspace, toolchain pin, lint defaults,
  MIT license.
- **`safeguard-audit-core`** — the domain model: structured error
  taxonomy; deterministic identifiers (`rec_`, `evt_`, `case_`, ...);
  UTC timestamps with a `Clock` abstraction and RFC 3339 rendering;
  cursor pagination; provider-neutral correlation references (ledger,
  transaction, operation, token, account, policy decision, enforcement
  result); data classification; the normalized `AuditEvent` envelope with
  an 18-kind registry and observed-vs-derived provenance; the append-only
  `AuditRecord` with correction links; integrity vocabulary (digests,
  schemes, outcomes, manifests); authorization models (roles, actions,
  scopes, identities, access entries); retention policy evaluation;
  investigation cases with timelines; evidence artifacts with mandatory
  provenance; reproducible report definitions; canonical JSON
  serialization.
- **`safeguard-audit-events`** — semantic event types: deterministic
  source identity, transaction framing, the observed hooks state-event
  surface (freeze/unfreeze, bind/unbind, config change), and the derived
  event set (transfer outcomes, sanctions flags, compliance decisions,
  policy version changes, authorization changes, audit access,
  investigation lifecycle, evidence/report generation, corrections) —
  each projecting onto the normalized envelope with honest provenance.
- **`safeguard-audit-storage`** — the `EventStore` contract: append-only
  and idempotent, atomic write batches, deterministic `PositionKey`
  ordering with lossless cursor encoding, and the `AuditQuery` model.
- **`safeguard-audit-memory-store`** — in-memory `EventStore` for tests,
  fixtures, and single-node development (explicitly non-durable).
- **Schemas and fixtures** — 17 JSON Schemas for the wire contracts and
  synthetic schema-valid fixtures, gated by a strict/structural checker.
- **Governance** — CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, this file.

### Phase 2 — Event pipeline and integrity (complete)

The ingestion, normalization, indexing, and tamper-evidence layer:

- **`EventSource` boundary** (`audit-core::source`) — the narrow door
  every raw event enters through: forward-only, resumable-from-any-
  position pages of raw items, provider-neutral by construction.
- **`safeguard-audit-normalizer`** — deterministic normalization:
  per-scheme parsers that reject unknown fields and wrong types, a
  validator that enforces type-dependent field presence and identifier
  shapes (and re-derives every envelope reference through its public
  constructor), a classifier that projects raw forms onto the envelope
  with canonical on-chain identity, and the `Normalizer` service that
  runs the whole pipeline per item and gates network consistency.
  The scheme registry is deliberately narrow: `hooks-state-event`
  (observed) and `audit-envelope` (re-ingest); transfer outcomes are
  never a raw scheme because denials are not emitted on-chain.
  The parse-validate-classify audit also caught and fixed a Phase-1
  wire-contract drift (`decision.policy` schema vs the real serde shape).
- **`safeguard-audit-indexer`** — checkpointed, idempotent ingestion:
  `run_once` fetches a page, normalizes, verifies strictly increasing
  placement, appends atomically, and checkpoints only after the write
  landed; dedup is keyed by deterministic event identity (skip or fail
  policies); malformed items abort or quarantine per policy; bounded
  `replay_into` reconstructs history into a caller-provided store
  without touching production.
- **`safeguard-audit-integrity`** — tamper-evident hashing over the
  `audit-core` vocabulary: canonical record digests (never hashing the
  record's own integrity block), the chained scheme
  (`digest(N) = H(prev || record(N))`) with deterministic sealing,
  integrity manifest generation with recomputed per-record digests and
  an aggregate over the inventory, machine-readable verification
  (per-record, whole-chain, manifest, aggregate), and tamper location.
- **Test vectors and invariants** — `test-vectors/normalization` as an
  executable corpus (valid + malformed with declared failure classes),
  store-integration integrity tests across the persistence boundary,
  an `safeguard-audit-integration-tests` crate driving the full
  pipeline end-to-end, and a cross-cutting invariants suite (including
  the unified rule that unknown placement sorts after known placement).
- **Examples and docs** — runnable `ingest-event` and `verify-record`
  demos; `event-ingestion`, `event-normalization`, `indexing`, and
  `evidence-integrity` docs.

### Later phases

Phases 3+ (audit authorization services, investigation services,
evidence generation, reporting, privacy enforcement, Soroban/RPC
adapters, the simulator bridge, the optional on-chain registry, and
security/performance hardening) are planned; see `docs/architecture.md`
for the map and this file will record each as it lands.
