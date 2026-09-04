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

### Later phases

Phases 2+ (event pipeline and normalization, integrity hashing, audit
authorization services, investigation services, evidence generation,
reporting, privacy enforcement, Soroban/RPC adapters, the simulator
bridge, the optional on-chain registry, and security/performance
hardening) are planned; see `docs/architecture.md` for the map and this
file will record each as it lands.
