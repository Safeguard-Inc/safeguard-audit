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

### Phase 3 — Authorization services (complete)

The decision engine over the Phase-1 authorization models, and the
access trail that records its outcomes:

- **`safeguard-audit-authorization`** — the role-to-permission matrix
  (one auditable cumulative table per `AuditorRole`, least-privilege by
  default); per-identity permission sets with additive/subtractive
  overrides that are explainable (`GrantedByRole`, `GrantedByOverride`,
  `ExplicitlyDenied`, `NotGranted`) and validated against role-baseline
  noise; scope containment as the single path to a grant (`All` covers
  everything by policy only, kinds never cross, classification grants
  are directional, time ranges must fully contain); auditor credentials
  with time-aware expiry and revocation verified against an injected
  clock (with hashed, never-exposed credential references); the auditor
  registry (who holds which role, scopes, and credential; scope-less
  grants rejected); and the authorizer composing credential → action →
  scope into an attributed decision with the fixed contract order.
- **Audit-access logging** — every decision becomes an `AuditAccessEntry`
  and lands in the `EventStore` as a derived `audit-access` record
  (idempotent per entry id, never re-authorized: the recursion boundary
  is explicit). The projection now stamps attribution — `auditor`,
  `accessed_at`, and `classification` — so a stored record answers
  who/what/when directly; the entry model gained the matching
  `classification()` accessor.
- **Privacy linkage** — `scope_for_classification` maps a record's
  `DataClassification` to the scope that must be granted, and
  `covers_classification` asks whether grants reach that level, so
  protected data is gated by the same containment rules as everything
  else.
- **Scenarios and invariants** — end-to-end authorization tests
  (authorized reads, action denials, out-of-scope requests, expired
  credentials denying even an administrator, a four-hop privilege-
  escalation attempt where every hop is denied/out-of-scope and
  recorded); cross-cutting invariants (no protected-data access without
  a granted classification scope, full attribution on every access
  record, unregistered auditors denied cleanly); and
  `test-vectors/authorization` as an executable corpus of allowed/
  denied/out-of-scope decisions.
- **Fixtures, examples, docs** — schema-validated decision fixtures for
  every outcome (granted/denied/out-of-scope) plus schema coverage for
  the unauthorized auditor fixture; the runnable `authorize-access`
  example; and `authorization`, `auditor-model`, and `access-control`
  docs.

### Phase 4 — Investigation services (complete)

The case workflow that turns denied or flagged operations into structured,
auditable investigations:

- **`safeguard-audit-investigation`** — the `CaseStore` contract for
  mutable case state (current state; history lives in the audit store as
  lifecycle events) with an in-memory implementation, and `CaseService`,
  the workflow facade: open (deterministic case id from network + case
  key), assign, status transitions validated by the core model, link
  audit records (verified to exist in the audit store — a case never
  references a ghost), findings and notes with deterministic per-case
  ids, and closure that requires a recorded reason and is terminal
  unless an administrator reopens the case. Every step is authorized
  through the real authorizer (`CreateInvestigation` to open or mutate,
  administrator role to reopen) and projected as an
  `investigation-opened` / `investigation-updated` /
  `investigation-closed` event.
- **Lifecycle identity** — two modeling fixes surfaced by the service:
  the event kind is now explicit (`LifecycleKind`), so updates that
  leave a case open or reopen a closed case are never misrecorded as a
  second open; and each step carries its zero-based sequence in the
  case history as part of the event identity, so distinct steps of one
  case never collide in the store while re-runs stay idempotent.
- **Scenarios, vectors, invariants** — end-to-end denial-to-closed tests
  asserting both views (case-store state and audit-store history),
  `test-vectors/investigation/lifecycle` as an executable transition
  corpus (all legal and illegal moves), and invariants for deterministic
  case ids and collision-free step identity under a fixed clock.
- **Fixtures, example, docs** — schema-validated closed and escalated
  case fixtures alongside the open case; the runnable
  `create-investigation` example; and `investigation.md` covering the
  two-store model, the workflow, and the authorization gates.

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

### Phase 5 — Evidence services (complete)

Turning verified audit records into exportable, independently checkable
evidence packages:

- **`safeguard-audit-evidence`** — the `EvidenceBuilder` pipeline
  (authorize the acting auditor, prove every named record exists in the
  audit store, refuse records whose stored digest no longer matches
  their body, canonicalize the record order, seal); the `EvidencePackage`
  model pairing an `EvidenceArtifact` (content digest over its canonical
  bytes, integrity slots excluded) with an artifact-linked
  `EvidenceManifest` (per-record digests recomputed from record bodies,
  an aggregate over the inventory, and the artifact/parser/network
  context); and two-depth verification — structure-only for exported
  packages (artifact digest + manifest aggregate) and store-backed
  (every per-record digest recomputed from the fetched bodies). Every
  generation is itself recorded as a derived `evidence-generated` event
  carrying the artifact id, kind, record count, manifest reference, and
  digest.
- **Integrity gate** — one architectural alignment: the pipeline seals
  history at verification time, so stored records may carry no integrity
  block. The gate refuses only records whose *stored* digest no longer
  matches their body; unsealed records are accepted with their digest
  recomputed and captured in the manifest, so later alteration stays
  detectable. The frozen-account fixture also gained its missing serde
  `details` field (schema-valid but previously not deserializable).
- **Scenarios, vectors, invariants** — end-to-end tests over the real
  pipeline (ingest → seal → recorded generation → verify → wire-level
  tamper detection), `test-vectors/evidence` as an executable
  integrity corpus (a verified package plus flipped artifact digest,
  flipped aggregate, and swapped entry), and a cross-cutting invariant
  pinning byte-identical reproducibility and conjunctive verification.
- **Fixtures, example, docs** — the placeholder evidence fixtures
  (fake digests, mismatched artifact/manifest pair) replaced with real
  generated packages; the runnable `generate-evidence` example; and
  `evidence.md` covering the package model, the build pipeline, the two
  verification depths, and the honest limits.

### Later phases

Phases 7+ (reporting, privacy enforcement, Soroban/RPC adapters, the
simulator bridge, the optional on-chain registry, and
security/performance hardening) are planned; see `docs/architecture.md`
for the map and this file will record each as it lands.
