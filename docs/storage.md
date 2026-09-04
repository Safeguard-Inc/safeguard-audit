# Storage

Audit history is append-only, idempotent, deterministically ordered, and
bounded at every query surface. The `EventStore` trait in
`crates/safeguard-audit-storage` is the contract every backend implements;
no production database is hard-coded anywhere, and the core domain never
names one.

## The contract

* **Append-only.** The trait has no update and no delete. Records cannot be
  silently rewritten; corrections append `record-corrected` records.
* **Idempotent.** Inserting an event already present reports
  `InsertOutcome::Duplicate` — it never fails and never double-writes.
  Duplicate ingestion of the same source event is therefore a no-op, which
  is what makes an indexer safe to stop and restart.
* **Atomic batches.** A `WriteBatch` is validated as a whole (records plus
  intra-batch uniqueness) before anything is written; the store commits the
  whole batch or nothing. No partial histories.
* **Deterministic order.** Every record has a `PositionKey`: the on-chain
  hierarchy (ledger sequence, operation index, event index) first, then
  recording time and record id as tiebreakers. Arrival order never
  dominates history order.
* **Stable cursor paging.** Cursors point at the last record served, not a
  count, so pages stay correct while history grows and never re-serve or
  skip records. All query paths return `Page<AuditRecord>`; nothing returns
  unbounded collections.

## Queries

`AuditQuery` filters by network, token, account (actor or subject),
transaction hash, policy contract, decision/outcome, event kind, and time
range — each filter optional, all ANDed, contradictions rejected at build
time (for example, a token scope on a different network than the query).
Stores translate the predicate onto their backend or apply the pure
`matches()` when scanning is acceptable.

## Implementations

* `memory-store` — the in-memory implementation for tests, fixtures, and
  single-node development. History lives in a `BTreeMap` keyed by position
  with event/record indexes. It is explicitly **non-durable** and must not
  be treated as a security boundary.
* Production backends (embedded KV, SQL) arrive as adapters implementing
  the same trait; callers never branch on which store they talk to, and the
  store's `StoreError` taxonomy is shared.

## Snapshotting and retention

Later phases add snapshot/restore (checkpointing with the indexer) and
retention *enforcement*. The retention *model* already exists in
`audit-core`: policies evaluate to eligibility (archival, and deletion only
when a policy explicitly opts in), and holds — legal or investigation —
always override elapsed time. Audit evidence is not destroyed by default,
and this layer performs no irreversible deletion on its own.
