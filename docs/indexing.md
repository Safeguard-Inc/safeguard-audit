# Indexing, ordering, and checkpoints

The indexer crate (`crates/event-indexer`) is the checkpointed,
idempotent ingestion layer. This document covers the design decisions
behind how it orders history, where its checkpoints live, and how replay
reconstructs windows.

## Deterministic ordering

Audit history must come out in the same order no matter how the indexer
happened to fetch it. Ordering follows the on-chain hierarchy — ledger
sequence, then operation index, then event index — **never local arrival
time**. `ordering.rs` defines a total comparison over the envelope's
`EventOrder` metadata:

* missing components sort into an explicit uncertainty band (a
  placement without a ledger sequence orders *after* any placement with
  one);
* pages are checked `is_strictly_increasing` before they commit, so a
  misbehaving source cannot scramble history;
* `describe_difference` explains *where* two placements diverge for
  operator diagnostics.

## Store ordering

Records are persisted through the `EventStore` contract, whose position
key orders history deterministically by `(ledger, operation, event,
recorded_at, record id)`. Events carrying on-chain placement therefore
read back in ledger order — which is also the order a chained digest
sequence must be verified in. Events without placement (an explicit
uncertainty case) sort by their deterministic record id, which is stable
across runs.

## Checkpoint semantics

A checkpoint is `(source name, last consumed position)`. The indexer:

* **loads** it once per run and resumes fetching strictly after it;
* **saves** it only after a page's records are durably in the store.

Because the store is append-only and inserts are idempotent, the exact
position of the save boundary is recoverable: crash before save →
re-serve the page → duplicates absorbed; crash after save → resume clean.
A checkpoint from a different source name can never be resumed against
the wrong feed.

Positions are opaque to everything except the source that minted them
and the store that persists them (`cursor.rs` only validates their
shape: non-space printable ASCII, 1-512 chars).

## Resume and idempotence guarantees

* Re-running the same window adds nothing (`inserted == 0`).
* A page-limited run can stop mid-window; the next run resumes from the
  checkpoint and completes it without duplicating the earlier pages.
* Re-ingesting an already-populated window with a fresh checkpoint (an
  operator reset) is absorbed by store-level dedup.
* Malformed items abort before anything from their page commits (or,
  under `SkipAndReport`, are quarantined with their source positions
  surfaced in the report).

## Bounded replay

Replay is *not* the live indexer with different knobs — it is a separate
function with deliberately different guarantees:

* it writes only into the caller-provided store, so production history
  is never touched implicitly;
* it uses its own private checkpoint, so it never interferes with the
  live indexer's checkpoint;
* budgets (`max_pages`, `max_records`, at page granularity) stop the run
  while more source remains and report `truncated` honestly — draining
  the source is always a complete, untruncated replay.

Because record ids are derived deterministically from canonical event
bytes, a replay reproduces byte-identical records (same record ids,
same events), which is what makes "reconstruct and verify" a meaningful
operation.
