# Event ingestion

Ingestion is how raw events enter the audit system. Its contract is
defined by the conditions the real world imposes:

* events may arrive **more than once** (at-least-once feeds, retries),
* the process may **stop and restart** at any point,
* a misbehaving source must not be able to **scramble history**,
* and history must be **reproducible**.

The core rule that satisfies all of them: *an event is recorded at most
once, keyed by its deterministic event identity — never by arrival time
and never by source position.*

## The door: `EventSource`

`audit-core::source` defines the narrow door every raw event enters
through. A source yields bounded pages of `RawEventItem`s — each with a
parsing scheme label, the raw JSON payload, and a stable position — and
must be resumable from any position it ever reported. Nothing in the
core parses, classifies, or judges payloads; providers (a Soroban
ledger, an RPC feed, the simulator, a fixture file) all implement the
same forward-only contract.

```text
EventSource (raw items + positions)
  → EventSource page
  → Normalizer (parse → validate → classify)
  → EventStore (append-only, idempotent)
  → CheckpointStore (durable "where did I leave off")
```

## The loop: `Indexer::run_once`

The indexer (`crates/event-indexer`) advances one source by exactly one
page in a crash-safe order:

1. load the checkpoint for the source (or start fresh),
2. fetch the page after the checkpointed position,
3. normalize every item,
4. verify the page's known placements are strictly increasing,
5. append the records **atomically** (the store deduplicates by event
   identity),
6. checkpoint the last consumed position — **only after** the store
   write durably landed.

The ordering of steps 5 and 6 is the whole crash-safety story: a crash
before the checkpoint re-serves the page next run and deduplication
absorbs it; a checkpoint is never advanced past work that did not
persist.

## Deduplication

Dedup is keyed by the deterministic `EventId` derived during
normalization. The store is the durable source of truth — its idempotent
insert reports duplicates instead of writing twice — and the indexer's
`DedupGuard` tracks what a single run already appended so it stops
asking the store about events it just wrote.

Two policies decide what a duplicate means:

* **SkipDuplicates** (default) — expected on resume, re-run, and
  backfill; skip and continue.
* **FailOnDuplicate** — any duplicate is a bug worth stopping for.

## Checkpoints

A checkpoint answers "which source position has this indexer consumed up
to?" It is scoped to a source name (a stale checkpoint from another feed
can never be resumed) and persisted only after committed work.
`CheckpointStore` is the durable contract; `InMemoryCheckpointStore` is
provided for tests and single-process runs and is clearly labelled as
non-durable.

## Ordering

Pages must be strictly increasing in the on-chain placement hierarchy
(ledger, operation, event) before they commit. Unknown placement sorts
into an explicit uncertainty band rather than being guessed at — see
`docs/indexing.md`.

## Failure handling

The indexer keeps four failure domains distinct so an operator can react
to the *kind* of failure:

| Domain | Meaning | Reaction |
|---|---|---|
| Source | fetch failed (network, malformed reply) | Retry at the page; never checkpoint past it. |
| Normalization | unsupported scheme/version, malformed/invalid payload | Per-item: abort the run (default) or skip-and-report into the report's quarantine list. |
| Ordering | page not strictly increasing | Abort before commit; a misbehaving source cannot scramble history. |
| Checkpoint / store | checkpoint or backend failure | Operator intervention; never advance the checkpoint past unpersisted work. |

## Replay

`replay_into` reconstructs history into the store the caller provides —
production stores are never touched implicitly — using its own private
checkpoint so it can start anywhere in the source without interfering
with the live indexer. Budgets (`max_pages`, `max_records`) bound the
run at page granularity and report `truncated` honestly. See
`docs/replay.md` for details.
