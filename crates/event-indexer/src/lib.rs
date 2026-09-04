//! # safeguard-audit-indexer
//!
//! Checkpointed, idempotent event ingestion for the audit layer.
//!
//! The indexer sits between an [`EventSource`] (a Soroban ledger, an RPC
//! feed, the simulator, a fixture) and the [`EventStore`] that persists
//! audit records. Its job is to make ingestion safe under the conditions
//! the spec demands — events may arrive more than once, the process may
//! stop and restart at any point, and history must be reproducible:
//!
//! * **Checkpointing** — the indexer persists the source position it has
//!   consumed and resumes from it after a restart, never re-serving what
//!   was already checkpointed and never skipping what was not.
//! * **Deduplication** — an event is recorded at most once, keyed by its
//!   deterministic event identity (not arrival time, not position). The
//!   store's idempotent insert makes re-runs converge instead of
//!   duplicating.
//! * **Deterministic ordering** — pages are verified monotonic in the
//!   on-chain ordering hierarchy before they are committed, so history
//!   cannot be scrambled by a misbehaving source.
//! * **Replay** — history can be reconstructed into a fresh store from a
//!   source window without mutating production history.
//!
//! The indexer never decides *policy* and never judges payloads; it only
//! shepherds normalized events from source to store, atomically and in
//! order.
//!
//! [`EventSource`]: safeguard_audit_core::EventSource
//! [`EventStore`]: safeguard_audit_storage::EventStore

pub mod checkpoint;
pub mod cursor;
pub mod deduplication;
pub mod errors;
pub mod ordering;

pub use checkpoint::{Checkpoint, CheckpointStore, InMemoryCheckpointStore};
pub use cursor::{CursorError, SourceCursor};
pub use deduplication::{classify, DedupGuard, DedupPolicy, DedupResult};
pub use errors::{IndexerError, IndexerResult};
pub use ordering::{compare_order, describe_difference, is_strictly_increasing};
