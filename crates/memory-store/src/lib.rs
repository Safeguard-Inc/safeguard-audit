//! # safeguard-audit-memory-store
//!
//! An in-memory [`EventStore`] implementation for tests, fixtures, and
//! single-node development.
//!
//! Records are kept in a `BTreeMap` keyed by their deterministic position,
//! so history is always stored in audit order and cursor pagination is
//! stable under inserts. Duplicate ingestion is idempotent by event
//! identity, batches are atomic, and there is no update or delete path —
//! the store is append-only by construction.
//!
//! > **Warning**: this implementation holds everything in memory and is for
//! > testing/development only. It must not be treated as a security
//! > boundary or as durable evidence storage.

pub mod errors;
pub mod query;
pub mod store;

pub use errors::{StoreError, StoreResult};
pub use store::MemoryEventStore;
