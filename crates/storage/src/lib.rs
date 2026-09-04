//! # safeguard-audit-storage
//!
//! The storage *interface* for the Safeguard audit layer.
//!
//! The core domain defines what an audit record is; this crate defines how
//! records are persisted and queried — as a trait contract, not a backend.
//! [`EventStore`] is the append-only, idempotent, queryable interface every
//! store implementation (in-memory, embedded KV, SQL adapter) provides.
//!
//! The crate also owns the pieces of that contract that are backend-
//! independent: the [`AuditQuery`] predicate model, deterministic
//! [`PositionKey`] ordering with lossless cursor encoding, and atomic
//! [`WriteBatch`]es. Store implementations translate these shapes onto
//! their backend; nothing in this crate talks to a concrete database.

pub mod errors;
pub mod pagination;
pub mod query;
pub mod store;
pub mod transaction;

pub use errors::{StoreError, StoreResult};
pub use pagination::PositionKey;
pub use query::{AuditQuery, AuditQueryBuilder, SortDirection};
pub use store::{EventStore, InsertOutcome};
pub use transaction::{BatchOutcome, WriteBatch};
