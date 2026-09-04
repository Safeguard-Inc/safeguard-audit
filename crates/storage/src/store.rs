//! The [`EventStore`] interface.
//!
//! The core domain never names a database. Everything that persists audit
//! records speaks to this trait: append with idempotent dedup, fetch by
//! identity, query with stable cursor pagination, and snapshot.
//!
//! ## Contract
//!
//! * Records are **append-only**: the interface has no update or delete.
//! * Insertion is **idempotent**: inserting an event that is already
//!   present reports [`InsertOutcome::Duplicate`] instead of failing or
//!   writing twice.
//! * Batches are **atomic**: either every record lands or none do.
//! * Query results are **deterministically ordered** by the record
//!   position key and page via opaque cursors that stay stable under
//!   inserts.
//!
//! Implementations may be in-memory (tests, single-node), an embedded KV,
//! or a SQL database behind an adapter — the trait never changes.

use safeguard_audit_core::{AuditRecord, EventId, Page, PageRequest, RecordId};

use crate::errors::{StoreError, StoreResult};
use crate::pagination::PositionKey;
use crate::query::AuditQuery;
use crate::transaction::{BatchOutcome, WriteBatch};

/// What an insert call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The record was newly appended.
    Inserted,
    /// The record (by event identity) was already present; nothing changed.
    Duplicate,
}

impl InsertOutcome {
    /// Whether the insert changed the store.
    pub fn changed(&self) -> bool {
        matches!(self, Self::Inserted)
    }
}

/// The append-only audit store contract.
///
/// All mutating methods take `&mut self`: stores are used single-writer
/// (one indexer process), and synchronization at a shared boundary is the
/// adapter's concern, not the trait's.
pub trait EventStore {
    /// Appends one record. Duplicate events are reported, not written.
    fn insert(&mut self, record: AuditRecord) -> StoreResult<InsertOutcome>;

    /// Appends a batch atomically: all records validate up front and the
    /// store accepts the whole batch or rejects it with no partial write.
    fn insert_batch(&mut self, batch: WriteBatch) -> StoreResult<BatchOutcome>;

    /// Fetches a record by its deterministic record id.
    fn get(&self, record_id: &RecordId) -> StoreResult<AuditRecord>;

    /// Fetches the record recorded for an event id, if any (dedup lookup).
    fn get_by_event(&self, event_id: &EventId) -> StoreResult<Option<AuditRecord>>;

    /// Whether an event id is already recorded.
    fn contains_event(&self, event_id: &EventId) -> StoreResult<bool>;

    /// Queries records in deterministic order with cursor pagination.
    fn query(&self, query: &AuditQuery, page: &PageRequest) -> StoreResult<Page<AuditRecord>>;

    /// The number of records stored.
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The position key of the most recently appended record, when any.
    fn last_position(&self) -> Option<PositionKey>;
}

/// Validates a record before insertion and enforces the batch contract.
pub fn validate_insertable(record: &AuditRecord) -> StoreResult<()> {
    record.validate().map_err(StoreError::from_core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_outcomes_are_queryable() {
        assert!(InsertOutcome::Inserted.changed());
        assert!(!InsertOutcome::Duplicate.changed());
    }
}
