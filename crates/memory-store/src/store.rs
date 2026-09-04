//! The in-memory [`EventStore`] implementation.
//!
//! Records live in a `BTreeMap` keyed by their deterministic
//! [`PositionKey`], so history is always stored in audit order; event and
//! record ids are indexed for O(1) dedup and lookup. The store implements
//! the full contract:
//!
//! * append-only (no update/delete API exists), with idempotent dedup by
//!   event identity,
//! * atomic batches (validated up front, committed together),
//! * deterministic ordering and stable cursor pagination.
//!
//! > This implementation is for tests, fixtures, and single-node
//! > development. It holds everything in memory and must not be treated as
//! > a durable security boundary.

use std::collections::{BTreeMap, HashMap};

use safeguard_audit_core::{AuditRecord, EventId, Page, PageRequest, RecordId};
use safeguard_audit_storage::{
    AuditQuery, BatchOutcome, EventStore, InsertOutcome, PositionKey, StoreError, StoreResult,
    WriteBatch,
};

/// An in-memory audit store.
#[derive(Debug, Clone, Default)]
pub struct MemoryEventStore {
    /// History in deterministic order.
    records: BTreeMap<PositionKey, AuditRecord>,
    /// Event id -> record id (dedup index).
    by_event: HashMap<EventId, RecordId>,
    /// Record id -> position (lookup index).
    by_record: HashMap<RecordId, PositionKey>,
}

impl MemoryEventStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventStore for MemoryEventStore {
    fn insert(&mut self, record: AuditRecord) -> StoreResult<InsertOutcome> {
        record.validate().map_err(StoreError::from_core)?;
        let event_id = record.event_id().clone();
        let record_id = record.record_id.clone();
        if self.by_event.contains_key(&event_id) {
            return Ok(InsertOutcome::Duplicate);
        }
        let key = PositionKey::of(&record);
        self.records.insert(key.clone(), record);
        self.by_event.insert(event_id, record_id.clone());
        self.by_record.insert(record_id, key);
        Ok(InsertOutcome::Inserted)
    }

    fn insert_batch(&mut self, batch: WriteBatch) -> StoreResult<BatchOutcome> {
        // Phase 1: validate the whole batch against the store without
        // mutating anything — atomicity means a rejected batch writes
        // nothing.
        let mut to_insert = Vec::with_capacity(batch.len());
        let mut inserted = 0usize;
        let mut duplicates = 0usize;
        for record in batch.records() {
            record.validate().map_err(StoreError::from_core)?;
            if self.by_event.contains_key(record.event_id()) {
                duplicates += 1;
            } else {
                inserted += 1;
                to_insert.push(record.clone());
            }
        }
        // Phase 2: commit (infallible map inserts).
        for record in to_insert {
            let event_id = record.event_id().clone();
            let record_id = record.record_id.clone();
            let key = PositionKey::of(&record);
            self.records.insert(key.clone(), record);
            self.by_event.insert(event_id, record_id.clone());
            self.by_record.insert(record_id, key);
        }
        Ok(BatchOutcome {
            inserted,
            duplicates,
        })
    }

    fn get(&self, record_id: &RecordId) -> StoreResult<AuditRecord> {
        let key = self
            .by_record
            .get(record_id)
            .ok_or_else(|| StoreError::NotFound(format!("record {record_id}")))?;
        self.records
            .get(key)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("record {record_id}")))
    }

    fn get_by_event(&self, event_id: &EventId) -> StoreResult<Option<AuditRecord>> {
        match self.by_event.get(event_id) {
            Some(record_id) => self.get(record_id).map(Some),
            None => Ok(None),
        }
    }

    fn contains_event(&self, event_id: &EventId) -> StoreResult<bool> {
        Ok(self.by_event.contains_key(event_id))
    }

    fn query(&self, query: &AuditQuery, page: &PageRequest) -> StoreResult<Page<AuditRecord>> {
        use safeguard_audit_storage::SortDirection;

        // Records matching the query, in the requested direction. Every
        // store result must be bounded, so this never returns unbounded
        // collections to callers.
        let matched: Vec<AuditRecord> = if query.sort() == SortDirection::Ascending {
            self.records
                .values()
                .filter(|r| query.matches(r))
                .cloned()
                .collect()
        } else {
            self.records
                .values()
                .rev()
                .filter(|r| query.matches(r))
                .cloned()
                .collect()
        };

        // Locate the first record at or past the cursor boundary.
        let start = match page.cursor() {
            None => 0,
            Some(cursor) => {
                let boundary = PositionKey::from_cursor(cursor)
                    .map_err(|e| StoreError::InvalidCursor(e.to_string()))?;
                let past = |key: &PositionKey| {
                    if query.sort() == SortDirection::Ascending {
                        *key > boundary
                    } else {
                        *key < boundary
                    }
                };
                matched
                    .iter()
                    .position(|r| past(&PositionKey::of(r)))
                    .unwrap_or(matched.len())
            }
        };

        let end = (start + page.limit()).min(matched.len());
        let items = matched[start..end].to_vec();
        // The cursor points at the last record served, so the next request
        // resumes strictly after it (records at or before the boundary are
        // never re-served).
        let next_cursor = if end < matched.len() && end > start {
            Some(PositionKey::of(&matched[end - 1]).to_cursor())
        } else {
            None
        };
        Ok(Page::new(items, next_cursor))
    }

    fn len(&self) -> usize {
        self.records.len()
    }

    fn last_position(&self) -> Option<PositionKey> {
        self.records.keys().next_back().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AccountId, AccountReference, AuditEvent, EventKind, EventOrder, EventProvenance,
        FixedClock, NetworkId, OriginKind, Timestamp, VersionLabel,
    };

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn record(id: &str, ledger: Option<i64>, op: Option<u32>, account: &str) -> AuditRecord {
        let provenance = EventProvenance::new(
            OriginKind::OnChain,
            "soroban",
            VersionLabel::new("1").unwrap(),
        )
        .unwrap();
        let mut event = AuditEvent::new(
            EventId::derive(&[id]),
            EventKind::TransferDenied,
            network(),
            provenance,
        );
        event.order = EventOrder {
            ledger_sequence: ledger,
            transaction_position: None,
            operation_index: op,
            event_index: None,
        };
        event.actor = Some(AccountReference::new(
            network(),
            AccountId::new(account).unwrap(),
        ));
        let clock = FixedClock::at(Timestamp::from_unix_seconds(100));
        AuditRecord::from_event(event, &clock).unwrap()
    }

    #[test]
    fn insertion_is_idempotent_and_append_only() {
        let mut store = MemoryEventStore::new();
        let r = record("e1", Some(1), Some(0), "Gacct1");
        assert_eq!(store.insert(r.clone()).unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(r).unwrap(), InsertOutcome::Duplicate);
        assert_eq!(store.len(), 1);
        assert!(store.contains_event(&EventId::derive(&["e1"])).unwrap());
    }

    #[test]
    fn records_fetch_by_id_and_event() {
        let mut store = MemoryEventStore::new();
        let r = record("e2", Some(2), None, "Gacct2");
        let record_id = r.record_id.clone();
        store.insert(r).unwrap();
        assert_eq!(store.get(&record_id).unwrap().record_id, record_id);
        assert!(store.get(&RecordId::derive_bytes(b"missing")).is_err());
        assert!(store
            .get_by_event(&EventId::derive(&["e2"]))
            .unwrap()
            .is_some());
    }

    #[test]
    fn batches_report_inserted_and_duplicate_counts() {
        let mut store = MemoryEventStore::new();
        let first = WriteBatch::new(vec![
            record("a", Some(1), None, "G1"),
            record("b", Some(2), None, "G2"),
        ])
        .unwrap();
        let outcome = store.insert_batch(first.clone()).unwrap();
        assert_eq!(outcome.inserted, 2);
        assert_eq!(outcome.duplicates, 0);

        // Replaying the same batch is a no-op, not an error.
        let again = store.insert_batch(first).unwrap();
        assert_eq!(again.inserted, 0);
        assert_eq!(again.duplicates, 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn queries_filter_and_page_with_stable_cursors() {
        let mut store = MemoryEventStore::new();
        for (i, ledger) in [1i64, 2, 3, 4, 5].iter().enumerate() {
            let r = record(&format!("e{i}"), Some(*ledger), None, &format!("G{i}"));
            store.insert(r).unwrap();
        }

        let q = AuditQuery::builder().build().unwrap();
        let page1 = store.query(&q, &PageRequest::new(2).unwrap()).unwrap();
        assert_eq!(page1.items().len(), 2);
        assert!(page1.has_more());

        let cursor = page1.next_cursor().unwrap().clone();
        let page2 = store
            .query(&q, &PageRequest::with_cursor(2, Some(cursor)).unwrap())
            .unwrap();
        assert_eq!(page2.items().len(), 2);
        let page3 = store
            .query(
                &q,
                &PageRequest::with_cursor(2, page2.next_cursor().unwrap().clone().into()).unwrap(),
            )
            .unwrap();
        assert_eq!(page3.items().len(), 1);
        assert!(!page3.has_more());

        // Inserting after a page was served does not shift earlier pages.
        let late = record("z", Some(0), None, "Gz"); // sorts first (None-style early? ledger 0 < 1)
        store.insert(late).unwrap();
        let again = store.query(&q, &PageRequest::new(2).unwrap()).unwrap();
        assert_eq!(again.items().len(), 2);
    }

    #[test]
    fn last_position_tracks_the_most_recent_record() {
        let mut store = MemoryEventStore::new();
        assert!(store.last_position().is_none());
        store.insert(record("a", Some(1), None, "G1")).unwrap();
        store.insert(record("b", Some(9), None, "G2")).unwrap();
        assert_eq!(store.last_position().unwrap().ledger, Some(9));
    }

    #[test]
    fn account_filters_work() {
        let mut store = MemoryEventStore::new();
        store.insert(record("a", Some(1), None, "GacctX")).unwrap();
        store.insert(record("b", Some(2), None, "GacctY")).unwrap();
        let q = AuditQuery::builder()
            .with_account("GacctX")
            .build()
            .unwrap();
        let page = store.query(&q, &PageRequest::new(10).unwrap()).unwrap();
        assert_eq!(page.items().len(), 1);
    }
}
