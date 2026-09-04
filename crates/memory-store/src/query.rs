//! Convenience queries over the in-memory store.
//!
//! The store's [`EventStore::query`] takes an [`AuditQuery`]; these helpers
//! assemble the common single-dimension queries so tests and the CLI's
//! `query` command stay terse. All of them page through the store contract
//! rather than reaching into its internals.

use safeguard_audit_core::{AuditRecord, Page, PageRequest};
use safeguard_audit_storage::{AuditQuery, AuditQueryBuilder, EventStore, StoreError, StoreResult};

/// Converts a core pagination error into the store taxonomy.
fn page_request(limit: usize) -> StoreResult<PageRequest> {
    PageRequest::new(limit).map_err(|e| StoreError::InvalidQuery(e.to_string()))
}

/// Fetches up to `limit` records involving `account`.
pub fn by_account<S: EventStore>(
    store: &S,
    account: &str,
    limit: usize,
) -> StoreResult<Page<AuditRecord>> {
    let query = AuditQuery::builder()
        .with_account(account)
        .build()
        .map_err(|e| StoreError::InvalidQuery(e.to_string()))?;
    store.query(&query, &page_request(limit)?)
}

/// Fetches up to `limit` records for a transaction hash.
pub fn by_transaction<S: EventStore>(
    store: &S,
    hash: &str,
    limit: usize,
) -> StoreResult<Page<AuditRecord>> {
    let query = AuditQuery::builder()
        .with_transaction(hash)
        .build()
        .map_err(|e| StoreError::InvalidQuery(e.to_string()))?;
    store.query(&query, &page_request(limit)?)
}

/// Fetches up to `limit` denied records.
pub fn denied<S: EventStore>(store: &S, limit: usize) -> StoreResult<Page<AuditRecord>> {
    let query = AuditQuery::builder()
        .with_decision(safeguard_audit_core::DecisionResult::Denied)
        .build()
        .map_err(|e| StoreError::InvalidQuery(e.to_string()))?;
    store.query(&query, &page_request(limit)?)
}

/// Builds an [`AuditQuery`] through the builder, mapping validation errors.
pub fn build_query(
    f: impl FnOnce(AuditQueryBuilder) -> AuditQueryBuilder,
) -> StoreResult<AuditQuery> {
    f(AuditQuery::builder())
        .build()
        .map_err(|e| StoreError::InvalidQuery(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryEventStore;
    use safeguard_audit_core::{
        AccountId, AccountReference, AuditEvent, EventId, EventKind, EventOrder, EventProvenance,
        FixedClock, NetworkId, OriginKind, Timestamp, VersionLabel,
    };

    fn record(id: &str, account: &str, tx: &str) -> safeguard_audit_core::AuditRecord {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let provenance = EventProvenance::new(
            OriginKind::OnChain,
            "soroban",
            VersionLabel::new("1").unwrap(),
        )
        .unwrap();
        let mut event = AuditEvent::new(
            EventId::derive(&[id, tx]),
            EventKind::TransferDenied,
            network.clone(),
            provenance,
        );
        event.actor = Some(AccountReference::new(
            network.clone(),
            AccountId::new(account).unwrap(),
        ));
        event.transaction = Some(safeguard_audit_core::TransactionReference::new(
            network.clone(),
            safeguard_audit_core::TransactionHash::new(tx).unwrap(),
        ));
        event.order = EventOrder {
            ledger_sequence: Some(5),
            transaction_position: None,
            operation_index: None,
            event_index: None,
        };
        event.outcome = Some(safeguard_audit_core::DecisionResult::Denied);
        let clock = FixedClock::at(Timestamp::from_unix_seconds(10));
        safeguard_audit_core::AuditRecord::from_event(event, &clock).unwrap()
    }

    #[test]
    fn convenience_queries_route_through_the_store_contract() {
        let mut store = MemoryEventStore::new();
        store.insert(record("a", "Gacct1", "txaa")).unwrap();
        store.insert(record("b", "Gacct2", "txbb")).unwrap();

        let page = by_account(&store, "Gacct1", 10).unwrap();
        assert_eq!(page.items().len(), 1);

        let page = denied(&store, 10).unwrap();
        assert_eq!(page.items().len(), 2);

        let page = by_transaction(&store, "txbb", 10).unwrap();
        assert_eq!(page.items().len(), 1);
    }
}
