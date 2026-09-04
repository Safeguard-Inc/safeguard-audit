//! Cross-cutting invariants that no single crate test owns.
//!
//! These tests pin properties the whole design depends on: deterministic
//! record identity across independent runs, deterministic ordering of
//! history, and append-only immutability where the first write of an
//! event always wins.

use safeguard_audit_core::{
    AuditRecord, EventKind, EventSource, FixedClock, NetworkId, PageRequest, RawEventItem,
    SourcePage, SourceResult, Timestamp, VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, Indexer, MalformedItemPolicy};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore, InsertOutcome};

const BOUND_FIXTURE: &str =
    include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
const CONFIG_FIXTURE: &str =
    include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");
const FROZEN_FIXTURE: &str =
    include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:invariants"
    }
    fn fetch_after(&mut self, after: Option<&str>, limit: usize) -> SourceResult<SourcePage> {
        let start = match after {
            None => 0,
            Some(pos) => {
                self.items
                    .iter()
                    .position(|i| i.position() == pos)
                    .ok_or_else(|| {
                        safeguard_audit_core::SourceError::InvalidPosition(pos.to_owned())
                    })?
                    + 1
            }
        };
        let end = (start + limit).min(self.items.len());
        let items = self.items[start..end].to_vec();
        let next = if end < self.items.len() {
            Some(self.items[end - 1].position().to_owned())
        } else {
            None
        };
        Ok(SourcePage::new(items, next))
    }
}

fn fixtures() -> Vec<RawEventItem> {
    vec![
        RawEventItem::new("hooks-state-event", BOUND_FIXTURE, "ledger:415").unwrap(),
        RawEventItem::new("hooks-state-event", CONFIG_FIXTURE, "ledger:419").unwrap(),
        RawEventItem::new("hooks-state-event", FROZEN_FIXTURE, "ledger:423").unwrap(),
    ]
}

fn normalizer() -> Normalizer {
    Normalizer::new(NormalizeConfig::new(
        NetworkId::new(NetworkId::TESTNET).unwrap(),
        "safeguard-hooks",
        VersionLabel::new("1.0.0").unwrap(),
    ))
}

fn indexer() -> Indexer {
    Indexer::new(
        normalizer(),
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        100,
    )
    .unwrap()
}

/// Indexes the fixture window into a fresh store, returning the store.
fn index_fresh() -> MemoryEventStore {
    let mut checkpoints = safeguard_audit_indexer::InMemoryCheckpointStore::new();
    let mut store = MemoryEventStore::new();
    let mut source = FixtureSource { items: fixtures() };
    indexer()
        .run_once(&mut source, &mut checkpoints, &mut store)
        .unwrap();
    store
}

fn fetch_all(store: &MemoryEventStore) -> Vec<AuditRecord> {
    store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(1000).unwrap(),
        )
        .unwrap()
        .items()
        .to_vec()
}

#[test]
fn invariant_record_identity_is_deterministic_across_runs() {
    // Two fully independent runs over the same source must produce the
    // same record ids for the same events.
    let store_a = index_fresh();
    let store_b = index_fresh();

    let ids_a: Vec<String> = fetch_all(&store_a)
        .iter()
        .map(|r| r.record_id.to_string())
        .collect();
    let ids_b: Vec<String> = fetch_all(&store_b)
        .iter()
        .map(|r| r.record_id.to_string())
        .collect();
    assert_eq!(
        ids_a, ids_b,
        "record ids must not depend on run order or timing"
    );
}

#[test]
fn invariant_ordered_events_read_back_in_ledger_order() {
    // Even though the events were recorded with a fixed clock (identical
    // recorded_at), store ordering follows on-chain placement.
    let store = index_fresh();
    let ledgers: Vec<i64> = fetch_all(&store)
        .iter()
        .map(|r| {
            r.event
                .order
                .ledger_sequence
                .expect("fixtures carry ledgers")
        })
        .collect();
    assert_eq!(ledgers, vec![415, 419, 423]);
    assert!(ledgers.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn invariant_events_without_placement_sort_deterministically_last() {
    // An event without on-chain placement must land in the uncertainty
    // band (after every placed event) rather than interleaving randomly.
    let network = NetworkId::new(NetworkId::TESTNET).unwrap();
    let provenance = safeguard_audit_core::EventProvenance::new(
        safeguard_audit_core::OriginKind::Derived,
        "safeguard-audit",
        VersionLabel::new("1.0.0").unwrap(),
    )
    .unwrap()
    .with_derivation(
        safeguard_audit_core::DerivationInfo::new(
            "no-placement-test",
            Vec::new(),
            "derived event with no on-chain placement",
        )
        .unwrap(),
    );
    let mut unplaced = safeguard_audit_core::AuditEvent::new(
        safeguard_audit_core::EventId::derive(&["testnet", "unplaced"]),
        EventKind::ReportGenerated,
        network,
        provenance,
    );
    unplaced.details.insert("test".into(), "1".into());

    let mut store = index_fresh();
    store
        .insert(
            AuditRecord::from_event(
                unplaced,
                &FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
            )
            .unwrap(),
        )
        .unwrap();

    let read_back = fetch_all(&store);
    assert_eq!(read_back.len(), 4);
    let last = read_back.last().unwrap();
    assert!(last.event.order.ledger_sequence.is_none());
    // The three placed records still lead in ledger order.
    let placed: Vec<i64> = read_back[..3]
        .iter()
        .map(|r| r.event.order.ledger_sequence.unwrap())
        .collect();
    assert_eq!(placed, vec![415, 419, 423]);
}

#[test]
fn invariant_first_write_of_an_event_always_wins() {
    // The store is append-only and keyed by event identity: re-recording
    // an event (even with a different recording time) reports a duplicate
    // and preserves the original record — history is never rewritten.
    let store_a = index_fresh();
    let original = fetch_all(&store_a)[0].clone();

    let mut store = MemoryEventStore::new();
    assert_eq!(
        store.insert(original.clone()).unwrap(),
        InsertOutcome::Inserted
    );

    // Same event, recorded later by a different clock: duplicate, and the
    // original body is preserved.
    let later_clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_999));
    let re_recorded = AuditRecord::from_event(original.event.clone(), &later_clock).unwrap();
    assert_eq!(re_recorded.record_id, original.record_id);
    assert_ne!(re_recorded.recorded_at, original.recorded_at);

    assert_eq!(store.insert(re_recorded).unwrap(), InsertOutcome::Duplicate);
    assert_eq!(store.len(), 1);
    let stored = store.get(&original.record_id).unwrap();
    assert_eq!(stored.recorded_at, original.recorded_at);
    assert_eq!(stored.event.event_id, original.event.event_id);
}

#[test]
fn invariant_every_stored_record_holds_a_valid_event() {
    let store = index_fresh();
    for record in fetch_all(&store) {
        record
            .event
            .validate()
            .expect("stored events must satisfy envelope invariants");
        record
            .validate()
            .expect("stored records must satisfy record invariants");
        // Record identity is derived from the canonical event: re-deriving
        // from the stored event reproduces the stored id.
        let rederived =
            AuditRecord::from_event(record.event.clone(), &FixedClock::at(record.recorded_at))
                .unwrap();
        assert_eq!(rederived.record_id, record.record_id);
    }
}
