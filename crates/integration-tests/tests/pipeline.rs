//! End-to-end pipeline: raw fixture source -> normalize -> index -> store
//! -> replay -> integrity verification.
//!
//! This is the phase-2 acceptance flow in one test: the same committed
//! fixtures an operator would ingest flow through the real normalizer,
//! indexer, checkpoint, and store; history is read back in order, sealed
//! into a chain, and verified; and a replay into a scratch store
//! reproduces byte-identical records without touching the production
//! store.

use safeguard_audit_core::{
    AuditRecord, EventSource, FixedClock, NetworkId, PageRequest, RawEventItem, SourcePage,
    SourceResult, Timestamp, VersionLabel,
};
use safeguard_audit_indexer::CheckpointStore;
use safeguard_audit_indexer::{
    replay_into, DedupPolicy, Indexer, MalformedItemPolicy, ReplayOptions,
};
use safeguard_audit_integrity::{locate_tampering, seal_chain, verify_chain};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore};

const BOUND_FIXTURE: &str =
    include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
const CONFIG_FIXTURE: &str =
    include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");
const FROZEN_FIXTURE: &str =
    include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");

/// A fixed, resumable fixture source ordered by ascending ledger (415,
/// 419, 423), mirroring a real source feed.
struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:phase2"
    }
    fn fetch_after(&mut self, after: Option<&str>, limit: usize) -> SourceResult<SourcePage> {
        if limit == 0 || limit > 1000 {
            return Err(safeguard_audit_core::SourceError::LimitOutOfRange(limit));
        }
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

fn clock() -> FixedClock {
    FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500))
}

fn indexer() -> Indexer {
    Indexer::new(
        normalizer(),
        clock(),
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        100,
    )
    .unwrap()
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

fn collect_checkpoints() -> safeguard_audit_indexer::InMemoryCheckpointStore {
    safeguard_audit_indexer::InMemoryCheckpointStore::new()
}

#[test]
fn fixtures_flow_source_to_store_and_back_out_intact() {
    let mut source = FixtureSource { items: fixtures() };
    let mut checkpoints = collect_checkpoints();
    let mut store = MemoryEventStore::new();

    let report = indexer()
        .run_once(&mut source, &mut checkpoints, &mut store)
        .unwrap();
    assert_eq!(report.inserted, 3);
    assert_eq!(store.len(), 3);
    assert_eq!(
        checkpoints
            .load("fixture:phase2")
            .unwrap()
            .unwrap()
            .as_str(),
        "ledger:423"
    );

    // Read back in history order (position key = ledger order).
    let history = fetch_all(&store);
    assert_eq!(history.len(), 3);
    let ledgers: Vec<i64> = history
        .iter()
        .map(|r| r.event.order.ledger_sequence.unwrap())
        .collect();
    assert_eq!(ledgers, vec![415, 419, 423]);

    // Sealing and verifying the persisted history is clean.
    let sealed = seal_chain(&history).unwrap();
    assert!(verify_chain(&sealed).is_ok());
}

#[test]
fn reindexing_the_same_window_is_idempotent() {
    let items = fixtures();
    let mut checkpoints = collect_checkpoints();
    let mut store = MemoryEventStore::new();
    let idx = indexer();

    let mut source1 = FixtureSource {
        items: items.clone(),
    };
    let first = idx
        .run_once(&mut source1, &mut checkpoints, &mut store)
        .unwrap();
    assert_eq!(first.inserted, 3);

    // A second full run against the same store (fresh checkpoint, as if an
    // operator reset it) inserts nothing.
    let mut source2 = FixtureSource { items };
    let mut fresh_checkpoints = collect_checkpoints();
    let second = idx
        .run_once(&mut source2, &mut fresh_checkpoints, &mut store)
        .unwrap();
    assert_eq!(second.fetched, 3);
    assert_eq!(second.inserted, 0);
    assert_eq!(store.len(), 3);
}

#[test]
fn replay_reproduces_identical_records_in_a_scratch_store() {
    let mut checkpoints = collect_checkpoints();
    let mut production = MemoryEventStore::new();
    let mut source = FixtureSource { items: fixtures() };
    indexer()
        .run_once(&mut source, &mut checkpoints, &mut production)
        .unwrap();
    let production_records = fetch_all(&production);

    // Replay the same window into a scratch store from the beginning.
    let mut replay_source = FixtureSource { items: fixtures() };
    let mut scratch = MemoryEventStore::new();
    let report = replay_into(
        &normalizer(),
        &clock(),
        &mut replay_source,
        &mut scratch,
        None,
        ReplayOptions::default(),
    )
    .unwrap();
    assert_eq!(report.inserted, 3);

    // Deterministic record ids: replay reproduces the exact same records.
    let scratch_records = fetch_all(&scratch);
    assert_eq!(production_records.len(), scratch_records.len());
    let production_ids: Vec<String> = production_records
        .iter()
        .map(|r| r.record_id.to_string())
        .collect();
    let scratch_ids: Vec<String> = scratch_records
        .iter()
        .map(|r| r.record_id.to_string())
        .collect();
    assert_eq!(production_ids, scratch_ids);
    // And the production store was untouched by the replay.
    assert_eq!(production.len(), 3);
}

#[test]
fn resume_from_a_checkpoint_continues_without_duplicates() {
    // A page-limited run stops mid-window; a later run resumes from the
    // checkpoint and completes it.
    let items = fixtures();
    let mut checkpoints = collect_checkpoints();
    let mut store = MemoryEventStore::new();
    let partial = Indexer::new(
        normalizer(),
        clock(),
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        1,
    )
    .unwrap();

    let mut source1 = FixtureSource {
        items: items.clone(),
    };
    let r1 = partial
        .run_once(&mut source1, &mut checkpoints, &mut store)
        .unwrap();
    assert_eq!(r1.inserted, 1);
    assert!(r1.has_more);

    let mut source2 = FixtureSource { items };
    let r2 = partial
        .run_once(&mut source2, &mut checkpoints, &mut store)
        .unwrap();
    assert_eq!(r2.inserted, 1);
    assert!(r2.has_more);

    let mut source3 = FixtureSource { items: fixtures() };
    let r3 = partial
        .run_once(&mut source3, &mut checkpoints, &mut store)
        .unwrap();
    assert_eq!(r3.inserted, 1);
    assert!(!r3.has_more);
    assert_eq!(store.len(), 3);
}

#[test]
fn a_tampered_store_record_is_detected_after_sealing_and_verify() {
    let mut checkpoints = collect_checkpoints();
    let mut store = MemoryEventStore::new();
    let mut source = FixtureSource { items: fixtures() };
    indexer()
        .run_once(&mut source, &mut checkpoints, &mut store)
        .unwrap();

    // History is intact as persisted...
    let history = fetch_all(&store);
    let sealed = seal_chain(&history).unwrap();
    assert!(locate_tampering(&sealed).unwrap().is_empty());

    // ...and a tampered copy (bytes edited at the persistence boundary)
    // is caught immediately.
    let mut altered = sealed;
    altered[1].recorded_at = Timestamp::from_unix_seconds(1_700_000_000 + 9);
    let found = locate_tampering(&altered).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].record_id(), &altered[1].record_id);
}
