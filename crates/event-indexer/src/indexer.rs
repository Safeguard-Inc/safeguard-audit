//! The indexer loop: one source, one checkpoint, one store.
//!
//! [`Indexer::run_once`] advances a source by exactly one page:
//!
//! 1. load the checkpoint for the source (or start fresh),
//! 2. fetch the page after the checkpointed position,
//! 3. normalize every item; malformed items abort the run or are
//!    quarantined into the report, depending on policy,
//! 4. verify the page's known placements are strictly increasing,
//! 5. append the records atomically (the store deduplicates by event
//!    identity),
//! 6. checkpoint the last consumed position — only after the store
//!    write succeeded.
//!
//! The ordering of steps 5 and 6 is the whole crash-safety story: a crash
//! before 6 re-serves the page next run and deduplication absorbs it; a
//! checkpoint is never advanced past work that did not durably land.
//!
//! `run_once` is safe to call repeatedly (polling) and safe to restart at
//! any point: resuming from a checkpoint re-fetches exactly the items
//! after the last committed position.

use safeguard_audit_core::{AuditRecord, Clock, EventSource};
use safeguard_audit_normalizer::Normalizer;
use safeguard_audit_storage::{BatchOutcome, EventStore, WriteBatch};

use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::cursor::SourceCursor;
use crate::deduplication::{DedupGuard, DedupPolicy};
use crate::errors::{IndexerError, IndexerResult};
use crate::ordering;

/// How the indexer treats a raw item that fails normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MalformedItemPolicy {
    /// Any malformed item aborts the run before anything from its page is
    /// committed or checkpointed. The default: nothing is silently lost,
    /// and the operator sees the failure with its source position.
    #[default]
    AbortOnMalformed,
    /// Malformed items are skipped and their positions surfaced in the
    /// report; the rest of the page still commits. Use only when a
    /// quarantine-and-review path exists downstream.
    SkipAndReport,
}

/// What one [`Indexer::run_once`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestReport {
    /// Items the source served on this page.
    pub fetched: usize,
    /// Records newly appended to the store.
    pub inserted: usize,
    /// Items already recorded (idempotent dedup).
    pub duplicates: usize,
    /// Items skipped for normalization failures under a skip policy.
    pub quarantined: Vec<String>,
    /// Events whose placement was unknown and therefore not
    /// ordering-verified (an explicit uncertainty count).
    pub unverified_order: usize,
    /// Whether the source reported more items after this page.
    pub has_more: bool,
}

impl IngestReport {
    /// The number of source positions this run consumed.
    pub fn consumed(&self) -> usize {
        self.fetched
    }
}

/// The indexer: configuration plus the run-once loop.
pub struct Indexer {
    normalizer: Normalizer,
    clock: Box<dyn Clock>,
    dedup_policy: DedupPolicy,
    malformed_policy: MalformedItemPolicy,
    page_limit: usize,
}

impl Indexer {
    /// Builds an indexer. `clock` stamps `recorded_at` on new records
    /// (deterministic in tests, wall-clock in production).
    pub fn new(
        normalizer: Normalizer,
        clock: impl Clock + 'static,
        dedup_policy: DedupPolicy,
        malformed_policy: MalformedItemPolicy,
        page_limit: usize,
    ) -> IndexerResult<Self> {
        if page_limit == 0 {
            return Err(IndexerError::Internal(
                "page limit must be positive".to_owned(),
            ));
        }
        Ok(Self {
            normalizer,
            clock: Box::new(clock),
            dedup_policy,
            malformed_policy,
            page_limit,
        })
    }

    /// The configured dedup policy.
    pub fn dedup_policy(&self) -> DedupPolicy {
        self.dedup_policy
    }

    /// The configured malformed-item policy.
    pub fn malformed_policy(&self) -> MalformedItemPolicy {
        self.malformed_policy
    }

    /// Advances `source` by one page, appending records to `store` and
    /// persisting the checkpoint only after the write succeeded.
    pub fn run_once<S, P, E>(
        &self,
        source: &mut S,
        checkpoints: &mut P,
        store: &mut E,
    ) -> IndexerResult<IngestReport>
    where
        S: EventSource,
        P: CheckpointStore,
        E: EventStore,
    {
        // 1. Resume from the checkpointed position, if any.
        let resumed = checkpoints.load(source.source_name())?;
        let after = resumed.as_ref().map(|c| c.as_str());

        // 2. Fetch one page. Source errors propagate: never checkpoint
        //    past a page we could not read.
        let page = source
            .fetch_after(after, self.page_limit)
            .map_err(|e| IndexerError::Source(e.to_string()))?;
        let mut report = IngestReport {
            fetched: page.items().len(),
            inserted: 0,
            duplicates: 0,
            quarantined: Vec::new(),
            unverified_order: 0,
            has_more: page.has_more(),
        };

        // 3. Normalize each item. Under the abort policy, any failure
        //    stops the run before anything commits.
        let mut guard = DedupGuard::new();
        let mut records = Vec::new();
        let mut placements = Vec::new();
        for item in page.items() {
            match self.normalizer.normalize(item) {
                Ok(normalized) => {
                    let event_id = normalized.event.event_id.clone();
                    let placement = normalized.event.order;
                    // Within this run the guard already recorded the event
                    // (the store deduplicates across runs).
                    if guard.contains(&event_id) {
                        report.duplicates += 1;
                    } else {
                        let record = AuditRecord::from_event(normalized.event, self.clock.as_ref())
                            .map_err(|e| IndexerError::Internal(e.to_string()))?;
                        guard.note(event_id);
                        records.push(record);
                    }
                    if placement.ledger_sequence.is_some() {
                        placements.push(placement);
                    } else {
                        report.unverified_order += 1;
                    }
                }
                Err(e) => match self.malformed_policy {
                    MalformedItemPolicy::AbortOnMalformed => {
                        return Err(IndexerError::Normalize(e));
                    }
                    MalformedItemPolicy::SkipAndReport => {
                        report.quarantined.push(item.position().to_owned());
                    }
                },
            }
        }

        // 4. Known placements in one page must be strictly increasing; a
        //    misbehaving source must not scramble history.
        if !ordering::is_strictly_increasing(&placements) {
            return Err(IndexerError::Ordering(
                "page events are not in strictly increasing ledger order".to_owned(),
            ));
        }

        // 5. Append atomically. The store reports duplicates by event
        //    identity; the policy decides whether they are acceptable.
        if !records.is_empty() {
            let batch =
                WriteBatch::new(records).map_err(|e| IndexerError::Internal(e.to_string()))?;
            let outcome: BatchOutcome = store.insert_batch(batch)?;
            report.inserted = outcome.inserted;
            report.duplicates += outcome.duplicates;
            if self.dedup_policy == DedupPolicy::FailOnDuplicate && outcome.duplicates > 0 {
                return Err(IndexerError::Checkpoint(format!(
                    "duplicate events under FailOnDuplicate policy: {}",
                    outcome.duplicates
                )));
            }
        }

        // 6. Checkpoint the last consumed position — only now, after the
        //    store write durably landed.
        if let Some(last) = page.items().last() {
            let position = SourceCursor::new(last.position())
                .map_err(|e| IndexerError::Checkpoint(e.to_string()))?;
            checkpoints.save(&Checkpoint::at(source.source_name(), position)?)?;
        }

        Ok(report)
    }
}

/// Asserts a report summary is coherent (test helper + report docs).
impl std::fmt::Display for IngestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fetched {}, inserted {}, duplicate {}, quarantined {}, unverified-order {}",
            self.fetched,
            self.inserted,
            self.duplicates,
            self.quarantined.len(),
            self.unverified_order
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::InMemoryCheckpointStore;
    use safeguard_audit_core::{FixedClock, NetworkId, Timestamp, VersionLabel};
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_normalizer::NormalizeConfig;

    const FROZEN_FIXTURE: &str =
        include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");
    const BOUND_FIXTURE: &str =
        include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
    const CONFIG_FIXTURE: &str =
        include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");

    fn normalizer() -> Normalizer {
        Normalizer::new(NormalizeConfig::new(
            NetworkId::new(NetworkId::TESTNET).unwrap(),
            "safeguard-hooks",
            VersionLabel::new("1.0.0").unwrap(),
        ))
    }

    fn indexer(policy: DedupPolicy) -> Indexer {
        Indexer::new(
            normalizer(),
            FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
            policy,
            MalformedItemPolicy::AbortOnMalformed,
            100,
        )
        .unwrap()
    }

    fn item(payload: &str, position: &str) -> safeguard_audit_core::RawEventItem {
        safeguard_audit_core::RawEventItem::new("hooks-state-event", payload, position).unwrap()
    }

    /// A source replaying a fixed list of items, resumable by position.
    struct VecSource {
        items: Vec<safeguard_audit_core::RawEventItem>,
    }

    impl EventSource for VecSource {
        type Error = safeguard_audit_core::SourceError;
        fn source_name(&self) -> &str {
            "test-vec"
        }
        fn fetch_after(
            &mut self,
            after: Option<&str>,
            limit: usize,
        ) -> safeguard_audit_core::SourceResult<safeguard_audit_core::SourcePage> {
            use safeguard_audit_core::SourcePage;
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

    #[test]
    fn first_run_indexes_the_whole_source() {
        let source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "ledger:415"),
                item(FROZEN_FIXTURE, "ledger:423"),
            ],
        };
        let mut source = source;
        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let report = indexer(DedupPolicy::SkipDuplicates)
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(report.fetched, 2);
        assert_eq!(report.inserted, 2);
        assert_eq!(store.len(), 2);
        // The checkpoint advanced past the whole window (last item).
        assert_eq!(
            checkpoints.load("test-vec").unwrap().unwrap().as_str(),
            "ledger:423"
        );
    }

    #[test]
    fn second_run_is_idempotent() {
        let source = VecSource {
            items: vec![item(FROZEN_FIXTURE, "ledger:423")],
        };
        let mut source = source;
        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let idx = indexer(DedupPolicy::SkipDuplicates);
        let first = idx
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(first.inserted, 1);
        let second = idx
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(second.fetched, 0);
        assert_eq!(second.inserted, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn restart_resumes_from_the_checkpoint() {
        // Simulate a crash: the store is discarded but the checkpoint
        // survives, and the source re-serves from the beginning (as a real
        // source would after a restart with no durable cursor of its own).
        let items = vec![item(BOUND_FIXTURE, "pos:1"), item(FROZEN_FIXTURE, "pos:2")];
        let mut checkpoints = InMemoryCheckpointStore::new();

        let mut store1 = MemoryEventStore::new();
        let idx = indexer(DedupPolicy::SkipDuplicates);
        let mut source1 = VecSource {
            items: items.clone(),
        };
        let r1 = idx
            .run_once(&mut source1, &mut checkpoints, &mut store1)
            .unwrap();
        assert_eq!(r1.inserted, 2);

        // "Crash": fresh store. The checkpoint says pos:2 was consumed, so
        // re-fetching from the beginning must not re-record anything.
        let mut store2 = MemoryEventStore::new();
        let mut source2 = VecSource { items };
        let r2 = idx
            .run_once(&mut source2, &mut checkpoints, &mut store2)
            .unwrap();
        assert_eq!(r2.fetched, 0);
        assert_eq!(r2.inserted, 0);
        assert_eq!(store2.len(), 0);
    }

    #[test]
    fn deduplication_absorbs_reingested_windows() {
        // A fresh checkpoint over an already-populated store: every item
        // normalizes to an already-recorded event and is skipped.
        let items = vec![item(FROZEN_FIXTURE, "pos:1")];
        let mut store = MemoryEventStore::new();
        let idx = indexer(DedupPolicy::SkipDuplicates);
        let mut checkpoints1 = InMemoryCheckpointStore::new();
        let mut source1 = VecSource {
            items: items.clone(),
        };
        idx.run_once(&mut source1, &mut checkpoints1, &mut store)
            .unwrap();

        // Re-run with an empty checkpoint (e.g. operator reset): the item
        // is fetched again but the store already has its event.
        let mut checkpoints2 = InMemoryCheckpointStore::new();
        let mut source2 = VecSource { items };
        let report = idx
            .run_once(&mut source2, &mut checkpoints2, &mut store)
            .unwrap();
        assert_eq!(report.fetched, 1);
        assert_eq!(report.duplicates, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn fail_on_duplicate_stops_on_conflict() {
        let items = vec![item(FROZEN_FIXTURE, "pos:1")];
        let mut store = MemoryEventStore::new();
        let idx_skip = indexer(DedupPolicy::SkipDuplicates);
        let mut c1 = InMemoryCheckpointStore::new();
        let mut s1 = VecSource {
            items: items.clone(),
        };
        idx_skip.run_once(&mut s1, &mut c1, &mut store).unwrap();

        let idx_strict = indexer(DedupPolicy::FailOnDuplicate);
        let mut c2 = InMemoryCheckpointStore::new();
        let mut s2 = VecSource { items };
        assert!(idx_strict.run_once(&mut s2, &mut c2, &mut store).is_err());
    }

    #[test]
    fn malformed_items_abort_before_any_write() {
        let bad = item("{ nope", "pos:bad");
        let mut source = VecSource {
            items: vec![item(FROZEN_FIXTURE, "pos:1"), bad],
        };
        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let err = indexer(DedupPolicy::SkipDuplicates)
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap_err();
        assert!(matches!(err, IndexerError::Normalize(_)));
        // Nothing from the poisoned page committed or checkpointed.
        assert_eq!(store.len(), 0);
        assert!(checkpoints.load("test-vec").unwrap().is_none());
    }

    #[test]
    fn skip_and_report_quarantines_malformed_positions() {
        let bad = item("{ nope", "pos:bad");
        let mut source = VecSource {
            items: vec![item(FROZEN_FIXTURE, "pos:1"), bad],
        };
        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let idx = Indexer::new(
            normalizer(),
            FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
            DedupPolicy::SkipDuplicates,
            MalformedItemPolicy::SkipAndReport,
            100,
        )
        .unwrap();
        let report = idx
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(report.inserted, 1);
        assert_eq!(report.quarantined, vec!["pos:bad".to_owned()]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn out_of_order_pages_are_rejected_before_commit() {
        // BOUND is ledger 415, FROZEN is ledger 423: serving frozen first
        // violates strictly-increasing page order.
        let mut source = VecSource {
            items: vec![item(FROZEN_FIXTURE, "pos:2"), item(BOUND_FIXTURE, "pos:1")],
        };
        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let err = indexer(DedupPolicy::SkipDuplicates)
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap_err();
        assert!(matches!(err, IndexerError::Ordering(_)));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn page_limits_resume_across_runs() {
        let items = vec![
            item(BOUND_FIXTURE, "pos:1"),
            item(CONFIG_FIXTURE, "pos:2"),
            item(FROZEN_FIXTURE, "pos:3"),
        ];
        let idx = Indexer::new(
            normalizer(),
            FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
            DedupPolicy::SkipDuplicates,
            MalformedItemPolicy::AbortOnMalformed,
            2, // two items per page
        )
        .unwrap();

        let mut checkpoints = InMemoryCheckpointStore::new();
        let mut store = MemoryEventStore::new();
        let mut source = VecSource { items };

        let r1 = idx
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(r1.fetched, 2);
        assert_eq!(r1.inserted, 2);
        assert!(r1.has_more);
        assert_eq!(store.len(), 2);

        let r2 = idx
            .run_once(&mut source, &mut checkpoints, &mut store)
            .unwrap();
        assert_eq!(r2.fetched, 1);
        assert_eq!(r2.inserted, 1);
        assert!(!r2.has_more);
        assert_eq!(store.len(), 3);
    }
}
