//! Bounded replay: reconstruct history without touching production.
//!
//! Replay answers "what would ingestion have recorded over this source
//! window?" — used to rebuild a lost store, to verify that a historical
//! window reproduces identically, or to seed a second environment. Its
//! guarantees mirror the indexer's own (same normalization, same
//! deterministic record ids, same deduplication) with two deliberate
//! differences:
//!
//! * replay writes only into the store the caller provides — the caller
//!   decides whether that is a fresh scratch store or a real one, and a
//!   production store is never touched implicitly;
//! * replay uses its own private checkpoint, so it can start anywhere in
//!   the source and never interferes with the live indexer's checkpoint.
//!
//! Bounds stop the replay after a page or record budget so an unbounded
//! feed cannot run away; hitting a budget reports `truncated`, never a
//! partial-looking success.

use safeguard_audit_core::{Clock, EventSource};
use safeguard_audit_normalizer::Normalizer;
use safeguard_audit_storage::EventStore;

use crate::checkpoint::{CheckpointStore as _, InMemoryCheckpointStore};
use crate::cursor::SourceCursor;
use crate::errors::IndexerResult;
use crate::indexer::{Indexer, IngestReport, MalformedItemPolicy};

/// Budgets that bound one replay run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayOptions {
    /// Maximum pages to fetch before stopping (`None` = unbounded).
    pub max_pages: Option<usize>,
    /// Maximum newly inserted records before stopping (`None` =
    /// unbounded). Bounds are enforced at page granularity: a page is
    /// committed whole, so the count can overshoot by less than one page.
    pub max_records: Option<usize>,
    /// Items fetched per page (controls budget granularity).
    pub page_limit: usize,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            max_pages: None,
            max_records: None,
            page_limit: 1000,
        }
    }
}

/// What one replay run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Pages fetched.
    pub pages: usize,
    /// Records inserted into the target store.
    pub inserted: usize,
    /// Events already present in the target store.
    pub duplicates: usize,
    /// Whether a budget stopped the replay before the source was drained.
    pub truncated: bool,
    /// The last source position consumed, when any.
    pub last_position: Option<String>,
}

impl ReplayReport {
    /// Summarizes the report.
    pub fn describe(&self) -> String {
        format!(
            "pages {}, inserted {}, duplicate {}, truncated {}",
            self.pages, self.inserted, self.duplicates, self.truncated
        )
    }
}

/// Replays `source` into `target` starting at `start_from`.
///
/// `normalizer` must be pinned to the same (network, source, parser)
/// configuration the live indexer uses, so replay reproduces the exact
/// same records.
pub fn replay_into<S, E>(
    normalizer: &Normalizer,
    clock: &dyn Clock,
    source: &mut S,
    target: &mut E,
    start_from: Option<SourceCursor>,
    options: ReplayOptions,
) -> IndexerResult<ReplayReport>
where
    S: EventSource,
    E: EventStore,
{
    // A private checkpoint: seed it with the requested start position so
    // the first fetch resumes exactly there.
    let mut checkpoints = InMemoryCheckpointStore::new();
    if let Some(start) = &start_from {
        let cp = crate::checkpoint::Checkpoint::at(source.source_name(), start.clone())?;
        checkpoints.save(&cp)?;
    }

    let indexer = Indexer::new(
        normalizer.clone(),
        // Replay stamps recorded_at with the caller's clock (typically a
        // fixed clock) so repeated replays are byte-identical.
        replay_clock(clock),
        crate::deduplication::DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        options.page_limit,
    )?;

    let mut report = ReplayReport {
        pages: 0,
        inserted: 0,
        duplicates: 0,
        truncated: false,
        last_position: start_from.as_ref().map(|c| c.as_str().to_owned()),
    };
    loop {
        // A zero-page budget means nothing to do at all.
        if let Some(max) = options.max_pages {
            if report.pages >= max {
                report.truncated = true;
                break;
            }
        }

        let page_report: IngestReport = indexer.run_once(source, &mut checkpoints, target)?;
        report.pages += 1;
        report.inserted += page_report.inserted;
        report.duplicates += page_report.duplicates;
        report.last_position = checkpoints
            .load(source.source_name())?
            .map(|c| c.as_str().to_owned());

        // A fully drained source is a complete replay, never truncated.
        if !page_report.has_more {
            break;
        }
        // Otherwise, honor the budgets: stopping while more exist means
        // the replay was truncated by design.
        let pages_exhausted = options.max_pages.is_some_and(|max| report.pages >= max);
        let records_exhausted = options
            .max_records
            .is_some_and(|max| report.inserted >= max);
        if pages_exhausted || records_exhausted {
            report.truncated = true;
            break;
        }
    }

    Ok(report)
}

/// A clock that clones a fixed instant for replay determinism.
fn replay_clock(clock: &dyn Clock) -> FixedReplayClock {
    FixedReplayClock {
        instant: clock.now(),
    }
}

/// A clock pinned to the instant captured at replay start.
#[derive(Debug, Clone, Copy)]
struct FixedReplayClock {
    instant: safeguard_audit_core::Timestamp,
}

impl Clock for FixedReplayClock {
    fn now(&self) -> safeguard_audit_core::Timestamp {
        self.instant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::PageRequest;
    use safeguard_audit_core::{FixedClock, NetworkId, RawEventItem, Timestamp, VersionLabel};
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_normalizer::NormalizeConfig;
    use safeguard_audit_storage::AuditQuery;

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

    fn clock() -> FixedClock {
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500))
    }

    fn item(payload: &str, position: &str) -> RawEventItem {
        RawEventItem::new("hooks-state-event", payload, position).unwrap()
    }

    struct VecSource {
        items: Vec<RawEventItem>,
    }

    impl EventSource for VecSource {
        type Error = safeguard_audit_core::SourceError;
        fn source_name(&self) -> &str {
            "fixture-window"
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

    fn all_records(store: &MemoryEventStore) -> Vec<String> {
        let page = store
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(1000).unwrap(),
            )
            .unwrap();
        page.items()
            .iter()
            .map(|r| r.record_id.as_str().to_owned())
            .collect()
    }

    #[test]
    fn replay_reconstructs_the_full_window() {
        let mut source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "pos:1"),
                item(CONFIG_FIXTURE, "pos:2"),
                item(FROZEN_FIXTURE, "pos:3"),
            ],
        };
        let mut target = MemoryEventStore::new();
        let report = replay_into(
            &normalizer(),
            &clock(),
            &mut source,
            &mut target,
            None,
            ReplayOptions::default(),
        )
        .unwrap();
        assert_eq!(report.pages, 1);
        assert_eq!(report.inserted, 3);
        assert!(!report.truncated);
        assert_eq!(report.last_position.as_deref(), Some("pos:3"));
        assert_eq!(target.len(), 3);
    }

    #[test]
    fn replay_is_deterministic() {
        let replay = || {
            let mut source = VecSource {
                items: vec![
                    item(BOUND_FIXTURE, "pos:1"),
                    item(CONFIG_FIXTURE, "pos:2"),
                    item(FROZEN_FIXTURE, "pos:3"),
                ],
            };
            let mut target = MemoryEventStore::new();
            replay_into(
                &normalizer(),
                &clock(),
                &mut source,
                &mut target,
                None,
                ReplayOptions::default(),
            )
            .unwrap();
            all_records(&target)
        };
        assert_eq!(replay(), replay());
    }

    #[test]
    fn replay_can_start_from_a_position() {
        let mut source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "pos:1"),
                item(CONFIG_FIXTURE, "pos:2"),
                item(FROZEN_FIXTURE, "pos:3"),
            ],
        };
        let mut target = MemoryEventStore::new();
        let report = replay_into(
            &normalizer(),
            &clock(),
            &mut source,
            &mut target,
            Some(SourceCursor::new("pos:2").unwrap()),
            ReplayOptions::default(),
        )
        .unwrap();
        assert_eq!(report.inserted, 1);
        assert_eq!(target.len(), 1);
    }

    #[test]
    fn record_budget_truncates_the_replay() {
        let mut source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "pos:1"),
                item(CONFIG_FIXTURE, "pos:2"),
                item(FROZEN_FIXTURE, "pos:3"),
            ],
        };
        let mut target = MemoryEventStore::new();
        let report = replay_into(
            &normalizer(),
            &clock(),
            &mut source,
            &mut target,
            None,
            ReplayOptions {
                max_pages: None,
                max_records: Some(2),
                page_limit: 1,
            },
        )
        .unwrap();
        assert!(report.truncated);
        assert_eq!(report.inserted, 2);
        assert_eq!(target.len(), 2);
    }

    #[test]
    fn page_budget_truncates_the_replay() {
        let mut source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "pos:1"),
                item(CONFIG_FIXTURE, "pos:2"),
                item(FROZEN_FIXTURE, "pos:3"),
            ],
        };
        let mut target = MemoryEventStore::new();
        let report = replay_into(
            &normalizer(),
            &clock(),
            &mut source,
            &mut target,
            None,
            ReplayOptions {
                max_pages: Some(2),
                max_records: None,
                page_limit: 1,
            },
        )
        .unwrap();
        assert!(report.truncated);
        assert_eq!(report.pages, 2);
        assert_eq!(report.inserted, 2);
        assert_eq!(target.len(), 2);
    }

    #[test]
    fn draining_the_source_is_never_truncated() {
        let mut source = VecSource {
            items: vec![
                item(BOUND_FIXTURE, "pos:1"),
                item(CONFIG_FIXTURE, "pos:2"),
                item(FROZEN_FIXTURE, "pos:3"),
            ],
        };
        let mut target = MemoryEventStore::new();
        let report = replay_into(
            &normalizer(),
            &clock(),
            &mut source,
            &mut target,
            None,
            ReplayOptions {
                max_pages: Some(10),
                max_records: Some(10),
                page_limit: 2,
            },
        )
        .unwrap();
        assert!(!report.truncated);
        assert_eq!(report.inserted, 3);
    }

    #[test]
    fn replay_never_touches_a_production_store_implicitly() {
        // The production store stays untouched because replay only writes
        // through the store reference it is given.
        let mut source = VecSource {
            items: vec![item(FROZEN_FIXTURE, "pos:1")],
        };
        let mut production = MemoryEventStore::new();
        // Index something into production first.
        let mut checkpoints = InMemoryCheckpointStore::new();
        Indexer::new(
            normalizer(),
            clock(),
            crate::deduplication::DedupPolicy::SkipDuplicates,
            MalformedItemPolicy::AbortOnMalformed,
            100,
        )
        .unwrap()
        .run_once(&mut source, &mut checkpoints, &mut production)
        .unwrap();
        assert_eq!(production.len(), 1);

        // A replay into a scratch store must not change production.
        let mut source2 = VecSource {
            items: vec![item(FROZEN_FIXTURE, "pos:1")],
        };
        let mut scratch = MemoryEventStore::new();
        replay_into(
            &normalizer(),
            &clock(),
            &mut source2,
            &mut scratch,
            None,
            ReplayOptions::default(),
        )
        .unwrap();
        assert_eq!(scratch.len(), 1);
        assert_eq!(production.len(), 1);
    }
}
