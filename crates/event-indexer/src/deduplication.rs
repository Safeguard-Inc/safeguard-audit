//! Deduplication: the rules that make ingestion idempotent.
//!
//! The audit rule is "an event is recorded at most once", and the dedup
//! key is the deterministic event identity derived during normalization —
//! never arrival time, never a source position (a position can legitimately
//! be re-served after a restart). The store is the source of truth: its
//! idempotent insert reports [`InsertOutcome::Duplicate`] for events that
//! are already recorded, so a re-run of the indexer over the same source
//! window converges instead of duplicating history.
//!
//! This module supplies the *policy* around that contract:
//!
//! * [`DedupPolicy`] — what a duplicate means to this indexer run
//!   (skip silently and continue, which is the normal resume/backfill
//!   behavior, or fail loudly when a caller expects a strictly fresh
//!   window);
//! * [`DedupGuard`] — a per-run set of event ids already recorded, so a
//!   single long run does not keep asking the store about events it just
//!   appended.
//!
//! [`InsertOutcome`]: safeguard_audit_storage::InsertOutcome

use std::collections::HashSet;

use safeguard_audit_core::EventId;
use safeguard_audit_storage::InsertOutcome;

/// How the indexer treats an event that turns out to be already recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DedupPolicy {
    /// Duplicates are expected (resume, re-run, backfill); skip them and
    /// keep going. The default.
    #[default]
    SkipDuplicates,
    /// Any duplicate is a bug worth stopping for (a strictly fresh
    /// window that unexpectedly overlaps existing history).
    FailOnDuplicate,
}

/// Classifies an insert outcome under a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupResult {
    /// The record was newly appended.
    New,
    /// The record was already present and the policy accepted that.
    Skipped,
    /// The record was already present and the policy rejects duplicates.
    Conflict,
}

/// Interprets a store outcome under `policy`.
pub fn classify(outcome: InsertOutcome, policy: DedupPolicy) -> DedupResult {
    match (outcome, policy) {
        (InsertOutcome::Inserted, _) => DedupResult::New,
        (InsertOutcome::Duplicate, DedupPolicy::SkipDuplicates) => DedupResult::Skipped,
        (InsertOutcome::Duplicate, DedupPolicy::FailOnDuplicate) => DedupResult::Conflict,
    }
}

/// A per-run record of event ids already appended.
///
/// The store remains the durable source of truth across runs; this guard
/// only avoids redundant store round-trips *within* one run and gives the
/// indexer an early, cheap duplicate signal for events that appear twice
/// in a single page batch.
#[derive(Debug, Default)]
pub struct DedupGuard {
    seen: HashSet<EventId>,
}

impl DedupGuard {
    /// An empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this run has already recorded the event id.
    pub fn contains(&self, event_id: &EventId) -> bool {
        self.seen.contains(event_id)
    }

    /// Records an event id as seen in this run.
    pub fn note(&mut self, event_id: EventId) {
        self.seen.insert(event_id);
    }

    /// How many distinct event ids this run has seen.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the guard is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_interprets_store_outcomes_under_policy() {
        assert_eq!(
            classify(InsertOutcome::Inserted, DedupPolicy::SkipDuplicates),
            DedupResult::New
        );
        assert_eq!(
            classify(InsertOutcome::Duplicate, DedupPolicy::SkipDuplicates),
            DedupResult::Skipped
        );
        assert_eq!(
            classify(InsertOutcome::Duplicate, DedupPolicy::FailOnDuplicate),
            DedupResult::Conflict
        );
        assert_eq!(
            classify(InsertOutcome::Inserted, DedupPolicy::FailOnDuplicate),
            DedupResult::New
        );
    }

    #[test]
    fn guard_tracks_seen_events_within_a_run() {
        let mut guard = DedupGuard::new();
        let a = EventId::derive(&["testnet", "tx-1", "op:0", "account-frozen"]);
        let b = EventId::derive(&["testnet", "tx-2", "op:0", "token-bound"]);
        assert!(!guard.contains(&a));
        guard.note(a.clone());
        assert!(guard.contains(&a));
        assert!(!guard.contains(&b));
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn default_policy_skips_duplicates() {
        assert_eq!(DedupPolicy::default(), DedupPolicy::SkipDuplicates);
    }
}
