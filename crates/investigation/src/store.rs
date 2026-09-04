//! The [`CaseStore`] contract and its in-memory implementation.
//!
//! Cases are *mutable current state* — findings accumulate, statuses
//! change, a closed case is reopened — so they cannot live in the
//! append-only audit [`EventStore`]. The case store is where the current
//! state of every case lives; the audit store keeps the lifecycle history.
//! Like the [`EventStore`] trait, this contract never names a database: an
//! in-memory implementation ships for tests and single-node development,
//! and a durable adapter can be added without touching the service.

use std::collections::BTreeMap;

use safeguard_audit_core::{AuditorId, CaseId, CaseStatus, InvestigationCase};

use crate::errors::{InvestigationError, InvestigationResult};

/// What one insert or update call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseWrite {
    /// A new case was created.
    Created,
    /// An existing case was updated.
    Updated,
}

/// The case-store contract.
///
/// All mutating methods take `&mut self`, matching the audit store's
/// single-writer convention. Query methods return stable, deterministic
/// ordering (by case id unless a query says otherwise).
pub trait CaseStore {
    /// Persists a new case. Returns an error if the case id exists.
    fn create(&mut self, case: InvestigationCase) -> InvestigationResult<()>;

    /// Replaces the state of an existing case. Returns an error if the
    /// case does not exist (creating through `create` keeps idempotent
    /// open semantics explicit).
    fn update(&mut self, case: InvestigationCase) -> InvestigationResult<()>;

    /// Fetches a case by id.
    fn get(&self, case_id: &CaseId) -> InvestigationResult<InvestigationCase>;

    /// Whether a case id exists.
    fn contains(&self, case_id: &CaseId) -> bool;

    /// All cases, ordered by case id.
    fn all(&self) -> Vec<InvestigationCase>;

    /// Cases with the given status.
    fn by_status(&self, status: CaseStatus) -> Vec<InvestigationCase>;

    /// Cases assigned to an auditor.
    fn by_assignee(&self, auditor: &AuditorId) -> Vec<InvestigationCase>;

    /// The number of cases stored.
    fn len(&self) -> usize;

    /// Whether no cases are stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The in-memory case store — for tests, fixtures, and single-node
/// development. State is not durable: a restart loses cases.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCaseStore {
    cases: BTreeMap<CaseId, InvestigationCase>,
}

impl InMemoryCaseStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CaseStore for InMemoryCaseStore {
    fn create(&mut self, case: InvestigationCase) -> InvestigationResult<()> {
        let id = case.case_id().clone();
        if self.cases.contains_key(&id) {
            return Err(InvestigationError::CaseAlreadyExists(id.as_str().to_owned()));
        }
        self.cases.insert(id, case);
        Ok(())
    }

    fn update(&mut self, case: InvestigationCase) -> InvestigationResult<()> {
        let id = case.case_id().clone();
        if !self.cases.contains_key(&id) {
            return Err(InvestigationError::CaseNotFound(id.as_str().to_owned()));
        }
        self.cases.insert(id, case);
        Ok(())
    }

    fn get(&self, case_id: &CaseId) -> InvestigationResult<InvestigationCase> {
        self.cases
            .get(case_id)
            .cloned()
            .ok_or_else(|| InvestigationError::CaseNotFound(case_id.as_str().to_owned()))
    }

    fn contains(&self, case_id: &CaseId) -> bool {
        self.cases.contains_key(case_id)
    }

    fn all(&self) -> Vec<InvestigationCase> {
        self.cases.values().cloned().collect()
    }

    fn by_status(&self, status: CaseStatus) -> Vec<InvestigationCase> {
        self.cases
            .values()
            .filter(|c| c.status() == status)
            .cloned()
            .collect()
    }

    fn by_assignee(&self, auditor: &AuditorId) -> Vec<InvestigationCase> {
        self.cases
            .values()
            .filter(|c| c.assigned_to() == Some(auditor))
            .cloned()
            .collect()
    }

    fn len(&self) -> usize {
        self.cases.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{CaseId, Priority, Timestamp};

    fn auditor(id: &str) -> AuditorId {
        AuditorId::derive(&[id])
    }

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_seconds(secs)
    }

    fn case(id: &str, status: CaseStatus) -> InvestigationCase {
        let mut c = InvestigationCase::open(
            CaseId::derive(&[id]),
            "review",
            Priority::Medium,
            at(100),
            auditor("a1"),
        )
        .unwrap();
        if status != CaseStatus::Open {
            let path: &[(CaseStatus, CaseStatus)] = match status {
                CaseStatus::Investigating => &[(CaseStatus::Open, CaseStatus::Investigating)],
                CaseStatus::Escalated => &[
                    (CaseStatus::Open, CaseStatus::Investigating),
                    (CaseStatus::Investigating, CaseStatus::Escalated),
                ],
                CaseStatus::Resolved => &[
                    (CaseStatus::Open, CaseStatus::Investigating),
                    (CaseStatus::Investigating, CaseStatus::Resolved),
                ],
                CaseStatus::Closed => &[
                    (CaseStatus::Open, CaseStatus::Investigating),
                    (CaseStatus::Investigating, CaseStatus::Resolved),
                    (CaseStatus::Resolved, CaseStatus::Closed),
                ],
                CaseStatus::Open => &[],
            };
            for (from, to) in path {
                debug_assert_eq!(c.status(), *from);
                c.change_status(*to, at(110), auditor("a1"), None).unwrap();
            }
        }
        c
    }

    #[test]
    fn create_then_get_round_trips() {
        let mut store = InMemoryCaseStore::new();
        let c = case("c1", CaseStatus::Open);
        store.create(c.clone()).unwrap();
        assert_eq!(store.get(c.case_id()).unwrap(), c);
        assert!(store.contains(c.case_id()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn duplicate_creates_are_rejected_and_updates_require_existence() {
        let mut store = InMemoryCaseStore::new();
        let c = case("c1", CaseStatus::Open);
        store.create(c.clone()).unwrap();
        assert!(store.create(c.clone()).is_err());
        assert!(store.update(case("ghost", CaseStatus::Open)).is_err());

        let mut moved = c.clone();
        moved.change_status(
            CaseStatus::Investigating,
            at(200),
            auditor("a2"),
            None,
        )
        .unwrap();
        store.update(moved.clone()).unwrap();
        assert_eq!(store.get(c.case_id()).unwrap().status(), CaseStatus::Investigating);
    }

    #[test]
    fn status_and_assignee_queries_are_deterministic() {
        let mut store = InMemoryCaseStore::new();
        let mut assigned = case("c1", CaseStatus::Investigating);
        assigned.assign(auditor("inv"), at(120)).unwrap();
        store.create(assigned).unwrap();
        store.create(case("c2", CaseStatus::Open)).unwrap();
        store.create(case("c3", CaseStatus::Closed)).unwrap();

        assert_eq!(store.len(), 3);
        assert_eq!(store.by_status(CaseStatus::Open).len(), 1);
        assert_eq!(store.by_status(CaseStatus::Closed).len(), 1);
        assert_eq!(store.by_assignee(&auditor("inv")).len(), 1);
        assert_eq!(store.by_assignee(&auditor("nobody")).len(), 0);
        // all() is ordered by case id.
        let ids: Vec<String> = store
            .all()
            .iter()
            .map(|c| c.case_id().as_str().to_owned())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}