//! The case service: the workflow facade over the case store.
//!
//! The core models define *what a case is*; the case store holds *current
//! state*; this service runs the *workflow*. Every method on
//! [`CaseService`]:
//!
//! 1. authorizes the acting auditor for the operation,
//! 2. reads/mutates the case through the [`CaseStore`], letting the core
//!    model validate transitions and timeline entries,
//! 3. records the lifecycle step into the audit [`EventStore`] so history
//!    and current state never drift.
//!
//! ## Authorization
//!
//! The service holds an [`Authorizer`] and treats a clean denial as a
//! [`InvestigationError::NotAuthorized`] outcome — never a panic and
//! never a silent pass. Opening a case requires the `CreateInvestigation`
//! action at the service's network scope. Mutating a case the actor
//! works (assignments, transitions, findings, notes, closure) follows in
//! later stages of this module.

use safeguard_audit_authorization::{reason, Authorizer};
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditorId, CaseId, CaseStatus, Clock, InvestigationCase, NetworkId,
    Priority, Timestamp, VersionLabel,
};
use safeguard_audit_storage::EventStore;

use crate::errors::{InvestigationError, InvestigationResult};
use crate::events::{record_step, LifecycleStep};
use crate::store::CaseStore;

/// Configuration and authorizer for the case workflow.
pub struct CaseService {
    network: NetworkId,
    source: String,
    parser: VersionLabel,
    clock: Box<dyn Clock>,
    authorizer: Authorizer,
}

impl CaseService {
    /// Builds the service for `network`, stamping records with `clock`
    /// (deterministic in tests) and gating operations with `authorizer`.
    pub fn new(
        network: NetworkId,
        source: impl Into<String>,
        parser: VersionLabel,
        clock: impl Clock + 'static,
        authorizer: Authorizer,
    ) -> Self {
        Self {
            network,
            source: source.into(),
            parser,
            clock: Box::new(clock),
            authorizer,
        }
    }

    /// The network this service operates on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Fetches a case from the store.
    pub fn get_case(
        &self,
        cases: &dyn CaseStore,
        case_id: &CaseId,
    ) -> InvestigationResult<InvestigationCase> {
        cases.get(case_id)
    }

    /// Opens a new case.
    ///
    /// The case id is derived deterministically from the network and a
    /// caller-supplied stable case key (typically the identifier of the
    /// operation being investigated), so re-opening the same investigation
    /// after a crash derives the same id — and the store rejects an
    /// accidental duplicate. The opening step is recorded in the audit
    /// store as an `investigation-opened` event.
    pub fn open_case(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        title: &str,
        priority: Priority,
        case_key: &str,
    ) -> InvestigationResult<InvestigationCase> {
        self.require(
            actor,
            AccessAction::CreateInvestigation,
            "open an investigation case",
        )?;

        let case_id = CaseId::derive(&[self.network.as_str(), case_key]);
        let now = Timestamp::now(self.clock.as_ref());

        let case = InvestigationCase::open(case_id.clone(), title, priority, now, actor.clone())
            .map_err(|e| InvestigationError::InvalidContent(e.to_string()))?;

        cases.create(case.clone())?;

        record_step(
            &LifecycleStep {
                network: self.network.clone(),
                case: case_id.as_str().to_owned(),
                actor: actor.as_str().to_owned(),
                status: CaseStatus::Open,
                summary: Some(title.to_owned()),
            },
            &self.source,
            self.parser.clone(),
            self.clock.as_ref(),
            audit,
        )?;

        Ok(case)
    }

    /// Authorizes `actor` for `action` at this service's network scope.
    fn require(
        &self,
        actor: &AuditorId,
        action: AccessAction,
        what: &str,
    ) -> InvestigationResult<()> {
        let scope = AccessScope::Network(self.network.clone());
        let decision = self
            .authorizer
            .authorize(actor, action, &scope)
            .map_err(|e| InvestigationError::Internal(format!("authorizer failure: {e}")))?;
        if decision.allowed() {
            Ok(())
        } else {
            let why = decision.reason().unwrap_or(reason::ACTION_DENIED);
            Err(InvestigationError::NotAuthorized(
                actor.as_str().to_owned(),
                format!("cannot {what}: {why}"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_authorization::{Credential, Grant, Registry};
    use safeguard_audit_core::{EventKind, FixedClock, PageRequest};
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::{AuditQuery, EventStore};

    fn net() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn clock() -> FixedClock {
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000))
    }

    fn auditor(name: &str) -> AuditorId {
        AuditorId::derive(&[name])
    }

    fn authorizer() -> Authorizer {
        let mut registry = Registry::new();
        let inv = auditor("inv");
        registry
            .register(
                Grant::new(inv.clone(), safeguard_audit_core::AuditorRole::Investigator)
                    .with_scope(AccessScope::Network(net()))
                    .with_credential(Credential::new(
                        inv,
                        "material",
                        Timestamp::from_unix_seconds(9_999_999_999),
                    )),
            )
            .unwrap();
        let ro = auditor("ro");
        registry
            .register(
                Grant::new(
                    ro.clone(),
                    safeguard_audit_core::AuditorRole::ReadOnlyReviewer,
                )
                .with_scope(AccessScope::Network(net()))
                .with_credential(Credential::new(
                    ro,
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
            )
            .unwrap();
        Authorizer::new(registry, clock())
    }

    fn service() -> CaseService {
        CaseService::new(
            net(),
            crate::SOURCE_LABEL,
            VersionLabel::new("1.0.0").unwrap(),
            clock(),
            authorizer(),
        )
    }

    fn stores() -> (crate::store::InMemoryCaseStore, MemoryEventStore) {
        (
            crate::store::InMemoryCaseStore::new(),
            MemoryEventStore::new(),
        )
    }

    #[test]
    fn opening_a_case_records_it_in_both_stores() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let opened = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "flagged transfer review",
                Priority::High,
                "denial:tx-abc",
            )
            .unwrap();
        assert_eq!(opened.status(), CaseStatus::Open);
        assert_eq!(cases.len(), 1);
        assert_eq!(audit.len(), 1);

        // Fetching returns the stored case.
        let fetched = service.get_case(&cases, opened.case_id()).unwrap();
        assert_eq!(fetched, opened);

        // The audit record is an investigation-opened lifecycle event.
        let page = audit
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].event.kind, EventKind::InvestigationOpened);
    }

    #[test]
    fn case_ids_are_deterministic_per_case_key() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let a = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "review",
                Priority::Medium,
                "denial:tx-abc",
            )
            .unwrap();
        let b = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "another title",
                Priority::Low,
                "denial:tx-abc",
            )
            .unwrap_err();
        assert!(matches!(b, InvestigationError::CaseAlreadyExists(_)));
        assert_eq!(
            a.case_id(),
            &CaseId::derive(&[net().as_str(), "denial:tx-abc"])
        );
    }

    #[test]
    fn failed_duplicate_open_records_no_second_event() {
        let service = service();
        let (mut cases, mut audit) = stores();
        service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "review",
                Priority::Medium,
                "denial:tx-abc",
            )
            .unwrap();
        assert_eq!(audit.len(), 1);
    }

    #[test]
    fn unauthorized_actors_cannot_open_cases() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let err = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("ro"),
                "review",
                Priority::Medium,
                "denial:tx-xyz",
            )
            .unwrap_err();
        assert!(matches!(err, InvestigationError::NotAuthorized(..)));
        assert!(cases.is_empty());
        assert!(audit.is_empty());
    }
}
