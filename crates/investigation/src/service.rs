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
use safeguard_audit_events::LifecycleKind;
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

    /// Assigns an investigator to a case, recording the assignment on the
    /// timeline and an `investigation-updated` event.
    pub fn assign(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case_id: &CaseId,
        investigator: &AuditorId,
    ) -> InvestigationResult<InvestigationCase> {
        self.require(actor, AccessAction::CreateInvestigation, "assign a case")?;
        let mut case = self.get_open(cases, case_id)?;
        case.assign(investigator.clone(), Timestamp::now(self.clock.as_ref()))
            .map_err(|e| InvestigationError::Internal(e.to_string()))?;
        self.commit(cases, audit, actor, case, None)
    }

    /// Transitions a case to `to`, validating the move against the core
    /// model and recording an `investigation-updated` (or `-closed`)
    /// event.
    ///
    /// Closing requires a reason; reopening a closed case requires an
    /// administrator (the only role trusted to reopen terminal cases).
    pub fn transition(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case_id: &CaseId,
        to: CaseStatus,
        reason: Option<&str>,
    ) -> InvestigationResult<InvestigationCase> {
        let mut case = cases.get(case_id)?;

        if to == CaseStatus::Closed && reason.is_none() {
            return Err(InvestigationError::InvalidContent(
                "closing a case requires a recorded reason".to_owned(),
            ));
        }
        if case.status() == CaseStatus::Closed {
            if to == CaseStatus::Open {
                // Admin reopen: only an administrator may reopen a closed case.
                self.require_role(actor, "reopen a closed case")?;
            } else {
                return Err(InvestigationError::ClosedCase(case_id.as_str().to_owned()));
            }
        } else {
            self.require(actor, AccessAction::CreateInvestigation, "update a case")?;
        }

        case.change_status(
            to,
            Timestamp::now(self.clock.as_ref()),
            actor.clone(),
            reason,
        )
        .map_err(|e| {
            InvestigationError::InvalidTransition(format!("case {}: {e}", case_id.as_str()))
        })?;
        case.validate()
            .map_err(|e| InvestigationError::Internal(e.to_string()))?;
        self.commit(cases, audit, actor, case, None)
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
                kind: LifecycleKind::Opened,
                // The open is step 0 of the case's history.
                sequence: 0,
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

    /// Links an audit record to the case after verifying it exists in the
    /// audit store. The record's kind drives the timeline entry type, so
    /// linking a denial record surfaces as a `denial` timeline entry.
    pub fn link_record(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case_id: &CaseId,
        record_id: &safeguard_audit_core::RecordId,
        kind: safeguard_audit_core::TimelineEntryKind,
    ) -> InvestigationResult<InvestigationCase> {
        self.require(
            actor,
            AccessAction::CreateInvestigation,
            "link a record to a case",
        )?;
        let mut case = self.get_open(cases, case_id)?;

        // The record must exist in the audit store before it can be linked
        // to an investigation: a case may reference reality, never ghosts.
        audit
            .get(record_id)
            .map_err(|_| InvestigationError::MissingRecord(record_id.as_str().to_owned()))?;

        case.add_related_record(record_id.clone(), kind, Timestamp::now(self.clock.as_ref()))
            .map_err(|e| InvestigationError::Internal(e.to_string()))?;
        self.commit(cases, audit, actor, case, None)
    }

    /// Adds a finding to the case, recording a `finding-added` timeline
    /// entry and an `investigation-updated` event.
    pub fn add_finding(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case_id: &CaseId,
        finding: NewFinding<'_>,
    ) -> InvestigationResult<InvestigationCase> {
        self.require(actor, AccessAction::CreateInvestigation, "add a finding")?;
        let mut case = self.get_open(cases, case_id)?;

        let now = Timestamp::now(self.clock.as_ref());
        // The finding id derives from the case and the step index, so the
        // Nth finding of a case is deterministically the Nth finding.
        let finding_id = safeguard_audit_core::FindingId::derive(&[
            case_id.as_str(),
            &format!("finding:{}", case.timeline().len()),
        ]);
        let NewFinding {
            kind,
            severity,
            summary,
            related_records,
        } = finding;
        let finding = safeguard_audit_core::Finding::new(
            finding_id,
            kind,
            severity,
            summary,
            now,
            actor.clone(),
        )
        .map_err(|e| InvestigationError::InvalidContent(e.to_string()))?
        .with_related_records(related_records);

        case.add_finding(finding, now)
            .map_err(|e| InvestigationError::Internal(e.to_string()))?;
        self.commit(cases, audit, actor, case, Some(summary))
    }

    /// Adds a note to the case.
    pub fn add_note(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case_id: &CaseId,
        body: &str,
    ) -> InvestigationResult<InvestigationCase> {
        self.require(actor, AccessAction::CreateInvestigation, "add a note")?;
        let mut case = self.get_open(cases, case_id)?;

        let now = Timestamp::now(self.clock.as_ref());
        let note_id = safeguard_audit_core::NoteId::derive(&[
            case_id.as_str(),
            &format!("note:{}", case.timeline().len()),
        ]);
        let note = safeguard_audit_core::Note::new(note_id, actor.clone(), body, now)
            .map_err(|e| InvestigationError::InvalidContent(e.to_string()))?;

        case.add_note(note)
            .map_err(|e| InvestigationError::Internal(e.to_string()))?;
        self.commit(cases, audit, actor, case, None)
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

    /// Requires `actor` to hold the administrator role (for admin-only
    /// operations such as reopening a closed case).
    fn require_role(&self, actor: &AuditorId, what: &str) -> InvestigationResult<()> {
        let role = self
            .authorizer
            .registry()
            .grant(actor)
            .map(|g| g.role)
            .map_err(|_| {
                InvestigationError::NotAuthorized(
                    actor.as_str().to_owned(),
                    format!("cannot {what}: unknown auditor"),
                )
            })?;
        if role == safeguard_audit_core::AuditorRole::Administrator {
            Ok(())
        } else {
            Err(InvestigationError::NotAuthorized(
                actor.as_str().to_owned(),
                format!("cannot {what}: requires administrator"),
            ))
        }
    }

    /// Fetches a case that must exist and must not be closed.
    fn get_open(
        &self,
        cases: &dyn CaseStore,
        case_id: &CaseId,
    ) -> InvestigationResult<InvestigationCase> {
        let case = cases.get(case_id)?;
        if case.status().is_terminal() {
            return Err(InvestigationError::ClosedCase(case_id.as_str().to_owned()));
        }
        Ok(case)
    }

    /// Persists a mutated case and records its lifecycle event. The case
    /// status at commit time drives the event kind (open/updated/closed).
    fn commit(
        &self,
        cases: &mut dyn CaseStore,
        audit: &mut dyn EventStore,
        actor: &AuditorId,
        case: InvestigationCase,
        summary: Option<&str>,
    ) -> InvestigationResult<InvestigationCase> {
        let case_id = case.case_id().clone();
        let status = case.status();
        // The step kind is explicit: an update that leaves the case Open
        // (assignment, note) is an update, never a second open; closing is
        // a close; anything else is an update.
        let kind = match status {
            CaseStatus::Closed => LifecycleKind::Closed,
            _ => LifecycleKind::Updated,
        };
        // Step index = the number of timeline entries already recorded on
        // this case. The case timeline is append-only, so step N of a case
        // is deterministically step N however often recording is re-run.
        let sequence = case.timeline().len() as u32;
        cases.update(case.clone())?;
        record_step(
            &LifecycleStep {
                network: self.network.clone(),
                case: case_id.as_str().to_owned(),
                actor: actor.as_str().to_owned(),
                kind,
                sequence,
                status,
                summary: summary.map(str::to_owned),
            },
            &self.source,
            self.parser.clone(),
            self.clock.as_ref(),
            audit,
        )?;
        Ok(case)
    }
}

/// A finding to attach to a case: its content, validated at record time.
#[derive(Debug, Clone)]
pub struct NewFinding<'a> {
    /// What the finding classifies as.
    pub kind: safeguard_audit_core::FindingKind,
    /// Severity of the finding.
    pub severity: safeguard_audit_core::Severity,
    /// Short bounded summary.
    pub summary: &'a str,
    /// Records supporting the finding.
    pub related_records: Vec<safeguard_audit_core::RecordId>,
}

impl<'a> NewFinding<'a> {
    /// A finding with no supporting records yet.
    pub fn new(
        kind: safeguard_audit_core::FindingKind,
        severity: safeguard_audit_core::Severity,
        summary: &'a str,
    ) -> Self {
        Self {
            kind,
            severity,
            summary,
            related_records: Vec::new(),
        }
    }

    /// Adds supporting records.
    pub fn with_records(mut self, records: Vec<safeguard_audit_core::RecordId>) -> Self {
        self.related_records = records;
        self
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

    #[test]
    fn assigning_records_an_update_not_a_second_open() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let opened = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "flagged transfer review",
                Priority::High,
                "denial:tx-assign",
            )
            .unwrap();

        let assigned = service
            .assign(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                &auditor("inv"),
            )
            .unwrap();
        assert_eq!(assigned.assigned_to(), Some(&auditor("inv")));
        // The assignment is a second lifecycle record, an *update*.
        let page = audit
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let items = page.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].event.kind, EventKind::InvestigationOpened);
        assert_eq!(items[1].event.kind, EventKind::InvestigationUpdated);
    }

    fn seed_record() -> (MemoryEventStore, safeguard_audit_core::RecordId) {
        // A minimal valid record in an audit store, used to test linking.
        let mut audit = MemoryEventStore::new();
        let event = safeguard_audit_core::AuditEvent::new(
            safeguard_audit_core::EventId::derive(&["testnet", "seed-tx"]),
            safeguard_audit_core::EventKind::TransferDenied,
            net(),
            safeguard_audit_core::EventProvenance::new(
                safeguard_audit_core::OriginKind::Derived,
                "test",
                VersionLabel::new("1.0.0").unwrap(),
            )
            .unwrap()
            .with_derivation(
                safeguard_audit_core::DerivationInfo::new(
                    "seed",
                    Vec::new(),
                    "seeded for link tests",
                )
                .unwrap(),
            ),
        );
        let record = safeguard_audit_core::AuditRecord::from_event(event, &clock()).unwrap();
        let id = record.record_id.clone();
        audit.insert(record).unwrap();
        (audit, id)
    }

    #[test]
    fn linking_a_record_requires_it_to_exist_in_the_audit_store() {
        let service = service();
        let (mut cases, mut audit_store) = stores();
        // Give the case store its own audit store to link from.
        let opened = service
            .open_case(
                &mut cases,
                &mut audit_store,
                &auditor("inv"),
                "denied transfer",
                Priority::High,
                "denial:tx-link",
            )
            .unwrap();

        // Linking a ghost record is rejected: a case references reality.
        let ghost = safeguard_audit_core::RecordId::derive(&["ghost"]);
        let err = service
            .link_record(
                &mut cases,
                &mut audit_store,
                &auditor("inv"),
                opened.case_id(),
                &ghost,
                safeguard_audit_core::TimelineEntryKind::Denial,
            )
            .unwrap_err();
        assert!(matches!(err, InvestigationError::MissingRecord(_)));

        // With a real record, the link succeeds and lands on the timeline.
        let (mut seed_audit, record_id) = seed_record();
        let linked = service
            .link_record(
                &mut cases,
                &mut seed_audit,
                &auditor("inv"),
                opened.case_id(),
                &record_id,
                safeguard_audit_core::TimelineEntryKind::Denial,
            )
            .unwrap();
        assert_eq!(linked.timeline().len(), 1);
        assert_eq!(
            linked.timeline()[0].kind(),
            safeguard_audit_core::TimelineEntryKind::Denial
        );
        assert_eq!(linked.timeline()[0].record(), Some(&record_id));
        linked
            .validate()
            .expect("a case with a linked record stays valid");
    }

    #[test]
    fn findings_and_notes_accumulate_with_timeline_entries() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let opened = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "denied transfer",
                Priority::High,
                "denial:tx-find",
            )
            .unwrap();

        let with_finding = service
            .add_finding(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                NewFinding::new(
                    safeguard_audit_core::FindingKind::Anomaly,
                    safeguard_audit_core::Severity::High,
                    "repeated denials from the same account",
                ),
            )
            .unwrap();
        assert_eq!(with_finding.findings().len(), 1);
        assert_eq!(
            with_finding.findings()[0].severity(),
            safeguard_audit_core::Severity::High
        );

        let with_note = service
            .add_note(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                "awaiting the account freeze record",
            )
            .unwrap();
        assert_eq!(with_note.notes().len(), 1);
        assert_eq!(with_note.timeline().len(), 2);
        with_note
            .validate()
            .expect("findings and notes keep the case valid");

        // Finding ids are deterministic per step index.
        assert!(with_finding.findings()[0]
            .finding_id()
            .as_str()
            .starts_with("find_"));
    }

    #[test]
    fn transitions_are_validated_and_recorded() {
        let service = service();
        let (mut cases, mut audit) = stores();
        let opened = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "review",
                Priority::High,
                "denial:tx-transition",
            )
            .unwrap();

        // open -> investigating is legal.
        let investigating = service
            .transition(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                CaseStatus::Investigating,
                None,
            )
            .unwrap();
        assert_eq!(investigating.status(), CaseStatus::Investigating);

        // open -> closed (skipping) is rejected by the model.
        let err = service
            .transition(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                CaseStatus::Closed,
                Some("done early"),
            )
            .unwrap_err();
        assert!(matches!(err, InvestigationError::InvalidTransition(_)));

        // resolving and closing, with a reason required to close.
        service
            .transition(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                CaseStatus::Resolved,
                None,
            )
            .unwrap();
        let closed = service
            .transition(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                opened.case_id(),
                CaseStatus::Closed,
                Some("no violation found"),
            )
            .unwrap();
        assert_eq!(closed.status(), CaseStatus::Closed);

        // Closure without a reason is rejected.
        let again = service
            .open_case(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                "second",
                Priority::Low,
                "denial:tx-transition-2",
            )
            .unwrap();
        let err = service
            .transition(
                &mut cases,
                &mut audit,
                &auditor("inv"),
                again.case_id(),
                CaseStatus::Closed,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, InvestigationError::InvalidContent(_)));

        // The lifecycle history contains one open, one close, and two
        // updates (investigating + resolved) for the first case, plus an
        // open for the second case. Records without on-chain placement and
        // a shared fixed clock read back in record-id order, so the
        // assertions count kinds rather than assuming insertion order.
        let page = audit
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(100).unwrap(),
            )
            .unwrap();
        let kinds: Vec<EventKind> = page.items().iter().map(|r| r.event.kind).collect();
        let count = |k: EventKind| kinds.iter().filter(|x| **x == k).count();
        assert_eq!(count(EventKind::InvestigationOpened), 2); // first + second case
        assert_eq!(count(EventKind::InvestigationUpdated), 2); // investigating + resolved
        assert_eq!(count(EventKind::InvestigationClosed), 1);
        assert_eq!(kinds.len(), 5);
    }
}
