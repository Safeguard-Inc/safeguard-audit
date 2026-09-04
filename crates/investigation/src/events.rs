//! Projection of case lifecycle steps onto the audit store.
//!
//! A case's *current state* lives in the case store; its *history* lives
//! in the audit store as derived `investigation-opened`,
//! `investigation-updated`, and `investigation-closed` events. This module
//! is the bridge: it turns a lifecycle description into a record and
//! writes it through the [`EventStore`], so the two views stay consistent
//! without duplicating case state in event form.

use safeguard_audit_core::{
    AuditRecord, CaseStatus, Clock, DataClassification, NetworkId, VersionLabel,
};
use safeguard_audit_events::{EventSlot, InvestigationLifecycle};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{InvestigationError, InvestigationResult};

/// A case lifecycle step to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleStep {
    /// The network the case belongs to (audit deployment domain).
    pub network: NetworkId,
    /// The case the step concerns.
    pub case: String,
    /// The acting auditor (stable id string).
    pub actor: String,
    /// The new status after the step.
    pub status: CaseStatus,
    /// Short summary or closure reason, when relevant.
    pub summary: Option<String>,
}

impl LifecycleStep {
    /// Builds the derived audit event for this step.
    pub fn to_event(
        &self,
        source: &str,
        parser: VersionLabel,
    ) -> InvestigationResult<safeguard_audit_core::AuditEvent> {
        let lifecycle = InvestigationLifecycle {
            network: self.network.clone(),
            source: source.to_owned(),
            parser,
            case: parse_case(&self.case)?,
            actor: parse_actor(&self.actor)?,
            status: self.status,
            summary: self.summary.clone(),
        };
        lifecycle
            .into_audit_event(EventSlot::default())
            .map_err(|e| InvestigationError::LifecycleRecord(e.to_string()))
    }
}

/// Records a lifecycle step into the audit store.
///
/// The record classification is `Confidential`: case activity is not
/// public ledger metadata, but it is not financial data either. Recording
/// is idempotent per event identity, so re-running a step after a crash
/// cannot duplicate history.
pub fn record_step(
    step: &LifecycleStep,
    source: &str,
    parser: VersionLabel,
    clock: &dyn Clock,
    store: &mut dyn EventStore,
) -> InvestigationResult<()> {
    let event = step.to_event(source, parser)?;
    let record = AuditRecord::from_event_classified(event, DataClassification::Confidential, clock)
        .map_err(|e| InvestigationError::LifecycleRecord(e.to_string()))?;
    match store.insert(record) {
        Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
        Err(e) => Err(InvestigationError::LifecycleRecord(e.to_string())),
    }
}

/// Parses and validates a case id string.
fn parse_case(raw: &str) -> InvestigationResult<safeguard_audit_core::CaseId> {
    safeguard_audit_core::CaseId::from_checked(raw)
        .map_err(|e| InvestigationError::Internal(format!("invalid case id {raw}: {e}")))
}

/// Parses and validates an actor id string.
fn parse_actor(raw: &str) -> InvestigationResult<safeguard_audit_core::AuditorId> {
    safeguard_audit_core::AuditorId::from_checked(raw)
        .map_err(|e| InvestigationError::Internal(format!("invalid actor id {raw}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        EventKind, FixedClock, NetworkId, PageRequest, Timestamp,
    };
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::{AuditQuery, EventStore};

    fn step(status: CaseStatus) -> LifecycleStep {
        LifecycleStep {
            network: NetworkId::new(NetworkId::TESTNET).unwrap(),
            case: "case_01010101010101010101010101010101".into(),
            actor: "aud_01010101010101010101010101010101".into(),
            status,
            summary: None,
        }
    }

    #[test]
    fn steps_project_to_the_expected_kinds() {
        let parser = VersionLabel::new("1.0.0").unwrap();
        let opened = step(CaseStatus::Open)
            .to_event(crate::SOURCE_LABEL, parser.clone())
            .unwrap();
        let updated = step(CaseStatus::Investigating)
            .to_event(crate::SOURCE_LABEL, parser.clone())
            .unwrap();
        let closed = step(CaseStatus::Closed)
            .to_event(crate::SOURCE_LABEL, parser)
            .unwrap();
        assert_eq!(opened.kind, EventKind::InvestigationOpened);
        assert_eq!(updated.kind, EventKind::InvestigationUpdated);
        assert_eq!(closed.kind, EventKind::InvestigationClosed);
        for event in [&opened, &updated, &closed] {
            event.validate().expect("lifecycle events must be valid");
        }
    }

    #[test]
    fn recording_a_step_lands_one_record() {
        let parser = VersionLabel::new("1.0.0").unwrap();
        let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
        let mut store = MemoryEventStore::new();
        let step = step(CaseStatus::Investigating).with_summary_for_test();

        record_step(&step, crate::SOURCE_LABEL, parser, &clock, &mut store).unwrap();
        let page = store
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let items = page.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].event.kind, EventKind::InvestigationUpdated);
        assert_eq!(
            items[0].event.details.get("status").map(String::as_str),
            Some("investigating")
        );
        assert_eq!(
            items[0].event.details.get("case").map(String::as_str),
            Some("case_01010101010101010101010101010101")
        );
    }

    #[test]
    fn re_recording_the_same_step_is_idempotent() {
        let parser = VersionLabel::new("1.0.0").unwrap();
        let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
        let mut store = MemoryEventStore::new();
        let step = step(CaseStatus::Open);

        record_step(&step, crate::SOURCE_LABEL, parser.clone(), &clock, &mut store).unwrap();
        record_step(&step, crate::SOURCE_LABEL, parser, &clock, &mut store).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn invalid_ids_are_rejected_before_writing() {
        let parser = VersionLabel::new("1.0.0").unwrap();
        let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
        let mut store = MemoryEventStore::new();
        let bad = LifecycleStep {
            case: "not-a-case".into(),
            ..step(CaseStatus::Open)
        };
        assert!(record_step(&bad, crate::SOURCE_LABEL, parser, &clock, &mut store).is_err());
        assert!(store.is_empty());
    }
}

// Test-only helper kept in the impl block for the tests above.
impl LifecycleStep {
    #[cfg(test)]
    fn with_summary_for_test(mut self) -> Self {
        self.summary = Some("reviewing a denied transfer".to_owned());
        self
    }
}
