//! Investigation lifecycle events.
//!
//! Opening, updating, and closing a case are audit-layer actions. They are
//! recorded as derived events (`investigation-opened`, `investigation-
//! updated`, `investigation-closed`) so the audit trail can answer "which
//! cases exist, who touched them, and when" — while the case model in
//! audit-core remains the source of truth for case state. Derivation keeps
//! the two views consistent without duplicating case state in event form.

use safeguard_audit_core::{
    AuditEvent, AuditorId, CaseId, CaseStatus, EventKind, NetworkId, VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// What a lifecycle step is: the *kind of step*, distinct from the case
/// status it results in.
///
/// The distinction matters: assigning an investigator or adding a finding
/// to a case that remains `Open` is an *update*, not a second *open*; and
/// reopening a closed case (status back to `Open`) is an update too, never
/// a claim that the case was newly created. The step kind is therefore
/// explicit and is never inferred from the resulting status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    /// The case was created.
    Opened,
    /// The case changed without being created or closed.
    Updated,
    /// The case was closed.
    Closed,
}

impl LifecycleKind {
    /// The normalized event kind for this step.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::Opened => EventKind::InvestigationOpened,
            Self::Updated => EventKind::InvestigationUpdated,
            Self::Closed => EventKind::InvestigationClosed,
        }
    }
}

/// A case lifecycle action to record as an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigationLifecycle {
    /// The network the case belongs to (audit deployment domain).
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-investigations`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The case this lifecycle step concerns.
    pub case: CaseId,
    /// The acting auditor.
    pub actor: AuditorId,
    /// The kind of step being recorded.
    pub kind: LifecycleKind,
    /// The zero-based sequence of this step within the case's history
    /// (the case timeline length at commit time). Steps of one case are
    /// recorded in order and never repeat, so the sequence makes every
    /// lifecycle event's identity distinct: two steps of the same case by
    /// the same actor must not collide in the store.
    pub sequence: u32,
    /// The case status the step resulted in.
    pub status: CaseStatus,
    /// Short summary or closure reason, when relevant.
    pub summary: Option<String>,
}

impl InvestigationLifecycle {
    /// Derives the normalized lifecycle event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        // The sequence is part of the identity: the Nth step of a case is
        // deterministically the Nth step, however many times the recording
        // is re-run after a crash.
        let sequence = format!("step:{}", self.sequence);
        let source_refs = [self.case.as_str(), self.actor.as_str(), sequence.as_str()];
        let mut event = derived_audit_event_base(
            self.kind.event_kind(),
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "investigation-lifecycle",
                note: "case lifecycle step recorded by the investigation service",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("case".into(), self.case.as_str().to_owned());
        event
            .details
            .insert("actor".into(), self.actor.as_str().to_owned());
        event
            .details
            .insert("status".into(), self.status.as_str().to_owned());
        if let Some(summary) = &self.summary {
            event.details.insert("summary".into(), summary.clone());
        }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{EventKind, NetworkId, OriginKind};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn step(kind: LifecycleKind, status: CaseStatus) -> InvestigationLifecycle {
        InvestigationLifecycle {
            network: network(),
            source: "safeguard-audit-investigations".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            case: CaseId::derive(&["c1"]),
            actor: AuditorId::derive(&["aud-1"]),
            kind,
            sequence: 0,
            status,
            summary: None,
        }
    }

    #[test]
    fn different_steps_of_one_case_never_collide_in_identity() {
        // Two lifecycle steps for the same case by the same actor must
        // derive distinct event ids, or the second would be dropped as a
        // duplicate by the store. The sequence breaks the tie.
        let opened = step(LifecycleKind::Opened, CaseStatus::Open);
        let second = InvestigationLifecycle {
            sequence: 1,
            ..step(LifecycleKind::Updated, CaseStatus::Investigating)
        };
        let e1 = opened.into_audit_event(EventSlot::default()).unwrap();
        let e2 = second.into_audit_event(EventSlot::default()).unwrap();
        assert_ne!(e1.event_id, e2.event_id);
        // Re-running the same step yields the same id (idempotent replay).
        let again = InvestigationLifecycle {
            sequence: 1,
            ..step(LifecycleKind::Updated, CaseStatus::Investigating)
        };
        assert_eq!(
            e2.event_id,
            again
                .into_audit_event(EventSlot::default())
                .unwrap()
                .event_id
        );
    }

    #[test]
    fn step_kinds_map_to_event_kinds_independently_of_status() {
        assert_eq!(
            step(LifecycleKind::Opened, CaseStatus::Open)
                .kind
                .event_kind(),
            EventKind::InvestigationOpened
        );
        assert_eq!(
            step(LifecycleKind::Updated, CaseStatus::Investigating)
                .kind
                .event_kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(LifecycleKind::Updated, CaseStatus::Escalated)
                .kind
                .event_kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(LifecycleKind::Updated, CaseStatus::Resolved)
                .kind
                .event_kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(LifecycleKind::Closed, CaseStatus::Closed)
                .kind
                .event_kind(),
            EventKind::InvestigationClosed
        );
    }

    #[test]
    fn an_update_that_leaves_a_case_open_is_never_a_second_open() {
        // Assigning an investigator to a case that stays Open is an
        // *update*; inferring the kind from the resulting status would
        // wrongly emit a second investigation-opened event.
        assert_eq!(
            step(LifecycleKind::Updated, CaseStatus::Open)
                .kind
                .event_kind(),
            EventKind::InvestigationUpdated
        );
        // Reopening a closed case (status back to Open) is likewise an
        // update, never a claim the case was newly created.
        assert_eq!(
            step(LifecycleKind::Updated, CaseStatus::Open)
                .kind
                .event_kind(),
            EventKind::InvestigationUpdated
        );
    }

    #[test]
    fn lifecycle_steps_project_as_derived_events() {
        let event = step(LifecycleKind::Closed, CaseStatus::Closed)
            .into_audit_event(EventSlot::default())
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::InvestigationClosed);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(
            event.details.get("case").unwrap(),
            step(LifecycleKind::Closed, CaseStatus::Closed)
                .case
                .as_str()
        );
    }
}
