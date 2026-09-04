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
    /// The new status (opened/updated/closed map onto the event kinds).
    pub status: CaseStatus,
    /// Short summary or closure reason, when relevant.
    pub summary: Option<String>,
}

impl InvestigationLifecycle {
    /// Maps the case status onto the normalized lifecycle kind.
    pub fn kind(&self) -> EventKind {
        match self.status {
            CaseStatus::Closed => EventKind::InvestigationClosed,
            CaseStatus::Open => EventKind::InvestigationOpened,
            _ => EventKind::InvestigationUpdated,
        }
    }

    /// Derives the normalized lifecycle event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let source_refs = [self.case.as_str(), self.actor.as_str()];
        let mut event = derived_audit_event_base(
            self.kind(),
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

    fn step(status: CaseStatus) -> InvestigationLifecycle {
        InvestigationLifecycle {
            network: network(),
            source: "safeguard-audit-investigations".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            case: CaseId::derive(&["c1"]),
            actor: AuditorId::derive(&["aud-1"]),
            status,
            summary: None,
        }
    }

    #[test]
    fn lifecycle_kinds_follow_case_status() {
        assert_eq!(
            step(CaseStatus::Open).kind(),
            EventKind::InvestigationOpened
        );
        assert_eq!(
            step(CaseStatus::Investigating).kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(CaseStatus::Escalated).kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(CaseStatus::Resolved).kind(),
            EventKind::InvestigationUpdated
        );
        assert_eq!(
            step(CaseStatus::Closed).kind(),
            EventKind::InvestigationClosed
        );
    }

    #[test]
    fn lifecycle_steps_project_as_derived_events() {
        let event = step(CaseStatus::Closed)
            .into_audit_event(EventSlot::default())
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::InvestigationClosed);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(
            event.details.get("case").unwrap(),
            step(CaseStatus::Closed).case.as_str()
        );
    }
}
