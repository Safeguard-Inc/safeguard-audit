//! Report generation events.
//!
//! Generating a report is an audit-layer action and is itself recorded: a
//! derived `report-generated` event answers *which report was produced,
//! of which kind, from how many records, with which digest*, so the
//! audit trail attests to its own reporting without duplicating the
//! report body (the report itself lives in the reporting crate; the store
//! holds the pointer and the provenance).

use safeguard_audit_core::{
    AuditEvent, EventKind, IntegrityDigest, NetworkId, ReportId, ReportKind, VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// A report generation action to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLifecycle {
    /// The network the report belongs to (audit deployment domain).
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-reporting`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The generated report.
    pub report: ReportId,
    /// The report kind.
    pub kind: ReportKind,
    /// How many records the report covered.
    pub record_count: u64,
    /// The report's content digest hex, when computed.
    pub digest: Option<IntegrityDigest>,
}

impl ReportLifecycle {
    /// Derives the normalized `report-generated` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let kind_label = self.kind.as_str();
        let count = self.record_count.to_string();
        let source_refs = [self.report.as_str(), kind_label, count.as_str()];
        let mut event = derived_audit_event_base(
            EventKind::ReportGenerated,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "report-generation",
                note: "report generation recorded by the reporting service",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("report".into(), self.report.as_str().to_owned());
        event.details.insert("kind".into(), kind_label.to_owned());
        event.details.insert("records".into(), count);
        if let Some(digest) = &self.digest {
            event
                .details
                .insert("digest".into(), digest.value().to_owned());
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

    fn lifecycle() -> ReportLifecycle {
        ReportLifecycle {
            network: network(),
            source: "safeguard-audit-reporting".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            report: ReportId::derive(&["testnet", "denied-transactions"]),
            kind: ReportKind::DeniedTransactions,
            record_count: 3,
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        }
    }

    #[test]
    fn generations_project_as_derived_report_events() {
        let event = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::ReportGenerated);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(
            event.details.get("report").unwrap(),
            lifecycle().report.as_str()
        );
        assert_eq!(event.details.get("kind").unwrap(), "denied-transactions");
        assert_eq!(event.details.get("records").unwrap(), "3");
    }

    #[test]
    fn generation_identity_is_deterministic_and_distinct() {
        let a = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        let b = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        assert_eq!(a.event_id, b.event_id);
        let other = ReportLifecycle {
            report: ReportId::derive(&["testnet", "compliance-activity"]),
            ..lifecycle()
        };
        let c = other.into_audit_event(EventSlot::default()).unwrap();
        assert_ne!(a.event_id, c.event_id);
    }
}
