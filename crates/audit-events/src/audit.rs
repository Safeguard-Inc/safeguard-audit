//! Audit-layer generated-event records.
//!
//! Evidence generation, report generation, and record correction are
//! themselves things worth recording — a compliance officer must be able to
//! prove *which* artifacts and reports were produced, by whom, and what was
//! corrected and why. These derived events close that loop.

use safeguard_audit_core::{
    AuditEvent, AuditorId, EventKind, EvidenceKind, NetworkId, RecordId, ReportId, VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// A generated evidence artifact, recorded as a derived event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGenerated {
    /// The network the evidence belongs to.
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-evidence`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The generated evidence artifact id.
    pub evidence: safeguard_audit_core::EvidenceId,
    /// What kind of evidence was generated.
    pub kind: EvidenceKind,
    /// How many records the artifact covers.
    pub record_count: u64,
    /// Who generated it.
    pub generated_by: AuditorId,
}

impl EvidenceGenerated {
    /// Derives the normalized `evidence-generated` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let source_refs = [
            self.evidence.as_str(),
            self.kind.as_str(),
            self.generated_by.as_str(),
        ];
        let mut event = derived_audit_event_base(
            EventKind::EvidenceGenerated,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "evidence-generation-recorded",
                note: "evidence artifact generation recorded for the audit trail",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("evidence".into(), self.evidence.as_str().to_owned());
        event
            .details
            .insert("kind".into(), self.kind.as_str().to_owned());
        event
            .details
            .insert("record_count".into(), self.record_count.to_string());
        event
            .details
            .insert("by".into(), self.generated_by.as_str().to_owned());
        Ok(event)
    }
}

/// A generated report, recorded as a derived event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportGenerated {
    /// The network the report belongs to.
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-reporting`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The generated report id.
    pub report: ReportId,
    /// The report kind label.
    pub kind: String,
    /// How many records the report covers.
    pub record_count: u64,
    /// Who generated it.
    pub generated_by: AuditorId,
}

impl ReportGenerated {
    /// Derives the normalized `report-generated` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let source_refs = [self.report.as_str(), self.kind.as_str()];
        let mut event = derived_audit_event_base(
            EventKind::ReportGenerated,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "report-generation-recorded",
                note: "report generation recorded for the audit trail",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("report".into(), self.report.as_str().to_owned());
        event.details.insert("kind".into(), self.kind.clone());
        event
            .details
            .insert("record_count".into(), self.record_count.to_string());
        event
            .details
            .insert("by".into(), self.generated_by.as_str().to_owned());
        Ok(event)
    }
}

/// A record correction, recorded as the `record-corrected` event that the
/// append-only correction record wraps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCorrected {
    /// The network the correction belongs to.
    pub network: NetworkId,
    /// Stable source label.
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The original record being corrected (never mutated).
    pub supersedes: RecordId,
    /// Why the correction was made.
    pub reason: String,
    /// Who authorized the correction.
    pub corrected_by: AuditorId,
}

impl RecordCorrected {
    /// Derives the normalized `record-corrected` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let source_refs = [self.supersedes.as_str()];
        let mut event = derived_audit_event_base(
            EventKind::RecordCorrected,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "record-correction",
                note: "correction appended; the original record is preserved unmodified",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("supersedes".into(), self.supersedes.as_str().to_owned());
        event.details.insert("reason".into(), self.reason.clone());
        event
            .details
            .insert("by".into(), self.corrected_by.as_str().to_owned());
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{EventKind, EvidenceId, NetworkId, OriginKind, RecordId};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn evidence_generation_is_recorded() {
        let record = EvidenceGenerated {
            network: network(),
            source: "safeguard-audit-evidence".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            evidence: EvidenceId::derive(&["ev-1"]),
            kind: EvidenceKind::TransactionEvidence,
            record_count: 2,
            generated_by: AuditorId::derive(&["aud-1"]),
        };
        let event = record.into_audit_event(EventSlot::default()).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::EvidenceGenerated);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(event.details.get("record_count").unwrap(), "2");
    }

    #[test]
    fn report_generation_is_recorded() {
        let record = ReportGenerated {
            network: network(),
            source: "safeguard-audit-reporting".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            report: ReportId::derive(&["r-1"]),
            kind: "denied-transactions".into(),
            record_count: 5,
            generated_by: AuditorId::derive(&["aud-2"]),
        };
        let event = record.into_audit_event(EventSlot::default()).unwrap();
        assert_eq!(event.kind, EventKind::ReportGenerated);
        assert_eq!(event.details.get("kind").unwrap(), "denied-transactions");
    }

    #[test]
    fn corrections_name_their_original() {
        let record = RecordCorrected {
            network: network(),
            source: "safeguard-audit".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            supersedes: RecordId::derive(&["original"]),
            reason: "wrong operation index".into(),
            corrected_by: AuditorId::derive(&["aud-3"]),
        };
        let event = record.into_audit_event(EventSlot::default()).unwrap();
        assert_eq!(event.kind, EventKind::RecordCorrected);
        assert_eq!(
            event.details.get("supersedes").unwrap(),
            RecordId::derive(&["original"]).as_str()
        );
        assert_eq!(
            event.details.get("reason").unwrap(),
            "wrong operation index"
        );
    }
}
