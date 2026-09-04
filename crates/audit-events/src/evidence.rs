//! Evidence generation events.
//!
//! Generating an evidence artifact is an audit-layer action and is itself
//! recorded: a derived `evidence-generated` event answers *which evidence
//! was produced, from how many records, with which manifest and digest*,
//! so the audit trail can attest to its own evidence production without
//! duplicating the artifact's content (the artifact and its integrity
//! manifest live in the evidence crate; the store holds the pointer and
//! the provenance).

use safeguard_audit_core::{
    AuditEvent, EvidenceId, EvidenceKind, EventKind, IntegrityDigest, ManifestId, NetworkId,
    VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// An evidence generation action to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLifecycle {
    /// The network the evidence belongs to (audit deployment domain).
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-evidence`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The generated evidence artifact.
    pub evidence: EvidenceId,
    /// The evidence kind.
    pub kind: EvidenceKind,
    /// How many source records the artifact was built from.
    pub record_count: u64,
    /// The integrity manifest covering the source records, when one was
    /// generated with the artifact.
    pub manifest: Option<ManifestId>,
    /// The artifact's content digest hex, when computed.
    pub digest: Option<IntegrityDigest>,
}

impl EvidenceLifecycle {
    /// Derives the normalized `evidence-generated` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let kind_label = self.kind.as_str();
        let count = self.record_count.to_string();
        let source_refs = [self.evidence.as_str(), kind_label, count.as_str()];
        let mut event = derived_audit_event_base(
            EventKind::EvidenceGenerated,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "evidence-generation",
                note: "evidence artifact generation recorded by the evidence service",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("evidence".into(), self.evidence.as_str().to_owned());
        event.details.insert("kind".into(), kind_label.to_owned());
        event.details.insert("records".into(), count);
        if let Some(manifest) = &self.manifest {
            event
                .details
                .insert("manifest".into(), manifest.as_str().to_owned());
        }
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

    fn lifecycle() -> EvidenceLifecycle {
        EvidenceLifecycle {
            network: network(),
            source: "safeguard-audit-evidence".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            evidence: EvidenceId::derive(&["testnet", "transaction-evidence", "rec_1"]),
            kind: EvidenceKind::TransactionEvidence,
            record_count: 1,
            manifest: Some(ManifestId::derive(&["m1"])),
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        }
    }

    #[test]
    fn generations_project_as_derived_evidence_events() {
        let event = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::EvidenceGenerated);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(
            event.details.get("evidence").unwrap(),
            lifecycle().evidence.as_str()
        );
        assert_eq!(event.details.get("kind").unwrap(), "transaction-evidence");
        assert_eq!(event.details.get("records").unwrap(), "1");
        assert_eq!(
            event.details.get("manifest").unwrap(),
            lifecycle().manifest.as_ref().unwrap().as_str()
        );
    }

    #[test]
    fn generation_identity_is_deterministic_and_distinct() {
        let a = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        let b = lifecycle().into_audit_event(EventSlot::default()).unwrap();
        assert_eq!(a.event_id, b.event_id);
        // A different evidence id (different source set) never collides.
        let other = EvidenceLifecycle {
            evidence: EvidenceId::derive(&["testnet", "transaction-evidence", "rec_2"]),
            ..lifecycle()
        };
        let c = other.into_audit_event(EventSlot::default()).unwrap();
        assert_ne!(a.event_id, c.event_id);
    }
}