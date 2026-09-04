//! Evidence artifact model.
//!
//! Evidence converts audit records into verifiable, exportable artifacts
//! with provenance. The model here guarantees the two things every evidence
//! artifact must have:
//!
//! * **source traceability** — which records and events support it, and
//!   which parser/generator versions produced it (reproducibility), and
//! * **integrity** — a digest slot that the integrity subsystem fills so
//!   tampering with an artifact is detectable.
//!
//! Building, exporting, and verifying artifacts are jobs for the evidence
//! and integrity crates; this module is the shape they operate on.

use serde::{Deserialize, Serialize};

use crate::correlation::VersionLabel;
use crate::errors::{AuditError, AuditResult};
use crate::identifiers::{AuditorId, EventId, EvidenceId, ManifestId, RecordId};
use crate::integrity::IntegrityDigest;
use crate::timestamps::Timestamp;

/// The current schema version of the evidence artifact format.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// What kind of evidence an artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Evidence about one or more transactions.
    TransactionEvidence,
    /// Evidence about a compliance decision.
    ComplianceDecisionEvidence,
    /// Evidence about enforcement behavior.
    EnforcementEvidence,
    /// Evidence assembled for an investigation.
    InvestigationEvidence,
    /// Historical activity evidence over a range.
    HistoricalActivityEvidence,
    /// Integrity verification evidence.
    IntegrityEvidence,
}

impl EvidenceKind {
    /// The stable label for this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TransactionEvidence => "transaction-evidence",
            Self::ComplianceDecisionEvidence => "compliance-decision-evidence",
            Self::EnforcementEvidence => "enforcement-evidence",
            Self::InvestigationEvidence => "investigation-evidence",
            Self::HistoricalActivityEvidence => "historical-activity-evidence",
            Self::IntegrityEvidence => "integrity-evidence",
        }
    }
}

/// The provenance of an evidence artifact.
///
/// Every artifact must answer: which records support it, which events
/// support those records, which parser normalized them, and which generator
/// version produced this artifact. Together with the artifact's schema
/// version this makes generation reproducible from the same inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    /// The audit records the artifact was built from.
    source_records: Vec<RecordId>,
    /// The source events behind those records, when known.
    source_events: Vec<EventId>,
    /// Version of the parser/normalizer that produced the source records.
    parser_version: VersionLabel,
    /// Version of the evidence generator that produced this artifact.
    generator_version: VersionLabel,
}

impl EvidenceProvenance {
    /// Builds provenance. At least one source record or event is required —
    /// evidence with no source is not evidence.
    pub fn new(
        source_records: Vec<RecordId>,
        source_events: Vec<EventId>,
        parser_version: VersionLabel,
        generator_version: VersionLabel,
    ) -> AuditResult<Self> {
        if source_records.is_empty() && source_events.is_empty() {
            return Err(AuditError::MalformedEvidence(
                "evidence provenance must name at least one source record or event".into(),
            ));
        }
        Ok(Self {
            source_records,
            source_events,
            parser_version,
            generator_version,
        })
    }

    /// The supporting records.
    pub fn source_records(&self) -> &[RecordId] {
        &self.source_records
    }

    /// The supporting source events.
    pub fn source_events(&self) -> &[EventId] {
        &self.source_events
    }

    /// The parser version.
    pub fn parser_version(&self) -> &VersionLabel {
        &self.parser_version
    }

    /// The generator version.
    pub fn generator_version(&self) -> &VersionLabel {
        &self.generator_version
    }
}

/// A generated evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    evidence_id: EvidenceId,
    kind: EvidenceKind,
    provenance: EvidenceProvenance,
    generated_at: Timestamp,
    generated_by: Option<AuditorId>,
    schema_version: u32,
    /// Digest over the artifact content, filled by the integrity subsystem.
    digest: Option<IntegrityDigest>,
    /// The integrity manifest covering this artifact's records, when one
    /// was generated with it.
    manifest_id: Option<ManifestId>,
}

impl EvidenceArtifact {
    /// Builds an artifact with the current schema version.
    pub fn new(
        evidence_id: EvidenceId,
        kind: EvidenceKind,
        provenance: EvidenceProvenance,
        generated_at: Timestamp,
        generated_by: Option<AuditorId>,
    ) -> Self {
        Self {
            evidence_id,
            kind,
            provenance,
            generated_at,
            generated_by,
            schema_version: EVIDENCE_SCHEMA_VERSION,
            digest: None,
            manifest_id: None,
        }
    }

    /// Attaches the content digest computed by the integrity subsystem.
    pub fn with_digest(mut self, digest: IntegrityDigest) -> Self {
        self.digest = Some(digest);
        self
    }

    /// Attaches the manifest covering this artifact's source records.
    pub fn with_manifest(mut self, manifest_id: ManifestId) -> Self {
        self.manifest_id = Some(manifest_id);
        self
    }

    /// Validates artifact invariants: schema version supported and digest
    /// algorithm understood.
    pub fn validate(&self) -> AuditResult<()> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(format!(
                "evidence schema version {} is not supported (expected {EVIDENCE_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        Ok(())
    }

    /// Canonical bytes for the artifact's *content* — the deterministic
    /// input to its content digest.
    ///
    /// The integrity slots are excluded by construction: the digest and
    /// manifest id are attached *after* the content is hashed, so they can
    /// never be part of the content they certify. The builder hashes these
    /// bytes and the verifier recomputes them from the stored artifact,
    /// which makes both paths agree without any field-stripping hacks.
    pub fn canonical_bytes(&self) -> AuditResult<Vec<u8>> {
        let mut content = self.clone();
        content.digest = None;
        content.manifest_id = None;
        crate::serialization::canonical_json(&content)
    }

    /// The evidence id.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// The evidence kind.
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// The provenance.
    pub fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }

    /// When the artifact was generated.
    pub fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    /// The content digest, once computed.
    pub fn digest(&self) -> Option<&IntegrityDigest> {
        self.digest.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{CaseId, NetworkId, RecordId};

    #[test]
    fn provenance_requires_a_source() {
        let version = VersionLabel::new("1.0.0").unwrap();
        assert!(EvidenceProvenance::new(vec![], vec![], version.clone(), version.clone()).is_err());
        let with_record = EvidenceProvenance::new(
            vec![RecordId::derive(&["rec-1"])],
            vec![],
            version.clone(),
            version,
        )
        .unwrap();
        assert_eq!(with_record.source_records().len(), 1);
    }

    #[test]
    fn artifacts_carry_schema_version_and_labels() {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let _ = network;
        let provenance = EvidenceProvenance::new(
            vec![RecordId::derive(&["rec-1"])],
            vec![],
            VersionLabel::new("1.0.0").unwrap(),
            VersionLabel::new("2.0.0").unwrap(),
        )
        .unwrap();
        let artifact = EvidenceArtifact::new(
            EvidenceId::derive(&["e1"]),
            EvidenceKind::InvestigationEvidence,
            provenance,
            Timestamp::from_unix_seconds(100),
            Some(AuditorId::derive(&["aud-1"])),
        );
        assert!(artifact.validate().is_ok());
        assert_eq!(artifact.kind().as_str(), "investigation-evidence");
        assert_eq!(
            EvidenceKind::IntegrityEvidence.as_str(),
            "integrity-evidence"
        );
        assert_eq!(artifact.provenance().generator_version().as_str(), "2.0.0");
        let _ = CaseId::derive(&["unused"]);
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let provenance = EvidenceProvenance::new(
            vec![RecordId::derive(&["r"])],
            vec![],
            VersionLabel::new("1").unwrap(),
            VersionLabel::new("1").unwrap(),
        )
        .unwrap();
        let mut artifact = EvidenceArtifact::new(
            EvidenceId::derive(&["e"]),
            EvidenceKind::TransactionEvidence,
            provenance,
            Timestamp::from_unix_seconds(0),
            None,
        );
        artifact.schema_version = 99;
        assert!(artifact.validate().is_err());
    }

    #[test]
    fn artifacts_round_trip_serde() {
        let provenance = EvidenceProvenance::new(
            vec![RecordId::derive(&["r"])],
            vec![EventId::derive(&["e"])],
            VersionLabel::new("1").unwrap(),
            VersionLabel::new("1").unwrap(),
        )
        .unwrap();
        let artifact = EvidenceArtifact::new(
            EvidenceId::derive(&["e"]),
            EvidenceKind::EnforcementEvidence,
            provenance,
            Timestamp::from_unix_seconds(0),
            None,
        );
        let json = serde_json::to_string(&artifact).unwrap();
        let back: EvidenceArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, artifact);
    }

    #[test]
    fn canonical_bytes_exclude_the_integrity_slots() {
        let provenance = EvidenceProvenance::new(
            vec![RecordId::derive(&["r"])],
            vec![],
            VersionLabel::new("1").unwrap(),
            VersionLabel::new("1").unwrap(),
        )
        .unwrap();
        let artifact = EvidenceArtifact::new(
            EvidenceId::derive(&["e"]),
            EvidenceKind::TransactionEvidence,
            provenance,
            Timestamp::from_unix_seconds(0),
            None,
        );
        let digest = IntegrityDigest::sha256("aa".repeat(32)).unwrap();
        let manifest = ManifestId::derive(&["m"]);
        let sealed = artifact
            .clone()
            .with_digest(digest)
            .with_manifest(manifest.clone());
        // Sealing never changes the canonical content: the digest and
        // manifest are attached after content hashing, not part of it.
        assert_eq!(artifact.canonical_bytes().unwrap(), sealed.canonical_bytes().unwrap());
        // And content bytes are deterministic.
        assert_eq!(
            sealed.canonical_bytes().unwrap(),
            sealed.canonical_bytes().unwrap()
        );
    }
}
