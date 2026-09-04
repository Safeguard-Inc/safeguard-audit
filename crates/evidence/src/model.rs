//! The evidence *package*: an artifact plus the manifest that certifies
//! its sources.
//!
//! A lone artifact can answer \"what was generated\"; a package can answer
//! \"can it be independently checked\". The package pairs the
//! [`EvidenceArtifact`] with an [`EvidenceManifest`] — the artifact-linked
//! digest inventory of the source records it was built from. The manifest
//! reuses the integrity crate's [`ManifestEntry`] and aggregate machinery
//! through the core [`IntegrityManifest`], and adds the artifact
//! reference, parser version, and network that make it a self-describing
//! evidence manifest rather than a generic record inventory.

use serde::{Deserialize, Serialize};

use safeguard_audit_core::{
    AuditResult, EvidenceArtifact, EvidenceId, IntegrityDigest, IntegrityManifest, ManifestEntry,
    ManifestId, NetworkId, Timestamp, VersionLabel,
};

use crate::errors::{EvidenceError, EvidenceResult};

/// The current schema version of the evidence package manifest.
pub const EVIDENCE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The integrity manifest shipped with an evidence package.
///
/// One entry per source record (digests recomputed from record bodies at
/// generation time), an aggregate digest over the entries themselves, and
/// the artifact reference plus parser/network context that let an
/// exported package be verified independently of the generating system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifest {
    manifest_id: ManifestId,
    /// The artifact this manifest certifies.
    artifact: EvidenceId,
    schema_version: u32,
    generated_at: Timestamp,
    /// Software version that generated the manifest (reproducibility).
    software_version: String,
    /// Parser version that produced the source records.
    parser_version: VersionLabel,
    /// The network the covered records belong to.
    network: NetworkId,
    /// First covered ledger, when every source record names one.
    from_ledger: Option<i64>,
    /// Last covered ledger, when every source record names one.
    to_ledger: Option<i64>,
    /// Number of covered records; must equal `entries.len()`.
    record_count: u64,
    entries: Vec<ManifestEntry>,
    /// Digest over the canonical manifest entries (the package aggregate).
    aggregate_digest: IntegrityDigest,
}

impl EvidenceManifest {
    /// Lifts an integrity manifest into an evidence package manifest by
    /// attaching the artifact reference, parser version, and network.
    pub fn from_integrity_manifest(
        manifest: IntegrityManifest,
        artifact: EvidenceId,
        parser_version: VersionLabel,
        network: NetworkId,
    ) -> EvidenceResult<Self> {
        manifest.validate().map_err(EvidenceError::from_core)?;
        let aggregate_digest = manifest.aggregate_digest().cloned().ok_or_else(|| {
            EvidenceError::InvalidContent("evidence manifests require an aggregate digest".into())
        })?;
        let built = Self {
            manifest_id: manifest.manifest_id().clone(),
            artifact,
            schema_version: EVIDENCE_MANIFEST_SCHEMA_VERSION,
            generated_at: manifest.generated_at(),
            software_version: manifest.software_version().to_owned(),
            parser_version,
            network,
            from_ledger: manifest.from_ledger(),
            to_ledger: manifest.to_ledger(),
            record_count: manifest.record_count(),
            entries: manifest.entries().to_vec(),
            aggregate_digest,
        };
        built.validate().map_err(|e| {
            EvidenceError::InvalidContent(format!("built manifest is invalid: {e}"))
        })?;
        Ok(built)
    }

    /// Validates package-manifest invariants: schema version supported,
    /// declared record count matches the entries, and the ledger range is
    /// coherent.
    pub fn validate(&self) -> AuditResult<()> {
        if self.schema_version != EVIDENCE_MANIFEST_SCHEMA_VERSION {
            return Err(safeguard_audit_core::AuditError::UnsupportedSchema(
                format!(
                    "evidence manifest schema version {} is not supported (expected \
                 {EVIDENCE_MANIFEST_SCHEMA_VERSION})",
                    self.schema_version
                ),
            ));
        }
        if self.record_count as usize != self.entries.len() {
            return Err(safeguard_audit_core::AuditError::ValidationFailure(
                format!(
                    "evidence manifest declares {} records but carries {}",
                    self.record_count,
                    self.entries.len()
                ),
            ));
        }
        if let (Some(from), Some(to)) = (self.from_ledger, self.to_ledger) {
            if from > to {
                return Err(safeguard_audit_core::AuditError::ValidationFailure(
                    "evidence manifest ledger range start exceeds its end".into(),
                ));
            }
        }
        Ok(())
    }

    /// The manifest id.
    pub fn manifest_id(&self) -> &ManifestId {
        &self.manifest_id
    }

    /// The artifact this manifest certifies.
    pub fn artifact(&self) -> &EvidenceId {
        &self.artifact
    }

    /// The manifest schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// When the manifest was generated.
    pub fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    /// The generating software version.
    pub fn software_version(&self) -> &str {
        &self.software_version
    }

    /// The parser version behind the source records.
    pub fn parser_version(&self) -> &VersionLabel {
        &self.parser_version
    }

    /// The network of the covered records.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The first covered ledger, when ledger-bounded.
    pub fn from_ledger(&self) -> Option<i64> {
        self.from_ledger
    }

    /// The last covered ledger, when ledger-bounded.
    pub fn to_ledger(&self) -> Option<i64> {
        self.to_ledger
    }

    /// The declared number of covered records.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// The per-record entries.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// The aggregate digest over the entries.
    pub fn aggregate_digest(&self) -> &IntegrityDigest {
        &self.aggregate_digest
    }
}

/// A complete evidence package: artifact plus its integrity manifest.
///
/// Construction validates the cross-links — the manifest must name the
/// artifact, and the artifact's manifest slot must name the manifest — so
/// a mismatched pair can never be assembled accidentally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePackage {
    artifact: EvidenceArtifact,
    manifest: EvidenceManifest,
}

impl EvidencePackage {
    /// Assembles a package, validating the artifact/manifest cross-links.
    pub fn new(artifact: EvidenceArtifact, manifest: EvidenceManifest) -> EvidenceResult<Self> {
        if manifest.artifact() != artifact.evidence_id() {
            return Err(EvidenceError::InvalidContent(format!(
                "manifest certifies artifact {} but the package carries {}",
                manifest.artifact(),
                artifact.evidence_id()
            )));
        }
        if let Some(manifest_id) = artifact.manifest_id() {
            if manifest_id != manifest.manifest_id() {
                return Err(EvidenceError::InvalidContent(format!(
                    "artifact names manifest {} but the package carries {}",
                    manifest_id,
                    manifest.manifest_id()
                )));
            }
        }
        artifact.validate().map_err(EvidenceError::from_core)?;
        manifest.validate().map_err(EvidenceError::from_core)?;
        Ok(Self { artifact, manifest })
    }

    /// The artifact.
    pub fn artifact(&self) -> &EvidenceArtifact {
        &self.artifact
    }

    /// The integrity manifest.
    pub fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }
}

#[cfg(test)]
impl EvidencePackage {
    /// Test-only convenience: validates both halves of a deserialized
    /// package (serde construction bypasses [`EvidencePackage::new`]).
    fn validate_package(&self) -> EvidenceResult<()> {
        self.artifact.validate().map_err(EvidenceError::from_core)?;
        self.manifest.validate().map_err(EvidenceError::from_core)?;
        Ok(())
    }

    pub(crate) fn with_artifact_for_test(mut self, artifact: EvidenceArtifact) -> Self {
        self.artifact = artifact;
        self
    }

    pub(crate) fn with_manifest_for_test(mut self, manifest: EvidenceManifest) -> Self {
        self.manifest = manifest;
        self
    }
}

#[cfg(test)]
impl EvidenceManifest {
    /// Test-only: replaces the entries of an otherwise-valid manifest to
    /// simulate a tampered inventory.
    pub(crate) fn from_entries_for_test(
        original: EvidenceManifest,
        entries: Vec<ManifestEntry>,
    ) -> Self {
        Self {
            entries,
            ..original
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{AuditorId, EvidenceKind, EvidenceProvenance, RecordId};

    fn integrity_manifest() -> IntegrityManifest {
        let digest = IntegrityDigest::sha256("ab".repeat(32)).unwrap();
        let entry = ManifestEntry::new(RecordId::derive(&["r1"]), digest.clone());
        IntegrityManifest::new(
            ManifestId::derive(&["m1"]),
            Timestamp::from_unix_seconds(1000),
            "0.3.0",
            Some(10),
            Some(20),
            vec![entry],
            Some(digest),
        )
    }

    fn artifact(evidence: &str) -> EvidenceArtifact {
        let provenance = EvidenceProvenance::new(
            vec![RecordId::derive(&["r1"])],
            vec![],
            VersionLabel::new("1.0.0").unwrap(),
            VersionLabel::new("0.3.0").unwrap(),
        )
        .unwrap();
        EvidenceArtifact::new(
            EvidenceId::derive(&[evidence]),
            EvidenceKind::TransactionEvidence,
            provenance,
            Timestamp::from_unix_seconds(1000),
            Some(AuditorId::derive(&["aud-1"])),
        )
    }

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn lifting_an_integrity_manifest_carries_counts_and_range() {
        let manifest = EvidenceManifest::from_integrity_manifest(
            integrity_manifest(),
            EvidenceId::derive(&["e1"]),
            VersionLabel::new("1.0.0").unwrap(),
            network(),
        )
        .unwrap();
        assert_eq!(manifest.record_count(), 1);
        assert_eq!(manifest.from_ledger(), Some(10));
        assert_eq!(manifest.to_ledger(), Some(20));
        assert_eq!(manifest.network().as_str(), "testnet");
        assert_eq!(
            manifest.artifact().as_str(),
            EvidenceId::derive(&["e1"]).as_str()
        );
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn packages_validate_cross_links() {
        let im = integrity_manifest();
        let manifest = EvidenceManifest::from_integrity_manifest(
            im.clone(),
            EvidenceId::derive(&["e1"]),
            VersionLabel::new("1.0.0").unwrap(),
            network(),
        )
        .unwrap();
        let sealed = artifact("e1").with_manifest(manifest.manifest_id().clone());
        assert!(EvidencePackage::new(sealed, manifest.clone()).is_ok());

        // A manifest certifying a different artifact must be rejected.
        let wrong = EvidenceManifest::from_integrity_manifest(
            im,
            EvidenceId::derive(&["other"]),
            VersionLabel::new("1.0.0").unwrap(),
            network(),
        )
        .unwrap();
        assert!(EvidencePackage::new(artifact("e1"), wrong).is_err());
    }

    #[test]
    fn packages_round_trip_serde() {
        let manifest = EvidenceManifest::from_integrity_manifest(
            integrity_manifest(),
            EvidenceId::derive(&["e1"]),
            VersionLabel::new("1.0.0").unwrap(),
            network(),
        )
        .unwrap();
        let artifact = artifact("e1").with_manifest(manifest.manifest_id().clone());
        let package = EvidencePackage::new(artifact, manifest).unwrap();
        let json = serde_json::to_string(&package).unwrap();
        let back: EvidencePackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, package);
        assert!(back.validate_package().is_ok());
    }
}
