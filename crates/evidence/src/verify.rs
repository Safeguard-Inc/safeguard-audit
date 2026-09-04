//! Verifying evidence packages.
//!
//! A package can be checked at two depths:
//!
//! * **structure** ([`verify_package_structure`]) — no store access: the
//!   artifact's content digest is recomputed from its canonical bytes and
//!   compared to the stored digest, and the manifest's aggregate digest is
//!   recomputed over its entries. This is what an *exported* package can
//!   be checked against without the generating system.
//! * **records** ([`verify_package`]) — with store access, every
//!   per-record digest in the manifest is also recomputed from the record
//!   bodies fetched out of the audit store, so the manifest can be trusted
//!   to certify the records it names.
//!
//! All checks reuse the integrity crate's primitives; nothing here
//! re-implements hashing.

use safeguard_audit_core::{IntegrityStatus, VerificationOutcome};
use safeguard_audit_integrity::{hash_bytes, verify_manifest_aggregate, verify_manifest_records};
use safeguard_audit_storage::EventStore;

use crate::errors::{EvidenceError, EvidenceResult};
use crate::model::EvidencePackage;

/// Machine-readable result of verifying an evidence package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceVerification {
    /// Whether the artifact's content digest matched its recomputation.
    artifact_verified: bool,
    /// The manifest aggregate outcome.
    aggregate: IntegrityStatus,
    /// Per-record outcomes (store-backed verification only).
    records: Vec<VerificationOutcome>,
    /// Whether every check passed.
    verified: bool,
}

impl EvidenceVerification {
    /// Whether the whole package verified.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Whether the artifact content is intact.
    pub fn artifact_verified(&self) -> bool {
        self.artifact_verified
    }

    /// The manifest aggregate outcome.
    pub fn aggregate(&self) -> IntegrityStatus {
        self.aggregate
    }

    /// Per-record outcomes (empty for structure-only verification).
    pub fn records(&self) -> &[VerificationOutcome] {
        &self.records
    }
}

/// A compact summary for logging and vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceVerificationSummary {
    artifact: bool,
    aggregate: bool,
    records: bool,
    verified: bool,
}

impl EvidenceVerificationSummary {
    /// Whether the whole package verified.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Whether the artifact content verified.
    pub fn artifact(&self) -> bool {
        self.artifact
    }

    /// Whether the manifest aggregate verified.
    pub fn aggregate(&self) -> bool {
        self.aggregate
    }

    /// Whether every per-record digest verified.
    pub fn records(&self) -> bool {
        self.records
    }
}

impl From<&EvidenceVerification> for EvidenceVerificationSummary {
    fn from(v: &EvidenceVerification) -> Self {
        let records_ok =
            !v.records.is_empty() && v.records.iter().all(|o| o.status().is_verified());
        Self {
            artifact: v.artifact_verified,
            aggregate: v.aggregate.is_verified(),
            records: records_ok,
            verified: v.verified,
        }
    }
}

/// Verifies a package without store access: artifact content digest and
/// manifest aggregate. Per-record digests cannot be checked here (they
/// need the record bodies) and are reported as unchecked.
pub fn verify_package_structure(package: &EvidencePackage) -> EvidenceResult<EvidenceVerification> {
    let artifact = package.artifact();
    artifact.validate().map_err(EvidenceError::from_core)?;

    let artifact_verified = match artifact.digest() {
        Some(digest) => {
            let bytes = artifact
                .canonical_bytes()
                .map_err(EvidenceError::from_core)?;
            let recomputed = hash_bytes(&bytes);
            recomputed == *digest
        }
        None => false,
    };

    let aggregate = verify_manifest_aggregate(&core_manifest(package)?)
        .map_err(EvidenceError::from_integrity)?;

    let verified = artifact_verified && aggregate.is_verified();
    Ok(EvidenceVerification {
        artifact_verified,
        aggregate,
        records: Vec::new(),
        verified,
    })
}

/// Verifies a package with store access: the structure checks plus every
/// per-record manifest digest recomputed from the stored record bodies.
pub fn verify_package(
    package: &EvidencePackage,
    audit: &dyn EventStore,
) -> EvidenceResult<EvidenceVerification> {
    let mut structure = verify_package_structure(package)?;

    let core = core_manifest(package)?;
    let records: Vec<_> = core
        .entries()
        .iter()
        .filter_map(|entry| audit.get(entry.record_id()).ok())
        .collect();
    let outcomes =
        verify_manifest_records(&core, &records).map_err(EvidenceError::from_integrity)?;

    let records_ok = outcomes.iter().all(|o| o.status().is_verified());
    structure.records = outcomes;
    structure.verified =
        structure.artifact_verified && structure.aggregate.is_verified() && records_ok;
    Ok(structure)
}

/// Reconstructs the core integrity-manifest view of the package manifest
/// so the integrity crate's verification primitives apply unchanged.
fn core_manifest(
    package: &EvidencePackage,
) -> EvidenceResult<safeguard_audit_core::IntegrityManifest> {
    let manifest = package.manifest();
    let core = safeguard_audit_core::IntegrityManifest::new(
        manifest.manifest_id().clone(),
        manifest.generated_at(),
        manifest.software_version(),
        manifest.from_ledger(),
        manifest.to_ledger(),
        manifest.entries().to_vec(),
        Some(manifest.aggregate_digest().clone()),
    );
    core.validate().map_err(EvidenceError::from_core)?;
    Ok(core)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests as builder_tests;
    use crate::builder::{EvidenceBuildOptions, EvidenceBuilder};
    use crate::model::EvidenceManifest;
    use safeguard_audit_core::{
        AuditorId, EvidenceKind, FixedClock, IntegrityDigest, ManifestEntry, NetworkId, RecordId,
        Timestamp, VersionLabel,
    };

    fn net() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn seeded_package(
        seeds: &[&str],
    ) -> (
        safeguard_audit_memory_store::MemoryEventStore,
        EvidencePackage,
    ) {
        let actor = AuditorId::derive(&["aud-1"]);
        let mut store = builder_tests::seeded_store(seeds);
        let builder = EvidenceBuilder::new(
            net(),
            crate::SOURCE_LABEL,
            VersionLabel::new("1.0.0").unwrap(),
            VersionLabel::new("0.3.0").unwrap(),
            FixedClock::at(Timestamp::from_unix_seconds(200)),
            builder_tests::authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor),
        );
        let ids: Vec<RecordId> = store
            .query(
                &safeguard_audit_storage::AuditQuery::builder()
                    .build()
                    .unwrap(),
                &safeguard_audit_core::PageRequest::new(seeds.len()).unwrap(),
            )
            .unwrap()
            .items()
            .iter()
            .map(|r| r.record_id.clone())
            .collect();
        let options =
            EvidenceBuildOptions::new(EvidenceKind::TransactionEvidence, ids, actor).unwrap();
        let package = builder.build(&mut store, &options).unwrap();
        (store, package)
    }

    #[test]
    fn freshly_built_packages_verify() {
        let (store, package) = seeded_package(&["a", "b"]);
        let structure = verify_package_structure(&package).unwrap();
        assert!(structure.verified());
        assert!(structure.artifact_verified());
        assert!(structure.aggregate().is_verified());
        let full = verify_package(&package, &store).unwrap();
        assert!(full.verified());
        assert_eq!(full.records().len(), 2);
        assert!(full.records().iter().all(|o| o.status().is_verified()));
    }

    #[test]
    fn missing_store_records_fail_verification() {
        let (_, package) = seeded_package(&["a"]);
        let empty = safeguard_audit_memory_store::MemoryEventStore::new();
        let full = verify_package(&package, &empty).unwrap();
        assert!(!full.verified());
        assert!(full
            .records()
            .iter()
            .any(|o| o.status() == IntegrityStatus::RecordMissing));
    }

    #[test]
    fn structure_only_verification_leaves_records_unchecked() {
        let (_, package) = seeded_package(&["a"]);
        let structure = verify_package_structure(&package).unwrap();
        assert!(structure.verified());
        assert!(structure.records().is_empty());
    }

    #[test]
    fn a_tampered_artifact_digest_fails_structure_verification() {
        let (store, package) = seeded_package(&["a"]);
        let tampered = package.clone().with_artifact_for_test(
            package
                .artifact()
                .clone()
                .with_digest(IntegrityDigest::sha256("ee".repeat(32)).unwrap()),
        );
        let structure = verify_package_structure(&tampered).unwrap();
        assert!(!structure.artifact_verified());
        assert!(!structure.verified());
        let full = verify_package(&tampered, &store).unwrap();
        assert!(!full.verified());
    }

    #[test]
    fn a_tampered_manifest_entry_fails_record_verification() {
        let (store, package) = seeded_package(&["a", "b"]);
        let manifest = package.manifest().clone();
        let mut entries = manifest.entries().to_vec();
        entries[1] = ManifestEntry::new(
            entries[1].record_id().clone(),
            IntegrityDigest::sha256("dd".repeat(32)).unwrap(),
        );
        let tampered = package
            .clone()
            .with_manifest_for_test(EvidenceManifest::from_entries_for_test(manifest, entries));
        let full = verify_package(&tampered, &store).unwrap();
        assert!(!full.records().iter().all(|o| o.status().is_verified()));
        assert!(!full.verified());
    }
}
