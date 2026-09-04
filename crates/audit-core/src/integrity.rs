//! Integrity domain models.
//!
//! Audit history must be *tamper-evident*: an investigator has to be able to
//! tell whether a record, an evidence package, or an export was altered
//! after it was written. This module holds the persisted vocabulary —
//! digests, schemes, verification outcomes, and manifests. The actual
//! hashing/verification *implementation* lives in the integrity crate;
//! nothing here computes a hash.
//!
//! ## Honest limits
//!
//! Chained digests over locally stored records make tampering *detectable*;
//! they do not create blockchain-level immutability on their own. The
//! system distinguishes on-chain source integrity (anchored by the ledger),
//! local record integrity (this module), and export integrity (manifests
//! shipped with evidence packages). Each is verified with the tools
//! appropriate to it, and the docs never claim otherwise.

use serde::{Deserialize, Serialize};

use crate::audit::RECORD_SCHEMA_VERSION;
use crate::errors::{AuditError, AuditResult};
use crate::identifiers::{ManifestId, RecordId};
use crate::timestamps::Timestamp;

/// The digest of a canonical record: an algorithm label plus the hex value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntegrityDigest {
    /// Algorithm label, currently always `sha-256`.
    algorithm: String,
    /// 64 lowercase hex characters.
    value: String,
}

impl IntegrityDigest {
    /// The SHA-256 algorithm label used in wire formats.
    pub const SHA256: &'static str = "sha-256";

    /// Builds a digest, validating the hex shape (64 lowercase hex chars).
    pub fn sha256(value: impl Into<String>) -> AuditResult<Self> {
        let value = value.into();
        let valid = value.len() == 64
            && value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if !valid {
            return Err(AuditError::invalid_identifier(
                "integrity digest",
                "must be 64 lowercase hex chars",
            ));
        }
        Ok(Self {
            algorithm: Self::SHA256.to_owned(),
            value,
        })
    }

    /// The algorithm label.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The digest hex value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// How record digests relate to each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityScheme {
    /// Each record's digest covers only that record.
    Standalone,
    /// Each record's digest covers the previous digest plus the record, so
    /// history forms a chain.
    Chained,
}

impl IntegrityScheme {
    /// The stable label for this scheme.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Chained => "chained",
        }
    }
}

/// The result of verifying a record or chain against its digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityStatus {
    /// The digest matched the recomputed value.
    Verified,
    /// The stored digest differs from the recomputed value (tampering or
    /// corruption).
    DigestMismatch,
    /// The record carries no digest to verify against.
    MissingDigest,
    /// A record in a chain is missing, so the chain cannot verify.
    BrokenChain,
    /// The digest uses an algorithm this build does not implement.
    UnsupportedAlgorithm,
    /// The record does not exist in the store.
    RecordMissing,
}

impl IntegrityStatus {
    /// The stable label for this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::DigestMismatch => "digest-mismatch",
            Self::MissingDigest => "missing-digest",
            Self::BrokenChain => "broken-chain",
            Self::UnsupportedAlgorithm => "unsupported-algorithm",
            Self::RecordMissing => "record-missing",
        }
    }

    /// Whether verification succeeded.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// A machine-readable verification result for one record.
///
/// Every integrity failure produces one of these (or a
/// [`VerificationFailure`] for whole-chain results) so automation can react
/// to tampering without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationOutcome {
    /// Which record was verified.
    record_id: RecordId,
    /// The outcome.
    status: IntegrityStatus,
    /// The expected (stored) digest hex, when one existed.
    expected: Option<String>,
    /// The recomputed digest hex, when it could be computed.
    computed: Option<String>,
    /// Optional short human detail; never contains protected values.
    detail: Option<String>,
}

impl VerificationOutcome {
    /// Builds an outcome.
    pub fn new(
        record_id: RecordId,
        status: IntegrityStatus,
        expected: Option<String>,
        computed: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            record_id,
            status,
            expected,
            computed,
            detail,
        }
    }

    /// The verified record.
    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    /// The outcome status.
    pub fn status(&self) -> IntegrityStatus {
        self.status
    }

    /// The stored digest that was verified against.
    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }

    /// The digest recomputed during verification.
    pub fn computed(&self) -> Option<&str> {
        self.computed.as_deref()
    }

    /// Short detail, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// A whole-chain verification result: which records failed and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFailure {
    /// Human/machine summary of the failure class.
    status: IntegrityStatus,
    /// The first failing record, when a specific record failed.
    record_id: Option<RecordId>,
    /// Detail explaining the failure.
    detail: String,
}

impl VerificationFailure {
    /// Builds a failure summary.
    pub fn new(
        status: IntegrityStatus,
        record_id: Option<RecordId>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            record_id,
            detail: detail.into(),
        }
    }

    /// The failure class.
    pub fn status(&self) -> IntegrityStatus {
        self.status
    }

    /// The failing record, when identified.
    pub fn record_id(&self) -> Option<&RecordId> {
        self.record_id.as_ref()
    }

    /// The failure detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// One entry in an integrity manifest: a record and its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    record_id: RecordId,
    digest: IntegrityDigest,
}

impl ManifestEntry {
    /// Builds a manifest entry.
    pub fn new(record_id: RecordId, digest: IntegrityDigest) -> Self {
        Self { record_id, digest }
    }

    /// The record this entry covers.
    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    /// The record's digest.
    pub fn digest(&self) -> &IntegrityDigest {
        &self.digest
    }
}

/// The current schema version of the integrity manifest format.
pub const INTEGRITY_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// An integrity manifest: the digest inventory of a record range, evidence
/// package, or export.
///
/// A verifier given a manifest and the covered records can determine
/// whether anything was altered after the manifest was generated. The
/// generation logic lives in the integrity crate; this is the wire model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityManifest {
    manifest_id: ManifestId,
    schema_version: u32,
    generated_at: Timestamp,
    /// Software version that generated the manifest (for reproducibility).
    software_version: String,
    /// First ledger covered, when the range is ledger-bounded.
    from_ledger: Option<i64>,
    /// Last ledger covered, when the range is ledger-bounded.
    to_ledger: Option<i64>,
    /// Number of entries; must equal `entries.len()`.
    record_count: u64,
    entries: Vec<ManifestEntry>,
    /// Digest over the canonical manifest entries (the package aggregate).
    aggregate_digest: Option<IntegrityDigest>,
}

impl IntegrityManifest {
    /// Builds an unverified manifest with schema version and counts filled.
    pub fn new(
        manifest_id: ManifestId,
        generated_at: Timestamp,
        software_version: &str,
        from_ledger: Option<i64>,
        to_ledger: Option<i64>,
        entries: Vec<ManifestEntry>,
        aggregate_digest: Option<IntegrityDigest>,
    ) -> Self {
        let record_count = entries.len() as u64;
        Self {
            manifest_id,
            schema_version: INTEGRITY_MANIFEST_SCHEMA_VERSION,
            generated_at,
            software_version: software_version.to_owned(),
            from_ledger,
            to_ledger,
            record_count,
            entries,
            aggregate_digest,
        }
    }

    /// Validates manifest invariants: schema version supported, the ledger
    /// range is coherent, and the declared record count matches the entries.
    pub fn validate(&self) -> AuditResult<()> {
        if self.schema_version != INTEGRITY_MANIFEST_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(format!(
                "integrity manifest schema version {} is not supported (expected \
                 {INTEGRITY_MANIFEST_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if let (Some(from), Some(to)) = (self.from_ledger, self.to_ledger) {
            if from > to {
                return Err(AuditError::ValidationFailure(
                    "manifest ledger range start exceeds its end".into(),
                ));
            }
        }
        if self.record_count as usize != self.entries.len() {
            return Err(AuditError::ValidationFailure(format!(
                "manifest declares {} records but carries {}",
                self.record_count,
                self.entries.len()
            )));
        }
        Ok(())
    }

    /// The manifest id.
    pub fn manifest_id(&self) -> &ManifestId {
        &self.manifest_id
    }

    /// The first ledger covered, when the range is ledger-bounded.
    pub fn from_ledger(&self) -> Option<i64> {
        self.from_ledger
    }

    /// The last ledger covered, when the range is ledger-bounded.
    pub fn to_ledger(&self) -> Option<i64> {
        self.to_ledger
    }

    /// The declared number of covered records (equals `entries().len()`).
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// The manifest schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// When the manifest was generated.
    pub fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    /// The entries (records covered by this manifest).
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// The aggregate digest over the manifest, when computed.
    pub fn aggregate_digest(&self) -> Option<&IntegrityDigest> {
        self.aggregate_digest.as_ref()
    }
}

/// Ensures the digest/versioning vocabulary is coherent with the record
/// schema constant (kept here so integrity and record versioning cannot
/// drift silently).
pub fn supported_record_schema_version() -> u32 {
    RECORD_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> IntegrityDigest {
        IntegrityDigest::sha256(format!("{seed:02x}").repeat(32)).unwrap()
    }

    #[test]
    fn digests_validate_lowercase_hex() {
        assert!(IntegrityDigest::sha256("a".repeat(64)).is_ok());
        assert!(IntegrityDigest::sha256("A".repeat(64)).is_err());
        assert!(IntegrityDigest::sha256("z".repeat(63)).is_err());
        assert_eq!(digest(1).algorithm(), "sha-256");
    }

    #[test]
    fn status_labels_are_stable_and_verification_is_queryable() {
        assert!(IntegrityStatus::Verified.is_verified());
        assert!(!IntegrityStatus::DigestMismatch.is_verified());
        assert_eq!(IntegrityStatus::BrokenChain.as_str(), "broken-chain");
        let outcome = VerificationOutcome::new(
            RecordId::derive(&["r"]),
            IntegrityStatus::DigestMismatch,
            Some("expected".into()),
            Some("computed".into()),
            None,
        );
        assert_eq!(outcome.status(), IntegrityStatus::DigestMismatch);
        assert_eq!(outcome.expected(), Some("expected"));
    }

    #[test]
    fn schemes_have_stable_labels() {
        assert_eq!(IntegrityScheme::Standalone.as_str(), "standalone");
        assert_eq!(IntegrityScheme::Chained.as_str(), "chained");
    }

    #[test]
    fn manifests_validate_counts_and_ranges() {
        let entry = ManifestEntry::new(RecordId::derive(&["rec-1"]), digest(7));
        let manifest = IntegrityManifest::new(
            ManifestId::derive(&["m"]),
            Timestamp::from_unix_seconds(1000),
            "0.1.0",
            Some(10),
            Some(20),
            vec![entry],
            Some(digest(9)),
        );
        assert!(manifest.validate().is_ok());

        let mut broken = manifest.clone();
        broken.record_count = 99;
        assert!(broken.validate().is_err());

        let mut inverted = manifest;
        inverted.from_ledger = Some(30);
        assert!(inverted.validate().is_err());
    }

    #[test]
    fn verification_failures_are_machine_readable() {
        let failure = VerificationFailure::new(
            IntegrityStatus::BrokenChain,
            Some(RecordId::derive(&["gone"])),
            "record 5 of the chain is missing",
        );
        assert_eq!(failure.status(), IntegrityStatus::BrokenChain);
        assert_eq!(failure.detail(), "record 5 of the chain is missing");
    }
}
