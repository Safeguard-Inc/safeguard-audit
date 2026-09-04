//! Integrity manifest generation.
//!
//! A manifest is the digest inventory of a record range, evidence
//! package, or export: one entry per record with a digest *recomputed*
//! from the record body (never copied from the record's stored integrity
//! block, so a forged stored digest cannot bless altered content), plus
//! an aggregate digest over the manifest's own entries so the inventory
//! itself is tamper-evident.
//!
//! Generation is deterministic for the same ordered records and options:
//! same entries, same aggregate, same manifest id. The manifest id is
//! derived from the generation parameters and the aggregate, so two
//! manifests over the same range agree and any difference is visible.

use safeguard_audit_core::{
    AuditRecord, IntegrityDigest, IntegrityManifest, ManifestEntry, ManifestId, Timestamp,
    VersionLabel,
};

use crate::digest::record_digest;
use crate::errors::{IntegrityError, IntegrityResult};

/// Options that shape a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestOptions {
    /// First ledger covered, when the range is ledger-bounded.
    pub from_ledger: Option<i64>,
    /// Last ledger covered, when the range is ledger-bounded.
    pub to_ledger: Option<i64>,
    /// Software version that generated the manifest (reproducibility).
    pub software_version: String,
}

impl ManifestOptions {
    /// Builds options, validating the ledger range and software label.
    pub fn new(
        from_ledger: Option<i64>,
        to_ledger: Option<i64>,
        software_version: impl Into<String>,
    ) -> IntegrityResult<Self> {
        let software_version = software_version.into();
        if let (Some(from), Some(to)) = (from_ledger, to_ledger) {
            if from > to {
                return Err(IntegrityError::InvalidArguments(format!(
                    "manifest ledger range {from}..{to} is inverted"
                )));
            }
        }
        // The core model keeps the label as a string; reuse the version
        // vocabulary's shape rules so labels stay URL- and manifest-safe.
        VersionLabel::new(&software_version)
            .map_err(|e| IntegrityError::InvalidArguments(format!("software version: {e}")))?;
        Ok(Self {
            from_ledger,
            to_ledger,
            software_version,
        })
    }
}

/// The canonical bytes a manifest's aggregate digest covers: the entries
/// in order, serialized canonically.
fn aggregate_input(entries: &[ManifestEntry]) -> IntegrityResult<Vec<u8>> {
    serde_json::to_vec(entries)
        .map_err(|e| IntegrityError::Canonicalization("manifest entries".into(), e.to_string()))
}

/// The hex aggregate digest over the canonical entries (shared with the
/// verification module so recomputation always matches generation). The
/// aggregate is SHA-256 over the canonical entry bytes — hashing the
/// inventory, not merely hex-encoding it.
pub(crate) fn aggregate_hex(entries: &[ManifestEntry]) -> IntegrityResult<String> {
    Ok(crate::hashing::hash_bytes(&aggregate_input(entries)?)
        .value()
        .to_owned())
}

/// Builds a manifest over `records` (already in history order) sealed at
/// `generated_at`.
///
/// Every record's digest is recomputed from its canonical body. Records
/// must carry distinct ids; a manifest over duplicate identities is a
/// caller bug, not a manifest.
pub fn build_manifest(
    records: &[AuditRecord],
    options: &ManifestOptions,
    generated_at: Timestamp,
) -> IntegrityResult<IntegrityManifest> {
    let mut entries = Vec::with_capacity(records.len());
    let mut seen = std::collections::HashSet::new();
    for record in records {
        if !seen.insert(record.record_id.clone()) {
            return Err(IntegrityError::InvalidArguments(format!(
                "duplicate record id {} in manifest range",
                record.record_id
            )));
        }
        let digest = record_digest(record)?;
        entries.push(ManifestEntry::new(record.record_id.clone(), digest));
    }

    let aggregate = IntegrityDigest::sha256(aggregate_hex(&entries)?)
        .map_err(|e| IntegrityError::Canonicalization("aggregate digest".into(), e.to_string()))?;

    // Deterministic identity: generation parameters plus the aggregate.
    let parts: [String; 5] = [
        options.software_version.clone(),
        options
            .from_ledger
            .map(|l| l.to_string())
            .unwrap_or_else(|| "start".into()),
        options
            .to_ledger
            .map(|l| l.to_string())
            .unwrap_or_else(|| "end".into()),
        records.len().to_string(),
        aggregate.value().to_owned(),
    ];
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    let manifest_id = ManifestId::derive(&refs);

    let manifest = IntegrityManifest::new(
        manifest_id,
        generated_at,
        &options.software_version,
        options.from_ledger,
        options.to_ledger,
        entries,
        Some(aggregate),
    );
    manifest
        .validate()
        .map_err(|e| IntegrityError::InvalidArguments(format!("built manifest is invalid: {e}")))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::seal_chain;
    use safeguard_audit_core::{
        AuditEvent, AuditRecord, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind,
    };

    fn record(seed: &str) -> AuditRecord {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap())
                .unwrap();
        let event = AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[seed]),
            EventKind::AccountFrozen,
            network,
            provenance,
        );
        AuditRecord::from_event(
            event,
            &FixedClock::at(safeguard_audit_core::Timestamp::from_unix_seconds(100)),
        )
        .unwrap()
    }

    fn options() -> ManifestOptions {
        ManifestOptions::new(Some(100), Some(102), "0.1.0").unwrap()
    }

    #[test]
    fn manifests_are_deterministic_over_the_same_range() {
        let records = seal_chain(&[record("a"), record("b"), record("c")]).unwrap();
        let at = Timestamp::from_unix_seconds(200);
        let m1 = build_manifest(&records, &options(), at).unwrap();
        let m2 = build_manifest(&records, &options(), at).unwrap();
        assert_eq!(m1, m2);
        assert_eq!(m1.manifest_id(), m2.manifest_id());
        assert_eq!(m1.record_count() as usize, 3);
        assert_eq!(m1.entries().len(), 3);
        assert!(m1.validate().is_ok());
    }

    #[test]
    fn entries_recompute_digests_from_record_bodies() {
        let records = seal_chain(&[record("a"), record("b")]).unwrap();
        let manifest =
            build_manifest(&records, &options(), Timestamp::from_unix_seconds(200)).unwrap();
        for (entry, record) in manifest.entries().iter().zip(&records) {
            assert_eq!(entry.record_id(), &record.record_id);
            assert_eq!(entry.digest(), &record_digest(record).unwrap());
        }
        // A manifest digest never equals the record's stored chain digest:
        // it is an independent recomputation, not a copy of the stored
        // integrity block.
        assert_ne!(
            manifest.entries()[1].digest(),
            &records[1].integrity.as_ref().unwrap().digest
        );
    }

    #[test]
    fn options_validate_range_and_label() {
        assert!(ManifestOptions::new(Some(5), Some(1), "0.1.0").is_err());
        assert!(ManifestOptions::new(None, None, "").is_err());
        assert!(ManifestOptions::new(Some(1), Some(5), "0.1.0").is_ok());
    }

    #[test]
    fn duplicate_record_ids_are_rejected() {
        let r = record("a");
        let dup = vec![r.clone(), r];
        assert!(build_manifest(&dup, &options(), Timestamp::from_unix_seconds(1)).is_err());
    }

    #[test]
    fn ledger_range_carries_through() {
        let records = vec![record("a")];
        let manifest = build_manifest(
            &records,
            &ManifestOptions::new(Some(10), Some(20), "0.1.0").unwrap(),
            Timestamp::from_unix_seconds(1),
        )
        .unwrap();
        assert_eq!(manifest.from_ledger(), Some(10));
        assert_eq!(manifest.to_ledger(), Some(20));
    }
}
