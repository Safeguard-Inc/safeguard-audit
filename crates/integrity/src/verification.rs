//! Verification: recompute, compare, report.
//!
//! Verification never trusts stored digests — it recomputes from the
//! canonical record body and compares. Results are machine-readable
//! [`VerificationOutcome`]s or whole-chain [`VerificationFailure`]s so
//! automation can react to tampering without parsing prose.
//!
//! A digest mismatch is a *result*, not an error: verification functions
//! report it in the outcome vocabulary instead of failing the call.

use safeguard_audit_core::{
    AuditRecord, IntegrityDigest, IntegrityManifest, IntegrityStatus, VerificationOutcome,
};

use crate::digest::record_digest;
use crate::errors::IntegrityResult;

/// Verifies one record's stored digest against a fresh recomputation.
///
/// Records without an integrity block report [`IntegrityStatus::MissingDigest`]
/// rather than failing, and digests under an algorithm this build does not
/// implement report [`IntegrityStatus::UnsupportedAlgorithm`].
pub fn verify_record(record: &AuditRecord) -> IntegrityResult<VerificationOutcome> {
    let Some(integrity) = &record.integrity else {
        return Ok(VerificationOutcome::new(
            record.record_id.clone(),
            IntegrityStatus::MissingDigest,
            None,
            None,
            Some("record carries no integrity block".to_owned()),
        ));
    };
    let expected = Some(integrity.digest.value().to_owned());
    if integrity.digest.algorithm() != IntegrityDigest::SHA256 {
        return Ok(VerificationOutcome::new(
            record.record_id.clone(),
            IntegrityStatus::UnsupportedAlgorithm,
            expected,
            None,
            Some(format!(
                "algorithm `{}` is not implemented",
                integrity.digest.algorithm()
            )),
        ));
    }

    let recomputed = record_digest(record)?;
    if recomputed == integrity.digest {
        Ok(VerificationOutcome::new(
            record.record_id.clone(),
            IntegrityStatus::Verified,
            expected,
            Some(recomputed.value().to_owned()),
            None,
        ))
    } else {
        Ok(VerificationOutcome::new(
            record.record_id.clone(),
            IntegrityStatus::DigestMismatch,
            expected,
            Some(recomputed.value().to_owned()),
            Some("record digest does not recompute from its content".to_owned()),
        ))
    }
}

/// Verifies a whole history under whichever scheme its records use.
///
/// When any record is flagged `chained`, the slice is verified as one
/// chain (flags are validated by the chain walker); otherwise every record
/// is verified standalone. Returns one outcome per record; a chain failure
/// surfaces as a single outcome naming the record where it broke.
pub fn verify_all(records: &[AuditRecord]) -> IntegrityResult<Vec<VerificationOutcome>> {
    let any_chained = records
        .iter()
        .any(|r| r.integrity.as_ref().is_some_and(|i| i.chained));
    if any_chained {
        match crate::chain::verify_chain(records) {
            Ok(()) => Ok(Vec::new()),
            Err(failure) => {
                let record_id = failure
                    .record_id()
                    .cloned()
                    .unwrap_or_else(|| safeguard_audit_core::RecordId::derive(&["unknown"]));
                Ok(vec![VerificationOutcome::new(
                    record_id,
                    failure.status(),
                    None,
                    None,
                    Some(failure.detail().to_owned()),
                )])
            }
        }
    } else {
        let mut outcomes = Vec::with_capacity(records.len());
        for record in records {
            outcomes.push(verify_record(record)?);
        }
        Ok(outcomes)
    }
}

/// Verifies the digest inventory of a manifest against the supplied
/// records (the records the manifest claims to cover).
///
/// Every manifest entry must find its record; each record's digest is
/// recomputed and compared to the entry. A record that is not in the
/// supplied set reports [`IntegrityStatus::RecordMissing`].
pub fn verify_manifest_records(
    manifest: &IntegrityManifest,
    records: &[AuditRecord],
) -> IntegrityResult<Vec<VerificationOutcome>> {
    let mut by_id = std::collections::HashMap::new();
    for record in records {
        by_id.insert(record.record_id.clone(), record);
    }

    let mut outcomes = Vec::with_capacity(manifest.entries().len());
    for entry in manifest.entries() {
        let digest = entry.digest();
        match by_id.get(entry.record_id()) {
            None => outcomes.push(VerificationOutcome::new(
                entry.record_id().clone(),
                IntegrityStatus::RecordMissing,
                Some(digest.value().to_owned()),
                None,
                Some("record is not in the supplied set".to_owned()),
            )),
            Some(record) => {
                let recomputed = record_digest(record)?;
                if recomputed == *digest {
                    outcomes.push(VerificationOutcome::new(
                        entry.record_id().clone(),
                        IntegrityStatus::Verified,
                        Some(digest.value().to_owned()),
                        Some(recomputed.value().to_owned()),
                        None,
                    ));
                } else {
                    outcomes.push(VerificationOutcome::new(
                        entry.record_id().clone(),
                        IntegrityStatus::DigestMismatch,
                        Some(digest.value().to_owned()),
                        Some(recomputed.value().to_owned()),
                        Some("record body no longer matches the manifest entry".to_owned()),
                    ));
                }
            }
        }
    }
    Ok(outcomes)
}

/// Verifies the manifest's aggregate digest against its own entries.
///
/// A changed entry (replaced, removed, or added) changes the aggregate,
/// so this detects tampering with the *inventory itself*.
pub fn verify_manifest_aggregate(manifest: &IntegrityManifest) -> IntegrityResult<IntegrityStatus> {
    let Some(aggregate) = manifest.aggregate_digest() else {
        return Ok(IntegrityStatus::MissingDigest);
    };
    if aggregate.algorithm() != IntegrityDigest::SHA256 {
        return Ok(IntegrityStatus::UnsupportedAlgorithm);
    }
    let recomputed = crate::manifest::aggregate_hex(manifest.entries())?;
    if recomputed == aggregate.value() {
        Ok(IntegrityStatus::Verified)
    } else {
        Ok(IntegrityStatus::DigestMismatch)
    }
}

/// Whether every record in the slice verified (convenience over
/// [`verify_all`]).
pub fn all_verified(records: &[AuditRecord]) -> IntegrityResult<bool> {
    Ok(verify_all(records)?
        .iter()
        .all(|o| o.status() == IntegrityStatus::Verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::seal_chain;
    use crate::digest::seal_standalone;
    use crate::manifest::{build_manifest, ManifestOptions};
    use safeguard_audit_core::{
        AuditEvent, AuditRecord, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind,
        Timestamp, VersionLabel,
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
        AuditRecord::from_event(event, &FixedClock::at(Timestamp::from_unix_seconds(100))).unwrap()
    }

    #[test]
    fn unsealed_records_report_missing_digest() {
        let outcome = verify_record(&record("a")).unwrap();
        assert_eq!(outcome.status(), IntegrityStatus::MissingDigest);
    }

    #[test]
    fn sealed_records_verify() {
        let sealed = seal_standalone(&record("a")).unwrap();
        let outcome = verify_record(&sealed).unwrap();
        assert_eq!(outcome.status(), IntegrityStatus::Verified);
        assert_eq!(outcome.expected().unwrap(), outcome.computed().unwrap());
    }

    #[test]
    fn tampered_records_report_digest_mismatch() {
        let mut sealed = seal_chain(&[record("a"), record("b")]).unwrap();
        sealed[1].recorded_at = Timestamp::from_unix_seconds(1234);
        let outcomes = verify_all(&sealed).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status(), IntegrityStatus::DigestMismatch);
        assert_eq!(outcomes[0].record_id(), &sealed[1].record_id);
    }

    #[test]
    fn intact_chains_report_no_failures() {
        let sealed = seal_chain(&[record("a"), record("b"), record("c")]).unwrap();
        assert!(verify_all(&sealed).unwrap().is_empty());
        assert!(all_verified(&sealed).unwrap());
    }

    #[test]
    fn manifest_verification_catches_altered_and_missing_records() {
        let records = seal_chain(&[record("a"), record("b"), record("c")]).unwrap();
        let manifest = build_manifest(
            &records,
            &ManifestOptions::new(Some(1), Some(3), "0.1.0").unwrap(),
            Timestamp::from_unix_seconds(200),
        )
        .unwrap();

        // Supplied set intact: everything verifies, aggregate verifies.
        let outcomes = verify_manifest_records(&manifest, &records).unwrap();
        assert!(outcomes
            .iter()
            .all(|o| o.status() == IntegrityStatus::Verified));
        assert_eq!(
            verify_manifest_aggregate(&manifest).unwrap(),
            IntegrityStatus::Verified
        );

        // Altered body: its entry no longer recomputes.
        let mut altered = records.clone();
        altered[1].recorded_at = Timestamp::from_unix_seconds(999);
        let outcomes = verify_manifest_records(&manifest, &altered).unwrap();
        assert_eq!(outcomes[1].status(), IntegrityStatus::DigestMismatch);

        // Missing record from the supplied set.
        let truncated = vec![records[0].clone(), records[2].clone()];
        let outcomes = verify_manifest_records(&manifest, &truncated).unwrap();
        assert_eq!(outcomes[1].status(), IntegrityStatus::RecordMissing);

        // Tampered inventory: swap an entry's digest through the wire
        // layer (the model is read-only), aggregate must break.
        let json = serde_json::to_string(&manifest).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["entries"][0]["digest"]["value"] = serde_json::json!("f".repeat(64));
        let tampered: IntegrityManifest = serde_json::from_value(value).unwrap();
        assert_eq!(
            verify_manifest_aggregate(&tampered).unwrap(),
            IntegrityStatus::DigestMismatch
        );
    }
}
