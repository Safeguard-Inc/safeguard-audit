//! Standalone record digests.
//!
//! The `standalone` scheme hashes each record in isolation: the digest
//! covers the canonical record and nothing else. It detects alteration of
//! a single record but not reordering or wholesale replacement of
//! records; the `chained` scheme in [`crate::chain`] adds those
//! guarantees. Both share the same canonical input and SHA-256 primitive.

use safeguard_audit_core::AuditRecord;

use crate::errors::IntegrityResult;
use crate::hashing::{canonical_record_input, hash_bytes};

/// Computes the standalone digest for `record`.
pub fn record_digest(
    record: &AuditRecord,
) -> IntegrityResult<safeguard_audit_core::IntegrityDigest> {
    Ok(hash_bytes(&canonical_record_input(record)?))
}

/// Attaches a standalone integrity block to `record` (its digest, no
/// predecessor, `chained: false`).
pub fn seal_standalone(record: &AuditRecord) -> IntegrityResult<safeguard_audit_core::AuditRecord> {
    let digest = record_digest(record)?;
    let mut sealed = record.clone();
    sealed.integrity = Some(safeguard_audit_core::RecordIntegrity {
        digest,
        prev_digest: None,
        chained: false,
    });
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditEvent, AuditRecord, EventKind, EventProvenance, FixedClock, IntegrityScheme,
        NetworkId, OriginKind, Timestamp, VersionLabel,
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
    fn standalone_digests_are_deterministic() {
        let r = record("x");
        assert_eq!(record_digest(&r).unwrap(), record_digest(&r).unwrap());
    }

    #[test]
    fn sealing_attaches_a_standalone_integrity_block() {
        let sealed = seal_standalone(&record("x")).unwrap();
        let integrity = sealed
            .integrity
            .as_ref()
            .expect("sealed record carries integrity");
        assert!(!integrity.chained);
        assert!(integrity.prev_digest.is_none());
        // The digest covers the record without its own integrity block.
        assert_eq!(integrity.digest, record_digest(&sealed).unwrap());
        assert_eq!(IntegrityScheme::Standalone.as_str(), "standalone");
    }
}
