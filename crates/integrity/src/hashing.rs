//! Canonical hashing primitives.
//!
//! Integrity hashing must be deterministic across processes, machines, and
//! software versions, so every hash input is derived from the same
//! canonical serialization the rest of the domain uses (stable field
//! order, sorted maps). The only supported algorithm today is SHA-256,
//! labelled `sha-256` on the wire.
//!
//! ## What a record digest covers
//!
//! A record digest covers the canonical record **without its own
//! integrity block**: the digest is computed first and the integrity block
//! (which carries that digest) is attached afterwards, so the digest never
//! hashes itself. Verification recomputes over the same integrity-cleared
//! canonical form, which is what makes the comparison meaningful.
//!
//! ## Honest limits
//!
//! These hashes make local tampering *detectable*. They are not a chain
//! anchor to the ledger and are never described as one.

use safeguard_audit_core::{AuditRecord, IntegrityDigest};
use sha2::{Digest, Sha256};

use crate::errors::{IntegrityError, IntegrityResult};

/// Lowercase-hex encodes a digest.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Hashes arbitrary bytes into a validated SHA-256 [`IntegrityDigest`].
pub fn hash_bytes(data: &[u8]) -> IntegrityDigest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    // A freshly computed digest is always 64 lowercase hex chars; the
    // validating constructor is a check, not a filter.
    IntegrityDigest::sha256(hex_lower(&digest)).expect("sha256 digest is valid hex")
}

/// The canonical bytes a record's digest is computed over: the record with
/// its own integrity block cleared, serialized with the domain's canonical
/// JSON.
pub fn canonical_record_input(record: &AuditRecord) -> IntegrityResult<Vec<u8>> {
    let mut cleared = record.clone();
    cleared.integrity = None;
    cleared
        .canonical_bytes()
        .map_err(|e| IntegrityError::Canonicalization(record.record_id.to_string(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditEvent, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind, Timestamp,
        VersionLabel,
    };

    fn event(seed: &str) -> AuditEvent {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap())
                .unwrap();
        AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[seed]),
            EventKind::AccountFrozen,
            network,
            provenance,
        )
    }

    fn record(seed: &str) -> AuditRecord {
        AuditRecord::from_event(
            event(seed),
            &FixedClock::at(Timestamp::from_unix_seconds(100)),
        )
        .unwrap()
    }

    #[test]
    fn hashes_are_valid_sha256_digests() {
        let d1 = hash_bytes(b"hello");
        let d2 = hash_bytes(b"hello");
        let d3 = hash_bytes(b"world");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
        assert_eq!(d1.algorithm(), "sha-256");
        assert_eq!(d1.value().len(), 64);
        assert!(d1.value().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn canonical_input_is_stable_and_integrity_independent() {
        let r1 = record("a");
        let a = canonical_record_input(&r1).unwrap();
        let b = canonical_record_input(&r1).unwrap();
        assert_eq!(a, b);

        // Attaching an integrity block must not change the digest input.
        let mut sealed = r1.clone();
        sealed.integrity = Some(safeguard_audit_core::RecordIntegrity {
            digest: hash_bytes(&a),
            prev_digest: None,
            chained: false,
        });
        assert_eq!(canonical_record_input(&sealed).unwrap(), a);
    }

    #[test]
    fn digest_changes_when_the_record_changes() {
        let r1 = record("a");
        let mut r2 = record("a");
        r2.recorded_at = Timestamp::from_unix_seconds(101);
        // recorded_at is part of the record body, so digests differ.
        let a = hash_bytes(&canonical_record_input(&r1).unwrap());
        let b = hash_bytes(&canonical_record_input(&r2).unwrap());
        assert_ne!(a, b);
    }
}
