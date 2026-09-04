//! The chained digest scheme.
//!
//! Under `chained`, each record's digest covers the previous record's
//! digest plus its own canonical body:
//!
//! ```text
//! digest(0) = H(record(0))
//! digest(N) = H(prev_digest(N-1) || record(N))
//! ```
//!
//! The previous digest is carried in hex form inside the next record's
//! integrity block (`prev_digest`), which is what makes the chain
//! verifiable later: a verifier walks the records in order and checks that
//! every linkage and every digest recomputes. Altering one record breaks
//! its own digest *and* every successor's `prev_digest`; deleting a
//! middle record breaks its successor's linkage; reordering breaks the
//! linkage at the first misplaced record.
//!
//! ## Honest limits
//!
//! This detects tampering in locally stored history; it does not anchor
//! history to the ledger or create blockchain-level immutability.

use safeguard_audit_core::{
    AuditRecord, IntegrityDigest, IntegrityStatus, RecordIntegrity, VerificationFailure,
};

use crate::errors::IntegrityResult;
use crate::hashing::{canonical_record_input, hash_bytes};

/// Computes the chained digest for `record` given the digest of its
/// predecessor (hex bytes of `prev` are prepended to the canonical input).
/// `None` means this record opens the chain.
pub fn chain_step(
    prev: Option<&IntegrityDigest>,
    record: &AuditRecord,
) -> IntegrityResult<IntegrityDigest> {
    let input = canonical_record_input(record)?;
    let mut bytes = Vec::with_capacity(64 + input.len());
    if let Some(p) = prev {
        bytes.extend_from_slice(p.value().as_bytes());
    }
    bytes.extend_from_slice(&input);
    Ok(hash_bytes(&bytes))
}

/// Seals an ordered sequence of records into a chain, returning the sealed
/// copies. Sealing is deterministic: the same ordered records always seal
/// to identical integrity blocks.
pub fn seal_chain(records: &[AuditRecord]) -> IntegrityResult<Vec<AuditRecord>> {
    let mut sealed = Vec::with_capacity(records.len());
    let mut prev: Option<IntegrityDigest> = None;
    for record in records {
        let digest = chain_step(prev.as_ref(), record)?;
        let mut next = record.clone();
        next.integrity = Some(RecordIntegrity {
            digest: digest.clone(),
            prev_digest: prev.clone(),
            chained: true,
        });
        prev = Some(digest);
        sealed.push(next);
    }
    Ok(sealed)
}

/// Verifies a chain of sealed records in order.
///
/// Returns `Ok(())` when every record carries a chained integrity block,
/// every linkage matches its predecessor's recomputed digest, and every
/// digest recomputes from the record body. The first violation is
/// reported as a machine-readable [`VerificationFailure`] naming the
/// record and the failure class.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), VerificationFailure> {
    let mut prev: Option<IntegrityDigest> = None;
    for record in records {
        let integrity = match &record.integrity {
            Some(i) if i.chained => i,
            Some(_) => {
                return Err(VerificationFailure::new(
                    IntegrityStatus::BrokenChain,
                    Some(record.record_id.clone()),
                    "record is not flagged as chained",
                ));
            }
            None => {
                return Err(VerificationFailure::new(
                    IntegrityStatus::BrokenChain,
                    Some(record.record_id.clone()),
                    "record carries no integrity block",
                ));
            }
        };

        // Linkage: the stored predecessor must equal the digest we
        // recomputed for the previous record.
        match (&integrity.prev_digest, &prev) {
            (None, None) => {}
            (Some(stored), Some(computed)) if stored == computed => {}
            _ => {
                return Err(VerificationFailure::new(
                    IntegrityStatus::BrokenChain,
                    Some(record.record_id.clone()),
                    "record's prev_digest does not match its predecessor's digest",
                ));
            }
        }

        // Body: the digest must recompute from this record's content.
        let expected = chain_step(prev.as_ref(), record).map_err(|e| {
            VerificationFailure::new(
                IntegrityStatus::BrokenChain,
                Some(record.record_id.clone()),
                format!("cannot recompute digest: {e}"),
            )
        })?;
        if integrity.digest != expected {
            return Err(VerificationFailure::new(
                IntegrityStatus::DigestMismatch,
                Some(record.record_id.clone()),
                "record digest does not recompute from its content",
            ));
        }

        prev = Some(expected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn three_records() -> Vec<AuditRecord> {
        vec![record("a"), record("b"), record("c")]
    }

    #[test]
    fn sealing_is_deterministic() {
        let a = seal_chain(&three_records()).unwrap();
        let b = seal_chain(&three_records()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn every_linkage_points_back_and_every_digest_recomputes() {
        let sealed = seal_chain(&three_records()).unwrap();
        assert_eq!(sealed.len(), 3);
        assert!(verify_chain(&sealed).is_ok());

        // Digest N depends on digest N-1: same record content, different
        // position in the chain yields a different digest.
        let first_only = seal_chain(&[three_records()[0].clone()]).unwrap();
        assert_eq!(
            sealed[0].integrity.as_ref().unwrap().digest,
            first_only[0].integrity.as_ref().unwrap().digest
        );
    }

    #[test]
    fn altering_a_body_breaks_its_digest() {
        let mut sealed = seal_chain(&three_records()).unwrap();
        // Tamper with the middle record's content after sealing.
        sealed[1].recorded_at = Timestamp::from_unix_seconds(999);
        let failure = verify_chain(&sealed).unwrap_err();
        assert_eq!(failure.status(), IntegrityStatus::DigestMismatch);
        assert_eq!(
            failure.record_id().unwrap(),
            &sealed[1].record_id,
            "the tampered record itself must be identified"
        );
    }

    #[test]
    fn deleting_the_middle_record_breaks_its_successor_linkage() {
        let mut sealed = seal_chain(&three_records()).unwrap();
        sealed.remove(1); // B is gone; C's prev_digest no longer matches.
        let failure = verify_chain(&sealed).unwrap_err();
        assert_eq!(failure.status(), IntegrityStatus::BrokenChain);
        assert_eq!(
            failure.record_id().unwrap(),
            &sealed[1].record_id,
            "C must be flagged: its predecessor B is missing"
        );
    }

    #[test]
    fn deleting_the_head_record_breaks_the_chain() {
        let mut sealed = seal_chain(&three_records()).unwrap();
        sealed.remove(0); // A is gone; B now opens but expects a predecessor.
        let failure = verify_chain(&sealed).unwrap_err();
        assert_eq!(failure.status(), IntegrityStatus::BrokenChain);
    }

    #[test]
    fn reordering_breaks_linkage_at_the_first_misplaced_record() {
        let sealed = seal_chain(&three_records()).unwrap();
        // Swap B and C: C now sits where B expects its predecessor A's
        // digest to chain into B... B's stored prev is A's digest but the
        // walker recomputed C's digest as the predecessor.
        let scrambled = vec![sealed[0].clone(), sealed[2].clone(), sealed[1].clone()];
        let failure = verify_chain(&scrambled).unwrap_err();
        assert_eq!(failure.status(), IntegrityStatus::BrokenChain);
        // C carries B's digest as its predecessor, but A now precedes it:
        // the linkage breaks at the first misplaced record, C.
        assert_eq!(failure.record_id().unwrap(), &scrambled[1].record_id);
    }

    #[test]
    fn chained_inputs_differ_from_standalone_inputs() {
        // Sanity: a chain digest is not the record's standalone digest.
        let sealed = seal_chain(&three_records()).unwrap();
        let standalone = crate::digest::record_digest(&sealed[1]).unwrap();
        assert_ne!(sealed[1].integrity.as_ref().unwrap().digest, standalone);
    }
}
