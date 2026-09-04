//! Tamper detection over record histories.
//!
//! This module turns verification into a *search*: given the records the
//! store returns in history order, where (if anywhere) did history stop
//! verifying? It reuses the recompute-and-compare rules from
//! [`crate::chain`] and [`crate::verification`] and reports the first
//! failure, so an operator can see at a glance whether an export, a
//! range, or a whole store is intact and which record broke it.

use safeguard_audit_core::{AuditRecord, IntegrityStatus, VerificationOutcome};

use crate::errors::IntegrityResult;
use crate::verification::verify_all;

/// Scans a history and returns every record that failed verification.
///
/// An intact history yields an empty list. A chained history that breaks
/// yields a single outcome naming the record where the chain broke (its
/// successors are unreachable by definition); a standalone history yields
/// one outcome per tampered record.
pub fn locate_tampering(records: &[AuditRecord]) -> IntegrityResult<Vec<VerificationOutcome>> {
    Ok(verify_all(records)?
        .into_iter()
        .filter(|o| o.status() != IntegrityStatus::Verified)
        .collect())
}

/// Whether any tampering was detected in the history.
pub fn detect(records: &[AuditRecord]) -> IntegrityResult<bool> {
    Ok(!locate_tampering(records)?.is_empty())
}

/// Whether the history is fully intact (convenience, mirrors
/// [`detect`]).
pub fn intact(records: &[AuditRecord]) -> IntegrityResult<bool> {
    Ok(!detect(records)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::seal_chain;
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
    fn intact_history_reports_no_tampering() {
        let records = seal_chain(&[record("a"), record("b")]).unwrap();
        assert!(locate_tampering(&records).unwrap().is_empty());
        assert!(!detect(&records).unwrap());
        assert!(intact(&records).unwrap());
    }

    #[test]
    fn tampering_is_located_to_the_breaking_record() {
        let mut records = seal_chain(&[record("a"), record("b"), record("c")]).unwrap();
        records[1].recorded_at = Timestamp::from_unix_seconds(4242);
        let found = locate_tampering(&records).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].record_id(), &records[1].record_id);
        assert!(detect(&records).unwrap());
        assert!(!intact(&records).unwrap());
    }
}
