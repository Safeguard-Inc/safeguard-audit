//! Write batches.
//!
//! Audit records are appended in batches (an indexer processing one ledger
//! writes many records at once). A [`WriteBatch`] is validated *as a whole*
//! before any insert: either every record is well-formed and unique within
//! the batch and the store accepts them all, or nothing is written. This is
//! the atomicity contract stores implement; it prevents partial histories.

use safeguard_audit_core::{AuditError, AuditRecord};

/// A validated set of records to append atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBatch {
    records: Vec<AuditRecord>,
}

impl WriteBatch {
    /// Builds a batch after validating every record and checking that the
    /// batch itself contains no duplicate event ids or record ids.
    pub fn new(records: Vec<AuditRecord>) -> Result<Self, AuditError> {
        let mut seen_events = std::collections::HashSet::new();
        let mut seen_records = std::collections::HashSet::new();
        for record in &records {
            record.validate()?;
            if !seen_events.insert(record.event_id().clone()) {
                return Err(AuditError::DuplicateEvent(format!(
                    "batch contains duplicate event {}",
                    record.event_id()
                )));
            }
            if !seen_records.insert(record.record_id.clone()) {
                return Err(AuditError::DuplicateEvent(format!(
                    "batch contains duplicate record {}",
                    record.record_id
                )));
            }
        }
        Ok(Self { records })
    }

    /// An empty batch.
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The records in the batch.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// How many records the batch carries.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// The outcome of an atomic batch write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Records newly inserted.
    pub inserted: usize,
    /// Records already present (idempotent dedup, not an error).
    pub duplicates: usize,
}

impl BatchOutcome {
    /// Summarizes the outcome.
    pub fn describe(&self) -> String {
        format!("inserted {}, duplicate {}", self.inserted, self.duplicates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditEvent, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind, Timestamp,
        VersionLabel,
    };

    fn record(id: &str) -> AuditRecord {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap())
                .unwrap();
        let event = AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[id]),
            EventKind::AccountFrozen,
            network,
            provenance,
        );
        let clock = FixedClock::at(Timestamp::from_unix_seconds(100));
        AuditRecord::from_event(event, &clock).unwrap()
    }

    #[test]
    fn batches_reject_duplicates_within_themselves() {
        let a = record("a");
        let b = record("a"); // same event -> same record id
        assert!(WriteBatch::new(vec![a, b]).is_err());
        assert!(WriteBatch::new(vec![record("a"), record("b")]).is_ok());
    }

    #[test]
    fn empty_batches_are_valid() {
        let batch = WriteBatch::empty();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }
}
