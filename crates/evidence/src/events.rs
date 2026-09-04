//! Projection of evidence generation onto the audit store.
//!
//! Generating an artifact is itself an audit-layer action and is
//! recorded as a derived `evidence-generated` event: the evidence id,
//! kind, source-record count, manifest reference, and content digest.
//! Recording is idempotent per event identity (deterministic per
//! artifact and kind), so re-running a generation after a crash cannot
//! duplicate history.

use safeguard_audit_core::{AuditRecord, Clock, DataClassification};
use safeguard_audit_events::{detail_policy, EventSlot, EvidenceLifecycle};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{EvidenceError, EvidenceResult};

/// Records an evidence generation into the audit store.
///
/// The record classification is `Confidential`: evidence production is
/// internal audit activity — not public ledger metadata, and not
/// financial data. The record carries references only; protected record
/// content is never copied into it. Its detail keys carry the declared
/// field-level policy from `audit-events`, so disclosure shows the
/// operational attribution facts (artifact id, kind, record count,
/// manifest, digest) instead of over-redacting them.
pub fn record_generation(
    lifecycle: &EvidenceLifecycle,
    clock: &dyn Clock,
    store: &mut dyn EventStore,
) -> EvidenceResult<()> {
    let event = lifecycle
        .into_audit_event(EventSlot::default())
        .map_err(|e| EvidenceError::EventRecord(e.to_string()))?;
    let mut record =
        AuditRecord::from_event_classified(event, DataClassification::Confidential, clock)
            .map_err(|e| EvidenceError::EventRecord(e.to_string()))?;
    record.redactions = detail_policy(&record.event);
    match store.insert(record) {
        Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
        Err(e) => Err(EvidenceError::EventRecord(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        EvidenceId, EvidenceKind, FixedClock, IntegrityDigest, ManifestId, NetworkId, PageRequest,
        Timestamp, VersionLabel,
    };
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::AuditQuery;

    #[test]
    fn recorded_generations_carry_their_declared_field_policy() {
        let lifecycle = EvidenceLifecycle {
            network: NetworkId::new(NetworkId::TESTNET).unwrap(),
            source: crate::SOURCE_LABEL.into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            evidence: EvidenceId::derive(&["e1"]),
            kind: EvidenceKind::TransactionEvidence,
            record_count: 1,
            manifest: Some(ManifestId::derive(&["m1"])),
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        };
        let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
        let mut store = MemoryEventStore::new();
        record_generation(&lifecycle, &clock, &mut store).unwrap();

        let page = store
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let record = &page.items()[0];
        assert_eq!(
            record.redactions.get("evidence"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(
            record.redactions.get("manifest"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(
            record.redactions.get("kind"),
            Some(&DataClassification::Public)
        );
        assert_eq!(record.redactions.len(), record.event.details.len());
    }
}
