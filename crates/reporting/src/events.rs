//! Projection of report generation onto the audit store.
//!
//! Generating a report is itself an audit-layer action and is recorded
//! as a derived `report-generated` event: the report id, kind,
//! covered-record count, and content digest. Recording is idempotent per
//! event identity (deterministic per report and kind), so re-running a
//! generation after a crash cannot duplicate history.

use safeguard_audit_core::{AuditRecord, Clock, DataClassification};
use safeguard_audit_events::{detail_policy, EventSlot, ReportLifecycle};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{ReportingError, ReportingResult};

/// Records a report generation into the audit store.
///
/// The record classification is `Confidential`: report production is
/// internal audit activity. The record carries references and counts
/// only; the report body is never duplicated into it. Its detail keys
/// carry the declared field-level policy from `audit-events`, so
/// disclosure shows the operational attribution facts (report id, kind,
/// record count, digest) instead of over-redacting them.
pub fn record_report(
    lifecycle: &ReportLifecycle,
    clock: &dyn Clock,
    store: &mut dyn EventStore,
) -> ReportingResult<()> {
    let event = lifecycle
        .into_audit_event(EventSlot::default())
        .map_err(|e| ReportingError::EventRecord(e.to_string()))?;
    let mut record =
        AuditRecord::from_event_classified(event, DataClassification::Confidential, clock)
            .map_err(|e| ReportingError::EventRecord(e.to_string()))?;
    record.redactions = detail_policy(&record.event);
    match store.insert(record) {
        Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
        Err(e) => Err(ReportingError::EventRecord(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        FixedClock, IntegrityDigest, NetworkId, PageRequest, ReportId, ReportKind, Timestamp,
        VersionLabel,
    };
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::AuditQuery;

    #[test]
    fn recorded_generations_carry_their_declared_field_policy() {
        let lifecycle = ReportLifecycle {
            network: NetworkId::new(NetworkId::TESTNET).unwrap(),
            source: crate::SOURCE_LABEL.into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            report: ReportId::derive(&["r1"]),
            kind: ReportKind::DeniedTransactions,
            record_count: 2,
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        };
        let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
        let mut store = MemoryEventStore::new();
        record_report(&lifecycle, &clock, &mut store).unwrap();

        let page = store
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let record = &page.items()[0];
        assert_eq!(
            record.redactions.get("report"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(
            record.redactions.get("kind"),
            Some(&DataClassification::Public)
        );
        assert_eq!(
            record.redactions.get("records"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(
            record.redactions.get("digest"),
            Some(&DataClassification::Public)
        );
        // The table names exactly the fields the record carries.
        assert_eq!(record.redactions.len(), record.event.details.len());
    }
}
