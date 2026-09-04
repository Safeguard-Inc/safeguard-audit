//! Projection of report generation onto the audit store.
//!
//! Generating a report is itself an audit-layer action and is recorded
//! as a derived `report-generated` event: the report id, kind,
//! covered-record count, and content digest. Recording is idempotent per
//! event identity (deterministic per report and kind), so re-running a
//! generation after a crash cannot duplicate history.

use safeguard_audit_core::{AuditRecord, Clock, DataClassification};
use safeguard_audit_events::{EventSlot, ReportLifecycle};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{ReportingError, ReportingResult};

/// Records a report generation into the audit store.
///
/// The record classification is `Confidential`: report production is
/// internal audit activity. The record carries references and counts
/// only; the report body is never duplicated into it.
pub fn record_report(
    lifecycle: &ReportLifecycle,
    clock: &dyn Clock,
    store: &mut dyn EventStore,
) -> ReportingResult<()> {
    let event = lifecycle
        .into_audit_event(EventSlot::default())
        .map_err(|e| ReportingError::EventRecord(e.to_string()))?;
    let record = AuditRecord::from_event_classified(event, DataClassification::Confidential, clock)
        .map_err(|e| ReportingError::EventRecord(e.to_string()))?;
    match store.insert(record) {
        Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
        Err(e) => Err(ReportingError::EventRecord(e.to_string())),
    }
}
