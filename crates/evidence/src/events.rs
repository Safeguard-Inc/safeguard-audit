//! Projection of evidence generation onto the audit store.
//!
//! Generating an artifact is itself an audit-layer action and is
//! recorded as a derived `evidence-generated` event: the evidence id,
//! kind, source-record count, manifest reference, and content digest.
//! Recording is idempotent per event identity (deterministic per
//! artifact and kind), so re-running a generation after a crash cannot
//! duplicate history.

use safeguard_audit_core::{AuditRecord, Clock, DataClassification};
use safeguard_audit_events::{EventSlot, EvidenceLifecycle};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{EvidenceError, EvidenceResult};

/// Records an evidence generation into the audit store.
///
/// The record classification is `Confidential`: evidence production is
/// internal audit activity — not public ledger metadata, and not
/// financial data. The record carries references only; protected record
/// content is never copied into it.
pub fn record_generation(
    lifecycle: &EvidenceLifecycle,
    clock: &dyn Clock,
    store: &mut dyn EventStore,
) -> EvidenceResult<()> {
    let event = lifecycle
        .into_audit_event(EventSlot::default())
        .map_err(|e| EvidenceError::EventRecord(e.to_string()))?;
    let record = AuditRecord::from_event_classified(event, DataClassification::Confidential, clock)
        .map_err(|e| EvidenceError::EventRecord(e.to_string()))?;
    match store.insert(record) {
        Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
        Err(e) => Err(EvidenceError::EventRecord(e.to_string())),
    }
}
