//! The audit record: the persisted unit of audit history.
//!
//! An [`AuditRecord`] wraps a normalized [`AuditEvent`] with everything the
//! store needs to persist, index, and verify it:
//!
//! * a **deterministic `record_id`** derived from the canonical bytes of the
//!   event — the same event always derives the same record id, which is what
//!   makes duplicate ingestion idempotent,
//! * the **time the record was created** (distinct from `observed_at`,
//!   which is when the underlying activity happened),
//! * a **data classification** plus a field-level redaction table, and
//! * **correction links** for the append-only correction model.
//!
//! ## Immutability
//!
//! Records are append-only. There is no update or delete path: once a
//! source event is recorded, the original record is never silently mutated.
//! If an interpretation needs correcting, a *new* record is appended with
//! kind `record-corrected`, `supersedes` pointing at the original, and a
//! correction reason — preserving history instead of rewriting it.

use serde::{Deserialize, Serialize};

use crate::audit::RECORD_SCHEMA_VERSION;
use crate::errors::{AuditError, AuditResult};
use crate::event::{AuditEvent, EventKind};
use crate::identifiers::RecordId;
use crate::integrity::IntegrityDigest;
use crate::privacy::{DataClassification, FieldClassifications};
use crate::timestamps::{Clock, Timestamp};

/// A persisted audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Deterministic identity, derived from the canonical event bytes.
    pub record_id: RecordId,
    /// The normalized event being recorded.
    pub event: AuditEvent,
    /// When this record was created (injection time, not event time).
    pub recorded_at: Timestamp,
    /// The record schema version.
    pub schema_version: u32,
    /// The most sensitive classification held by this record's content.
    pub classification: DataClassification,
    /// Field-level classification table used for redaction and export.
    pub redactions: FieldClassifications,
    /// When set, this record corrects an earlier record (kind must be
    /// `RecordCorrected`).
    pub supersedes: Option<RecordId>,
    /// Why the correction was recorded, when this is a correction.
    pub correction_reason: Option<String>,
    /// Integrity information (digest, chaining) — filled by the integrity
    /// subsystem when the record is committed.
    pub integrity: Option<RecordIntegrity>,
}

/// Integrity information attached to a committed record.
///
/// The *hashing implementation* lives in the integrity crate; this is the
/// persisted model it fills in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordIntegrity {
    /// The digest algorithm and value over the canonical record bytes.
    pub digest: IntegrityDigest,
    /// The previous record's digest, when chaining is enabled.
    pub prev_digest: Option<IntegrityDigest>,
    /// Whether this record is chained to its predecessor.
    pub chained: bool,
}

impl AuditRecord {
    /// Records an event, deriving the deterministic record identity from
    /// the event's canonical bytes and stamping the recording time from
    /// `clock`.
    ///
    /// Recording the same event twice produces the same record id — callers
    /// use that to deduplicate idempotently.
    pub fn from_event(event: AuditEvent, clock: &dyn Clock) -> AuditResult<Self> {
        event.validate()?;
        let record_id = RecordId::derive_bytes(&event.canonical_bytes()?);
        Ok(Self {
            record_id,
            recorded_at: Timestamp::now(clock),
            schema_version: RECORD_SCHEMA_VERSION,
            classification: DataClassification::Confidential,
            redactions: FieldClassifications::new(),
            supersedes: None,
            correction_reason: None,
            integrity: None,
            event,
        })
    }

    /// Records an event with an explicit classification.
    pub fn from_event_classified(
        event: AuditEvent,
        classification: DataClassification,
        clock: &dyn Clock,
    ) -> AuditResult<Self> {
        let mut record = Self::from_event(event, clock)?;
        record.classification = classification;
        Ok(record)
    }

    /// Appends a correction record that supersedes `original`.
    ///
    /// `event` must have kind `RecordCorrected`. The original record is
    /// left untouched; history is preserved, never rewritten.
    pub fn correction(
        original: &AuditRecord,
        reason: &str,
        event: AuditEvent,
        clock: &dyn Clock,
    ) -> AuditResult<Self> {
        if event.kind != EventKind::RecordCorrected {
            return Err(AuditError::InvalidEvent(
                "correction records require kind `record-corrected`".into(),
            ));
        }
        if reason.trim().is_empty() {
            return Err(AuditError::ValidationFailure(
                "correction reason must not be empty".into(),
            ));
        }
        if reason.len() > 512 {
            return Err(AuditError::ValidationFailure(
                "correction reason must be at most 512 chars".into(),
            ));
        }
        let mut record = Self::from_event(event, clock)?;
        record.supersedes = Some(original.record_id.clone());
        record.correction_reason = Some(reason.to_owned());
        Ok(record)
    }

    /// Validates record-wide invariants:
    ///
    /// * the embedded event is valid,
    /// * the schema version is supported,
    /// * `record-corrected` events carry a supersedes link and reason,
    /// * non-correction records never carry correction links.
    pub fn validate(&self) -> AuditResult<()> {
        self.event.validate()?;
        if self.schema_version != RECORD_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(format!(
                "record schema version {} is not supported (expected {RECORD_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        match self.event.kind {
            EventKind::RecordCorrected => {
                if self.supersedes.is_none() {
                    return Err(AuditError::InvalidEvent(
                        "record-corrected events must carry a supersedes link".into(),
                    ));
                }
                if self.correction_reason.is_none() {
                    return Err(AuditError::InvalidEvent(
                        "record-corrected events must carry a correction reason".into(),
                    ));
                }
            }
            _ => {
                if self.supersedes.is_some() || self.correction_reason.is_some() {
                    return Err(AuditError::InvalidEvent(
                        "correction links are only valid on record-corrected events".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The deterministic record id.
    pub fn record_id(&self) -> &RecordId {
        &self.record_id
    }

    /// The id of the underlying event (deduplication key of the source).
    pub fn event_id(&self) -> &crate::identifiers::EventId {
        &self.event.event_id
    }

    /// The kind of the underlying event.
    pub fn kind(&self) -> EventKind {
        self.event.kind
    }

    /// Canonical JSON bytes for this record — the input to its digest.
    pub fn canonical_bytes(&self) -> AuditResult<Vec<u8>> {
        crate::serialization::canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventProvenance, OriginKind};
    use crate::identifiers::{EventId, NetworkId};
    use crate::VersionLabel;

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn frozen_event(id: &str) -> AuditEvent {
        let provenance = EventProvenance::new(
            OriginKind::OnChain,
            "soroban",
            VersionLabel::new("1.0").unwrap(),
        )
        .unwrap();
        AuditEvent::new(
            EventId::derive(&["testnet", id]),
            EventKind::AccountFrozen,
            testnet(),
            provenance,
        )
    }

    fn clock() -> impl Clock {
        crate::timestamps::FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000))
    }

    #[test]
    fn same_event_records_same_deterministic_id() {
        let c = clock();
        let a = AuditRecord::from_event(frozen_event("tx-1"), &c).unwrap();
        let b = AuditRecord::from_event(frozen_event("tx-1"), &c).unwrap();
        assert_eq!(a.record_id, b.record_id);
        assert_eq!(a.event_id(), b.event_id());
        assert_ne!(
            a.record_id,
            AuditRecord::from_event(frozen_event("tx-2"), &c)
                .unwrap()
                .record_id
        );
    }

    #[test]
    fn records_stamp_time_and_defaults() {
        let c = clock();
        let record = AuditRecord::from_event(frozen_event("tx-9"), &c).unwrap();
        assert_eq!(
            record.recorded_at,
            Timestamp::from_unix_seconds(1_700_000_000)
        );
        assert_eq!(record.schema_version, RECORD_SCHEMA_VERSION);
        assert_eq!(record.classification, DataClassification::Confidential);
        assert!(record.integrity.is_none());
        assert!(record.validate().is_ok());
    }

    #[test]
    fn correction_records_require_links_and_preserve_originals() {
        let c = clock();
        let original = AuditRecord::from_event(frozen_event("tx-1"), &c).unwrap();

        let mut correction_event = frozen_event("tx-1-corrected");
        correction_event.kind = EventKind::RecordCorrected;
        let ok =
            AuditRecord::correction(&original, "wrong event index", correction_event.clone(), &c)
                .unwrap();
        assert_eq!(ok.supersedes.as_ref(), Some(&original.record_id));
        assert!(ok.validate().is_ok());

        // Original is untouched.
        assert!(original.supersedes.is_none());
        assert!(original.validate().is_ok());

        // A correction without a reason is rejected.
        assert!(AuditRecord::correction(&original, "  ", correction_event, &c).is_err());

        // Non-correction kinds cannot carry correction links.
        let mut bad = original.clone();
        bad.event.kind = EventKind::AccountFrozen;
        bad.supersedes = Some(original.record_id.clone());
        bad.correction_reason = Some("because".into());
        assert!(bad.validate().is_err());
    }

    #[test]
    fn record_ids_derive_from_content_not_arrival_time() {
        let early = crate::timestamps::FixedClock::at(Timestamp::from_unix_seconds(1));
        let late = crate::timestamps::FixedClock::at(Timestamp::from_unix_seconds(2));
        let a = AuditRecord::from_event(frozen_event("same"), &early).unwrap();
        let b = AuditRecord::from_event(frozen_event("same"), &late).unwrap();
        assert_eq!(a.record_id, b.record_id);
        assert_ne!(a.recorded_at, b.recorded_at);
    }

    #[test]
    fn records_round_trip_serde() {
        let c = clock();
        let record = AuditRecord::from_event(frozen_event("tx-r"), &c).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }
}
