//! Position keys and cursor encoding.
//!
//! Cursor pagination over an append-only audit history must be stable under
//! inserts: a page boundary points at a *record*, not at a count. Every
//! record has a deterministic [`PositionKey`] — the on-chain ordering
//! hierarchy (ledger, operation, event) with `recorded_at` and `record_id`
//! as the final tiebreakers — and a position key encodes losslessly into an
//! opaque [`Cursor`].
//!
//! Two processes that sort the same records derive the same keys, so
//! pagination is reproducible.

use safeguard_audit_core::{AuditError, AuditRecord, Cursor, RecordId};

/// The deterministic sort key of a record within audit history.
///
/// Ordering follows on-chain metadata first (ledger sequence, operation
/// index, event index) and falls back to recording time and record id only
/// when on-chain placement is absent or equal — arrival order never
/// dominates history order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PositionKey {
    /// Ledger sequence, or `None` for events without on-chain placement.
    pub ledger: Option<i64>,
    /// Operation index within the transaction.
    pub operation: Option<u32>,
    /// Event index within the operation.
    pub event: Option<u32>,
    /// When the record was recorded (tiebreaker).
    pub recorded_at: i64,
    /// Deterministic record id (final tiebreaker).
    pub record_id: RecordId,
}

impl PositionKey {
    /// Derives the position key of a record.
    pub fn of(record: &AuditRecord) -> Self {
        let order = &record.event.order;
        Self {
            ledger: order.ledger_sequence,
            operation: order.operation_index,
            event: order.event_index,
            recorded_at: record.recorded_at.as_unix_seconds(),
            record_id: record.record_id.clone(),
        }
    }

    /// Encodes this position as an opaque cursor string.
    ///
    /// The encoding is stable, lossless, and URL-safe:
    /// `ledger|op|event|recorded_at|record_id` with `-` for absent fields.
    pub fn to_cursor(&self) -> Cursor {
        let f = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        let g = |v: Option<u32>| v.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
        let raw = format!(
            "{}|{}|{}|{}|{}",
            f(self.ledger),
            g(self.operation),
            g(self.event),
            self.recorded_at,
            self.record_id.as_str()
        );
        Cursor::new(&raw).expect("position-key cursors are always URL-safe")
    }

    /// Decodes a cursor back into a position, or errors if malformed.
    pub fn from_cursor(cursor: &Cursor) -> Result<Self, AuditError> {
        let parts: Vec<&str> = cursor.as_str().split('|').collect();
        if parts.len() != 5 {
            return Err(AuditError::invalid_identifier(
                "cursor",
                "expected 5 position fields",
            ));
        }
        let parse_i64 = |s: &str, name: &str| -> Result<Option<i64>, AuditError> {
            if s == "-" {
                Ok(None)
            } else {
                s.parse::<i64>().map(Some).map_err(|_| {
                    AuditError::invalid_identifier("cursor", format!("{name} is not an integer"))
                })
            }
        };
        let parse_u32 = |s: &str, name: &str| -> Result<Option<u32>, AuditError> {
            if s == "-" {
                Ok(None)
            } else {
                s.parse::<u32>().map(Some).map_err(|_| {
                    AuditError::invalid_identifier("cursor", format!("{name} is not an integer"))
                })
            }
        };
        let recorded_at = parts[3].parse::<i64>().map_err(|_| {
            AuditError::invalid_identifier("cursor", "recorded_at is not an integer")
        })?;
        let record_id = RecordId::from_checked(parts[4])?;
        Ok(Self {
            ledger: parse_i64(parts[0], "ledger")?,
            operation: parse_u32(parts[1], "operation")?,
            event: parse_u32(parts[2], "event")?,
            recorded_at,
            record_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditEvent, EventKind, EventOrder, EventProvenance, FixedClock, NetworkId, OriginKind,
        Timestamp, VersionLabel,
    };

    fn event(
        id: &str,
        ledger: Option<i64>,
        op: Option<u32>,
        ev: Option<u32>,
        ts: i64,
    ) -> AuditRecord {
        let network = NetworkId::new(NetworkId::TESTNET).unwrap();
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap())
                .unwrap();
        let mut event = AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[id]),
            EventKind::TransferDenied,
            network,
            provenance,
        );
        event.order = EventOrder {
            ledger_sequence: ledger,
            transaction_position: None,
            operation_index: op,
            event_index: ev,
        };
        let clock = FixedClock::at(Timestamp::from_unix_seconds(ts));
        AuditRecord::from_event(event, &clock).unwrap()
    }

    #[test]
    fn keys_order_by_onchain_placement_then_time_then_id() {
        let mut keys = [
            PositionKey::of(&event("a", Some(10), Some(1), Some(0), 100)),
            PositionKey::of(&event("b", Some(9), None, None, 100)),
            PositionKey::of(&event("c", None, None, None, 200)),
            PositionKey::of(&event("d", Some(10), Some(1), Some(0), 50)),
            PositionKey::of(&event("e", Some(10), Some(0), None, 300)),
        ];
        keys.sort();
        // Missing ledger placement sorts before ledgered events (None sorts
        // first); then ledger 9 < 10; within ledger 10, op 0 < op 1; equal
        // keys fall back to recorded_at (50 < 100) then record id.
        let order: Vec<Option<i64>> = keys.iter().map(|k| k.ledger).collect();
        assert_eq!(order, vec![None, Some(9), Some(10), Some(10), Some(10)]);
    }

    #[test]
    fn cursors_round_trip_losslessly() {
        let record = event("x", Some(42), Some(3), Some(7), 1_700_000_000);
        let key = PositionKey::of(&record);
        let cursor = key.to_cursor();
        let back = PositionKey::from_cursor(&cursor).unwrap();
        assert_eq!(back, key);
        assert!(cursor.as_str().contains("42|3|7|"));
    }

    #[test]
    fn absent_fields_encode_as_dashes() {
        let record = event("y", None, None, None, 5);
        let key = PositionKey::of(&record);
        let back = PositionKey::from_cursor(&key.to_cursor()).unwrap();
        assert_eq!(back.ledger, None);
        assert_eq!(back.operation, None);
        assert_eq!(back.event, None);
    }

    #[test]
    fn malformed_cursors_error_cleanly() {
        let bad = Cursor::new("42|3").unwrap();
        assert!(PositionKey::from_cursor(&bad).is_err());
    }
}
