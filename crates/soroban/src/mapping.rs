//! Mapping the verified wire envelope onto normalized metadata.
//!
//! A [`SorobanEvent`] is provider-shaped: ledger numbers, transaction
//! indices, a TOID id, ISO close times. Nothing downstream should touch
//! that shape. [`to_normalized`] converts one event into the
//! provider-neutral pieces the audit model speaks — an [`EventOrder`]
//! (ledger sequence, transaction/operation position, event index from
//! the id suffix), a [`LedgerReference`] with the ledger close time, and
//! an optional [`TransactionReference`] — validated through the
//! `audit-core` constructors so a malformed wire value is an error, not
//! a silently wrong reference.
//!
//! The close time arrives as an RFC 3339 UTC string (Stellar reports
//! ledger times as Unix seconds in most places but ISO strings here).
//! The parser is deliberately strict and self-validating: it converts
//! the text to Unix seconds and then asks `audit-core`'s own renderer
//! to reproduce the input; a string that does not round-trip exactly
//! (an impossible date, a non-UTC offset, trailing garbage) is rejected
//! rather than approximated. No calendar logic is invented in this
//! crate.

use safeguard_audit_core::{
    AuditError, AuditResult, EventOrder, LedgerReference, NetworkId, Timestamp, TransactionHash,
    TransactionReference,
};

use crate::source::is_toid_id;
use crate::wire::SorobanEvent;

/// The provider-neutral context of one Soroban event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedParts {
    /// Deterministic ordering metadata for the event.
    pub order: EventOrder,
    /// The ledger the event was emitted in, with its close time when the
    /// node reported it.
    pub ledger: LedgerReference,
    /// The transaction that triggered the event, when the event names one.
    pub transaction: Option<TransactionReference>,
}

/// Converts `event` into normalized metadata on `network`.
///
/// Fails when the wire data is incoherent: an event id that is not a
/// TOID, an event index that does not fit, a ledger sequence that is
/// not positive, or a close time that is not a valid RFC 3339 UTC
/// string. Absence is never an error — a missing transaction hash or
/// close time simply yields `None`.
pub fn to_normalized(event: &SorobanEvent, network: NetworkId) -> AuditResult<NormalizedParts> {
    let order = EventOrder {
        ledger_sequence: Some(event.ledger),
        transaction_position: event.transaction_index,
        operation_index: event.operation_index,
        event_index: Some(event_index_from_id(&event.id)?),
    };
    let close_time = match &event.ledger_closed_at {
        Some(raw) => Some(parse_ledger_close_time(raw)?),
        None => None,
    };
    let ledger = LedgerReference::new(network.clone(), event.ledger, close_time)?;
    let transaction = match &event.tx_hash {
        Some(raw) => {
            // Core accepts hex or strkey structurally; the getEvents wire
            // contract is 64 lowercase hex, and format enforcement belongs
            // to the adapter.
            if !is_64_lowercase_hex(raw) {
                return Err(AuditError::invalid_identifier(
                    "transaction hash",
                    "must be 64 lowercase hex chars on the getEvents wire",
                ));
            }
            let hash = TransactionHash::new(raw)
                .map_err(|_| AuditError::invalid_identifier("transaction hash", raw.clone()))?;
            Some(TransactionReference::new(network, hash))
        }
        None => None,
    };
    Ok(NormalizedParts {
        order,
        ledger,
        transaction,
    })
}

/// Parses the event index out of a TOID event id (the 10-digit suffix
/// after the hyphen).
fn event_index_from_id(id: &str) -> AuditResult<u32> {
    if !is_toid_id(id) {
        return Err(AuditError::invalid_identifier(
            "event id",
            "must be a TOID: 19-digit TOID + hyphen + 10-digit event index",
        ));
    }
    let suffix = &id[20..];
    let index: u64 = suffix
        .parse()
        .map_err(|_| AuditError::invalid_identifier("event index", suffix))?;
    u32::try_from(index).map_err(|_| {
        AuditError::invalid_identifier(
            "event index",
            format!("{suffix} exceeds the supported event-index range"),
        )
    })
}

/// Parses a ledger close time from the RFC 3339 UTC form Stellar's
/// `getEvents` reports (`2026-07-21T18:01:10Z`).
///
/// Strict by construction: the parsed instant is rendered back with the
/// core time model's own RFC 3339 formatter and must reproduce the input
/// exactly. Impossible dates, offsets, and trailing text therefore
/// fail instead of being approximated.
pub fn parse_ledger_close_time(raw: &str) -> AuditResult<Timestamp> {
    let b = raw.as_bytes();
    let shaped = b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && digits(&b[0..4])
        && digits(&b[5..7])
        && digits(&b[8..10])
        && digits(&b[11..13])
        && digits(&b[14..16])
        && digits(&b[17..19]);
    if !shaped {
        return Err(AuditError::InvalidTimestamp(format!(
            "{raw} is not an RFC 3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)"
        )));
    }
    let year: i64 = raw[0..4].parse().unwrap();
    let month: u32 = raw[5..7].parse().unwrap();
    let day: u32 = raw[8..10].parse().unwrap();
    let hour: u32 = raw[11..13].parse().unwrap();
    let minute: u32 = raw[14..16].parse().unwrap();
    let second: u32 = raw[17..19].parse().unwrap();
    if !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(AuditError::InvalidTimestamp(format!(
            "{raw} is out of range"
        )));
    }

    // Days-from-civil (Howard Hinnant) is the inverse of the algorithm
    // audit-core uses to render RFC 3339, so round-tripping is exact.
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);
    let parsed = Timestamp::from_unix_seconds(secs);
    let rendered = parsed
        .to_rfc3339()
        .map_err(|e| AuditError::InvalidTimestamp(e.to_string()))?;
    if rendered == raw {
        Ok(parsed)
    } else {
        Err(AuditError::InvalidTimestamp(format!(
            "{raw} is not a real UTC instant (round-trips as {rendered})"
        )))
    }
}

fn digits(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_digit())
}

/// Whether `value` is 64 lowercase hex chars — the `getEvents` `txHash`
/// wire shape.
fn is_64_lowercase_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's
/// `days_from_civil`, the inverse of audit-core's civil renderer).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + u64::from(doy);
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::TransactionHash;

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn toid(index: u32) -> String {
        format!("0016010972359577600-{index:010}")
    }

    fn doc_event() -> SorobanEvent {
        // Field values from the Stellar documentation's getEvents example.
        SorobanEvent {
            event_type: crate::wire::SorobanEventType::Contract,
            ledger: 3727845,
            ledger_closed_at: Some("2026-07-21T18:01:10Z".into()),
            contract_id: None,
            id: toid(1),
            transaction_index: Some(5),
            operation_index: Some(0),
            in_successful_contract_call: Some(true),
            topic: vec!["AAAADwAAAAh0cmFuc2Zlcg==".into()],
            value: None,
            tx_hash: Some(
                "a5c9247b77eb04c0d857934a2e988c408167976c8acbdf3d8acf64c44deb3beb".into(),
            ),
        }
    }

    #[test]
    fn the_documented_event_maps_onto_normalized_metadata() {
        let parts = to_normalized(&doc_event(), testnet()).unwrap();
        assert_eq!(parts.order.ledger_sequence, Some(3727845));
        assert_eq!(parts.order.transaction_position, Some(5));
        assert_eq!(parts.order.operation_index, Some(0));
        // The event index comes from the TOID id suffix.
        assert_eq!(parts.order.event_index, Some(1));
        assert_eq!(parts.ledger.sequence(), 3727845);
        assert_eq!(parts.ledger.network(), &testnet());
        let close = parts.ledger.close_time().unwrap();
        assert_eq!(close.to_rfc3339().unwrap(), "2026-07-21T18:01:10Z");
        let tx = parts.transaction.unwrap();
        assert_eq!(
            tx.hash(),
            &TransactionHash::new(
                "a5c9247b77eb04c0d857934a2e988c408167976c8acbdf3d8acf64c44deb3beb"
            )
            .unwrap()
        );
        assert_eq!(tx.network(), &testnet());
    }

    #[test]
    fn absent_transaction_and_close_time_stay_absent() {
        let mut event = doc_event();
        event.tx_hash = None;
        event.ledger_closed_at = None;
        let parts = to_normalized(&event, testnet()).unwrap();
        assert!(parts.transaction.is_none());
        assert!(parts.ledger.close_time().is_none());
    }

    #[test]
    fn close_times_round_trip_exactly_against_the_core_renderer() {
        // The parser must agree with audit-core's own RFC 3339 renderer
        // on every direction, including the epoch and a leap day.
        for secs in [0i64, 951_782_400, 1_700_000_000, 1_609_459_200] {
            let t = Timestamp::from_unix_seconds(secs);
            let rendered = t.to_rfc3339().unwrap();
            assert_eq!(parse_ledger_close_time(&rendered).unwrap(), t);
        }
    }

    #[test]
    fn malformed_close_times_are_rejected_not_approximated() {
        // Impossible dates, offsets, and trailing text all fail: the
        // parser round-trips against the core renderer and refuses
        // anything that does not reproduce exactly.
        for bad in [
            "2026-02-30T18:01:10Z",      // February 30th does not exist
            "2026-13-01T18:01:10Z",      // month 13
            "2026-07-21T18:01:10",       // missing Z
            "2026-07-21T18:01:10+02:00", // offset, not UTC
            "2026-07-21T18:01:10Zextra", // trailing text
            "not-a-time",
        ] {
            assert!(
                parse_ledger_close_time(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_ids_and_hashes_fail_as_errors() {
        let mut bad_id = doc_event();
        bad_id.id = "not-a-toid".into();
        assert!(to_normalized(&bad_id, testnet()).is_err());

        let mut bad_hash = doc_event();
        bad_hash.tx_hash = Some("zz".repeat(32));
        assert!(to_normalized(&bad_hash, testnet()).is_err());

        let mut zero_ledger = doc_event();
        zero_ledger.ledger = 0;
        assert!(to_normalized(&zero_ledger, testnet()).is_err());
    }
}
