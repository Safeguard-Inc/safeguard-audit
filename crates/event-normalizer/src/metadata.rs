//! Deterministic placement metadata for raw hooks events.
//!
//! A raw hooks event arrives with its on-chain placement: ledger sequence,
//! close time, transaction hash, operation index, and event index. This
//! module turns those raw numbers into the typed references and ordering
//! metadata the normalized envelope carries — observed timestamp from the
//! ledger close time (never arrival time), the ledger/transaction/
//! operation references, and the [`EventOrder`] that makes event ordering
//! deterministic across ingestion runs.
//!
//! Extraction is pure: no clocks, no randomness, no environment. The
//! validator has already rejected nonsense placements (zero ledgers,
//! malformed hashes); these helpers still return results so a bug can
//! never slip through as a silent default.

use safeguard_audit_core::{
    EventOrder, LedgerReference, NetworkId, OperationReference, Timestamp, TransactionHash,
    TransactionReference,
};

use crate::errors::{NormalizerError, NormalizerResult};
use crate::parser::RawHooksEvent;

/// The on-chain placement of a raw hooks event, fully typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HooksPlacement {
    /// Ledger close time — the authoritative observed timestamp.
    pub observed_at: Timestamp,
    /// Deterministic ordering metadata.
    pub order: EventOrder,
    /// The ledger reference.
    pub ledger: LedgerReference,
    /// The transaction reference.
    pub transaction: TransactionReference,
    /// The operation reference, when the source reported an operation
    /// index (it always does for the current hooks surface).
    pub operation: Option<OperationReference>,
}

/// Extracts placement metadata for a raw hooks event on `network`.
pub fn hooks_placement(
    raw: &RawHooksEvent,
    network: NetworkId,
) -> NormalizerResult<HooksPlacement> {
    let observed_at = Timestamp::from_unix_seconds(raw.close_time);
    let transaction = TransactionReference::new(
        network.clone(),
        TransactionHash::new(&raw.transaction_hash)
            .map_err(|e| classify_error("transaction", e))?,
    );
    let ledger = LedgerReference::new(network.clone(), raw.ledger, Some(observed_at))
        .map_err(|e| classify_error("ledger", e))?;
    let operation = OperationReference::new(transaction.clone(), raw.operation_index, None)
        .map_err(|e| classify_error("operation", e))?;
    let order = EventOrder {
        ledger_sequence: Some(raw.ledger),
        transaction_position: None,
        operation_index: Some(raw.operation_index),
        event_index: Some(raw.event_index),
    };
    Ok(HooksPlacement {
        observed_at,
        order,
        ledger,
        transaction,
        operation: Some(operation),
    })
}

fn classify_error(field: &str, e: safeguard_audit_core::AuditError) -> NormalizerError {
    NormalizerError::ClassificationFailed {
        scheme: "hooks-state-event",
        detail: format!("{field}: {e}"),
    }
}
