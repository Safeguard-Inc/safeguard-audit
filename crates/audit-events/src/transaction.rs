//! Source-shaped transaction context.
//!
//! Every on-chain event arrives inside a transaction, and every derived
//! outcome references one. This module frames that context in
//! provider-neutral, source-shaped terms (loose strings, optional
//! positions) and converts it into the validated core references the
//! normalized envelope carries.
//!
//! The transaction *status* is framing data only: it tells derived-event
//! builders whether an operation is known to have failed (a revert), which
//! is how denied operations are recognized. Nothing here judges why.

use safeguard_audit_core::{
    AuditResult, LedgerReference, NetworkId, OperationReference, Timestamp, TransactionHash,
    TransactionReference,
};

use crate::EventError;

/// What became of the transaction on the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TxStatus {
    /// The transaction applied successfully.
    Succeeded,
    /// The transaction was reverted (e.g. a fail-closed denial).
    Failed,
    /// The outcome is not known from this source.
    Unknown,
}

impl TxStatus {
    /// The stable label for this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// Source-shaped transaction context before normalization.
///
/// Strings are intentionally loose here — RPC and Soroban adapters produce
/// these; conversion into validated core references happens explicitly so
/// garbage cannot slip into a normalized envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionContext {
    /// Network the transaction belongs to.
    pub network: NetworkId,
    /// Transaction hash as reported by the source.
    pub hash: String,
    /// Ledger sequence, when known.
    pub ledger_sequence: Option<i64>,
    /// Ledger close time, when known.
    pub close_time: Option<Timestamp>,
    /// Whether the transaction succeeded, failed, or is unknown.
    pub status: TxStatus,
}

impl TransactionContext {
    /// Builds a transaction context.
    pub fn new(
        network: NetworkId,
        hash: impl Into<String>,
        ledger_sequence: Option<i64>,
        close_time: Option<Timestamp>,
        status: TxStatus,
    ) -> Self {
        Self {
            network,
            hash: hash.into(),
            ledger_sequence,
            close_time,
            status,
        }
    }

    /// Converts to the validated core transaction reference.
    pub fn to_reference(&self) -> Result<TransactionReference, EventError> {
        TransactionHash::new(&self.hash)
            .map(|hash| TransactionReference::new(self.network.clone(), hash))
            .map_err(|err| EventError::InvalidFieldValue {
                field: "transaction.hash".into(),
                detail: err.to_string(),
            })
    }

    /// Converts to the validated core ledger reference, when a sequence is
    /// known.
    pub fn ledger_reference(&self) -> Result<Option<LedgerReference>, EventError> {
        match self.ledger_sequence {
            Some(seq) => LedgerReference::new(self.network.clone(), seq, self.close_time)
                .map(Some)
                .map_err(|err| EventError::InvalidFieldValue {
                    field: "ledger.sequence".into(),
                    detail: err.to_string(),
                }),
            None => Ok(None),
        }
    }
}

/// A source-shaped operation position within a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationPosition {
    /// Zero-based operation index inside the transaction.
    pub index: u32,
}

/// Builds a validated operation reference for `position` inside `tx`.
pub fn operation_reference(
    tx: &TransactionReference,
    position: OperationPosition,
    op_type: Option<&str>,
) -> AuditResult<OperationReference> {
    OperationReference::new(tx.clone(), position.index, op_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn contexts_convert_to_validated_references() {
        let ctx = TransactionContext::new(
            testnet(),
            "ab".repeat(32),
            Some(42),
            Some(Timestamp::from_unix_seconds(100)),
            TxStatus::Succeeded,
        );
        let tx = ctx.to_reference().unwrap();
        assert_eq!(tx.network().as_str(), "testnet");
        let ledger = ctx.ledger_reference().unwrap().unwrap();
        assert_eq!(ledger.sequence(), 42);

        let op = operation_reference(&tx, OperationPosition { index: 1 }, Some("invoke_contract"))
            .unwrap();
        assert_eq!(op.index(), 1);
        assert_eq!(op.transaction(), &tx);
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(TxStatus::Succeeded.as_str(), "succeeded");
        assert_eq!(TxStatus::Failed.as_str(), "failed");
        assert_eq!(TxStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn missing_ledger_metadata_stays_absent() {
        let ctx = TransactionContext::new(testnet(), "hash", None, None, TxStatus::Failed);
        assert!(ctx.ledger_reference().unwrap().is_none());
    }

    #[test]
    fn invalid_hashes_fail_conversion() {
        let ctx = TransactionContext::new(testnet(), "not a hash!", None, None, TxStatus::Unknown);
        assert!(ctx.to_reference().is_err());
    }
}
