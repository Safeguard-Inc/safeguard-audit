//! Structured error taxonomy for the indexer.
//!
//! The indexer sits between four failure domains and must keep them
//! distinct so an operator can react to the *kind* of failure:
//!
//! * **source** failures (network, malformed reply) — retryable at the
//!   page level, never checkpointed past;
//! * **normalization** failures (unsupported scheme/version, malformed or
//!   invalid payload) — a per-item problem: skip or quarantine, keep the
//!   checkpoint;
//! * **checkpoint** failures (position unknown to the source, storage of
//!   the checkpoint itself) — operator intervention;
//! * **store** failures (backend down, integrity rejections) — operator
//!   intervention, do not advance the checkpoint past unpersisted work.
//!
//! Every variant maps onto the core [`AuditError`] taxonomy so pipeline
//! callers and the CLI can handle all errors uniformly.
//!
//! [`AuditError`]: safeguard_audit_core::AuditError

use safeguard_audit_core::AuditError;

/// The structured error type for the indexer.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// The event source failed to produce a page (retryable). The message
    /// carries the source's own error text.
    #[error("source failure: {0}")]
    Source(String),

    /// A raw item failed normalization (per-item, not retryable as-is).
    #[error("normalization failure: {0}")]
    Normalize(#[from] safeguard_audit_normalizer::NormalizerError),

    /// The store rejected a write (operator intervention).
    #[error("store failure: {0}")]
    Store(#[from] safeguard_audit_storage::StoreError),

    /// The checkpoint could not be loaded, saved, or honored.
    #[error("checkpoint failure: {0}")]
    Checkpoint(String),

    /// Events within one page violated the deterministic ordering rules.
    #[error("ordering failure: {0}")]
    Ordering(String),

    /// An item's recorded position is inconsistent with the source's
    /// contract (e.g. the source re-served an item at or before the
    /// checkpoint position).
    #[error("source position failure: {0}")]
    Position(String),

    /// Invariant violation or programmer error; never user-triggerable.
    #[error("internal error: {0}")]
    Internal(String),
}

impl IndexerError {
    /// Maps onto the core error taxonomy for uniform pipeline handling.
    pub fn into_core(self) -> AuditError {
        match self {
            Self::Source(d) => AuditError::SourceFailure(d),
            Self::Normalize(e) => e.into_core(),
            Self::Store(e) => AuditError::StorageFailure(e.to_string()),
            Self::Checkpoint(d) | Self::Ordering(d) | Self::Position(d) | Self::Internal(d) => {
                AuditError::Internal(d)
            }
        }
    }
}

/// A result alias for indexer operations.
pub type IndexerResult<T> = Result<T, IndexerError>;

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::NetworkId;

    #[test]
    fn source_errors_map_onto_core_source_failures() {
        let err = IndexerError::Source("page fetch failed".into());
        assert!(matches!(err.into_core(), AuditError::SourceFailure(_)));
    }

    #[test]
    fn normalization_errors_map_onto_core_event_errors() {
        let err = IndexerError::Normalize(
            safeguard_audit_normalizer::NormalizerError::UnsupportedScheme("x".into()),
        );
        assert!(matches!(err.into_core(), AuditError::UnsupportedEvent(_)));
    }

    #[test]
    fn checkpoint_and_store_errors_are_distinguishable() {
        let store = IndexerError::Store(safeguard_audit_storage::StoreError::from_core(
            AuditError::StorageFailure("backend down".into()),
        ));
        let checkpoint = IndexerError::Checkpoint("unknown position".into());
        let store_core = store.into_core();
        let checkpoint_core = checkpoint.into_core();
        assert!(matches!(store_core, AuditError::StorageFailure(_)));
        assert!(matches!(checkpoint_core, AuditError::Internal(_)));
        let _ = NetworkId::TESTNET; // keep import referenced
    }
}
