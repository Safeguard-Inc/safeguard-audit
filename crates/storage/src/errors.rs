//! Error taxonomy for audit stores.
//!
//! Stores translate backend failures into these classes so callers (the
//! indexer, the CLI, a future server) can react to *kinds* of failure.
//! Messages name identifiers and cursors only — never protected values.

use safeguard_audit_core::AuditError;

/// A store-level error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The requested record does not exist.
    #[error("record not found: {0}")]
    NotFound(String),

    /// An insert collided with an existing record/event.
    #[error("duplicate record: {0}")]
    Duplicate(String),

    /// A cursor was malformed or out of range.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    /// A query was structurally invalid (e.g. contradictory filters).
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// A batch was rejected as a whole (validation or write conflict).
    #[error("batch rejected: {0}")]
    BatchRejected(String),

    /// An integrity expectation of the store failed (tamper detection).
    #[error("integrity mismatch: {0}")]
    IntegrityMismatch(String),

    /// The requested operation is unsupported by this store.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// The underlying storage backend failed.
    #[error("storage failure: {0}")]
    StorageFailure(String),
}

impl StoreError {
    /// Maps a core domain error into the closest store error class.
    pub fn from_core(err: AuditError) -> Self {
        match err {
            AuditError::DuplicateEvent(d) => Self::Duplicate(d),
            AuditError::InvalidEvent(d) => Self::InvalidQuery(d),
            AuditError::IntegrityFailure(d) => Self::IntegrityMismatch(d),
            AuditError::StorageFailure(d) => Self::StorageFailure(d),
            other => Self::StorageFailure(other.to_string()),
        }
    }
}

/// A result alias for store operations.
pub type StoreResult<T> = Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_errors_map_onto_store_classes() {
        assert!(matches!(
            StoreError::from_core(AuditError::DuplicateEvent("x".into())),
            StoreError::Duplicate(_)
        ));
        assert!(matches!(
            StoreError::from_core(AuditError::InvalidEvent("x".into())),
            StoreError::InvalidQuery(_)
        ));
    }
}
