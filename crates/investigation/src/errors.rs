//! Errors for the investigation services.

use thiserror::Error;

/// Errors returned by the investigation crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InvestigationError {
    /// The case id does not exist in the case store.
    #[error("case {0} not found")]
    CaseNotFound(String),

    /// A case with this id already exists (idempotent re-open is handled
    /// explicitly; an unexpected duplicate is a bug).
    #[error("case {0} already exists")]
    CaseAlreadyExists(String),

    /// The requested status transition is not allowed by the case model.
    #[error("invalid status transition: {0}")]
    InvalidTransition(String),

    /// The operation requires the case to be open (findings, notes,
    /// linking, and transitions after closure are rejected).
    #[error("case {0} is closed and cannot be modified")]
    ClosedCase(String),

    /// The actor is not authorized for the operation on this case.
    #[error("actor {0} is not authorized: {1}")]
    NotAuthorized(String, String),

    /// A referenced audit record does not exist in the store.
    #[error("audit record {0} does not exist")]
    MissingRecord(String),

    /// A case-store operation failed.
    #[error("case store failure: {0}")]
    Store(String),

    /// An audit-store (EventStore) operation failed while recording a
    /// lifecycle event.
    #[error("lifecycle event could not be recorded: {0}")]
    LifecycleRecord(String),

    /// Validation of case content failed (title, summary bounds, etc.).
    #[error("invalid case content: {0}")]
    InvalidContent(String),

    /// An internal invariant was violated. This is a bug, not a workflow
    /// outcome.
    #[error("internal investigation error: {0}")]
    Internal(String),
}

/// Convenience result alias for the investigation crate.
pub type InvestigationResult<T> = Result<T, InvestigationError>;
