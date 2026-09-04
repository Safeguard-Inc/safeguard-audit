//! Error vocabulary for the reporting crate.
//!
//! Errors are typed so callers can react to the classes that matter: an
//! *authorization* failure (never a panic, never a silent pass), an
//! *invalid request* (bad network label, incoherent query), and a
//! *query/scan* failure from the store.

use safeguard_audit_core::ReportKind;

/// Errors produced by the reporting service.
#[derive(Debug, thiserror::Error)]
pub enum ReportingError {
    /// The acting auditor was not authorized to generate reports.
    #[error("auditor {0} is not authorized: {1}")]
    NotAuthorized(String, String),

    /// The request was malformed or incoherent.
    #[error("invalid report request: {0}")]
    InvalidRequest(String),

    /// An unsupported report kind was requested.
    #[error("report kind {0} is not supported by this generator")]
    UnsupportedKind(ReportKind),

    /// The store query/scan failed.
    #[error("audit store failure: {0}")]
    Store(String),

    /// Hashing or canonicalization failed.
    #[error("integrity failure: {0}")]
    Integrity(String),

    /// Recording the report-generated event failed.
    #[error("recording the report event failed: {0}")]
    EventRecord(String),

    /// Internal invariant broken (never expected at runtime).
    #[error("internal reporting error: {0}")]
    Internal(String),
}

/// Result alias for the reporting crate.
pub type ReportingResult<T> = Result<T, ReportingError>;

impl ReportingError {
    /// Wraps an integrity-crate error.
    pub(crate) fn from_integrity(e: impl std::fmt::Display) -> Self {
        Self::Integrity(e.to_string())
    }

    /// Wraps a core audit error (e.g. canonicalization).
    pub(crate) fn from_core(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }
}