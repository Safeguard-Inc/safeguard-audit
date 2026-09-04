//! Error vocabulary for the evidence crate.
//!
//! Errors are typed so callers can react to the classes that matter:
//! an *authorization* failure (never a panic, never a silent pass), a
//! *missing* source record (evidence cannot name records that do not
//! exist), and a *tampered* source (evidence is never built over records
//! whose integrity does not verify — an altered source would poison the
//! artifact).

use safeguard_audit_core::RecordId;

/// Errors produced by the evidence service.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// The acting auditor was not authorized to generate evidence.
    #[error("auditor {0} is not authorized: {1}")]
    NotAuthorized(String, String),

    /// Evidence requires at least one named source record.
    #[error("evidence must name at least one source record")]
    NoSourceRecords,

    /// A named source record does not exist in the audit store.
    #[error("source record {0} does not exist in the audit store")]
    RecordMissing(RecordId),

    /// A source record failed integrity verification; evidence is never
    /// built over altered records.
    #[error("source record integrity failed: {0}")]
    TamperedSource(String),

    /// Invalid arguments or content (e.g. an unsupported kind).
    #[error("invalid evidence content: {0}")]
    InvalidContent(String),

    /// The integrity crate failed (hashing, manifest, or verification).
    #[error("integrity failure: {0}")]
    Integrity(String),

    /// Recording the evidence-generated event into the audit store failed.
    #[error("recording the evidence event failed: {0}")]
    EventRecord(String),

    /// Internal invariant broken (never expected at runtime).
    #[error("internal evidence error: {0}")]
    Internal(String),
}

/// Result alias for the evidence crate.
pub type EvidenceResult<T> = Result<T, EvidenceError>;

impl EvidenceError {
    /// Wraps an integrity-crate error.
    pub(crate) fn from_integrity(e: impl std::fmt::Display) -> Self {
        Self::Integrity(e.to_string())
    }

    /// Wraps a core audit error (e.g. canonicalization).
    pub(crate) fn from_core(e: impl std::fmt::Display) -> Self {
        Self::Internal(e.to_string())
    }
}