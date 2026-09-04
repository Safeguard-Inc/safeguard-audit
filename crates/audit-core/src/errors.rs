//! Structured error taxonomy for the audit domain.
//!
//! Errors distinguish failure classes so callers — the CLI, the ingestion
//! pipeline, an HTTP boundary later — can react to *kinds* of failure rather
//! than parsing prose. The taxonomy mirrors the spec surface: invalid versus
//! unsupported events, authorization versus scope failures, integrity
//! failures, replay conflicts, and so on.
//!
//! ## Privacy rule
//!
//! Error messages must never carry confidential values: no balances,
//! ciphertexts, view keys, or credentials. Variants carry *identifiers*
//! (which are public transaction metadata) and short descriptions only.
//! When a detail would expose protected data, the variant carries a stable
//! code instead and the detail is kept out of the message.

/// The structured error type for the audit domain.
///
/// Every variant carries a human-readable description that names
/// identifiers but never private data. Errors are `PartialEq` so tests can
/// assert on exact failure classes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// An identifier failed structural validation (empty, wrong length,
    /// forbidden characters, or an out-of-range value).
    #[error("invalid {kind}: {detail}")]
    InvalidIdentifier {
        /// What kind of identifier failed, e.g. `"record id"`.
        kind: &'static str,
        /// Why it failed.
        detail: String,
    },

    /// A timestamp was outside the representable or acceptable range.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// The event is structurally well-formed but semantically invalid.
    #[error("invalid event: {0}")]
    InvalidEvent(String),

    /// The event type is not in the supported registry.
    #[error("unsupported event: {0}")]
    UnsupportedEvent(String),

    /// The event version predates or postdates what this build understands.
    #[error("unsupported event version: {0}")]
    UnsupportedEventVersion(String),

    /// An event that was already recorded was presented for insertion.
    #[error("duplicate event: {0}")]
    DuplicateEvent(String),

    /// A caller attempted something they are not authorized to do.
    #[error("authorization failure: {0}")]
    AuthorizationFailure(String),

    /// The caller is authorized but the request is outside their scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// The underlying storage layer failed.
    #[error("storage failure: {0}")]
    StorageFailure(String),

    /// An upstream event source failed (network, timeout, malformed reply).
    #[error("source failure: {0}")]
    SourceFailure(String),

    /// An integrity check failed: digest mismatch, broken chain, tampering.
    #[error("integrity failure: {0}")]
    IntegrityFailure(String),

    /// Evidence could not be parsed or did not match its manifest.
    #[error("malformed evidence: {0}")]
    MalformedEvidence(String),

    /// A report could not be generated.
    #[error("report generation failure: {0}")]
    ReportGenerationFailure(String),

    /// An export could not be produced.
    #[error("export failure: {0}")]
    ExportFailure(String),

    /// A decryption request was refused by the authorization boundary.
    #[error("decryption authorization failure: {0}")]
    DecryptionAuthorizationFailure(String),

    /// The data carries a schema this build does not understand.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    /// Two versions that must agree do not (policy, enforcement, parser...).
    #[error("version mismatch: {0}")]
    VersionMismatch(String),

    /// Replay would conflict with existing production history.
    #[error("replay conflict: {0}")]
    ReplayConflict(String),

    /// Canonical serialization failed (a value was not serializable).
    #[error("serialization failure: {0}")]
    SerializationFailure(String),

    /// A query was structurally invalid (contradictory filters, unknown
    /// fields, impossible ranges).
    #[error("invalid query: {0}")]
    InvalidQuery(String),

    /// A value failed validation that is not covered by a more specific
    /// variant (used by builders for compound invariants).
    #[error("validation failure: {0}")]
    ValidationFailure(String),

    /// An invariant violation or programmer error; never user-triggerable.
    #[error("internal error: {0}")]
    Internal(String),
}

impl AuditError {
    /// Convenience constructor for [`AuditError::InvalidIdentifier`].
    pub fn invalid_identifier(kind: &'static str, detail: impl Into<String>) -> Self {
        Self::InvalidIdentifier {
            kind,
            detail: detail.into(),
        }
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(err: serde_json::Error) -> Self {
        // serde_json messages can include a line/column; they never include
        // value contents, so forwarding the message is safe.
        Self::SerializationFailure(err.to_string())
    }
}

/// A result alias used across the domain layer.
pub type AuditResult<T> = Result<T, AuditError>;
