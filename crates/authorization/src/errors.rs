//! Errors for the authorization services.
//!
//! The error vocabulary mirrors the three authorization outcomes at the
//! model level (`granted`, `denied`, `out-of-scope`) but distinguishes
//! *configuration* failures from *decision* failures: a missing grant, an
//! expired credential, or an invalid scope are problems an operator must
//! fix, while a clean denial is a valid decision result the caller should
//! surface, not a crash.

use thiserror::Error;

/// Errors returned by the authorization crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    /// The auditor identity is not registered with any grants.
    #[error("auditor {0} has no grants registered")]
    UnknownAuditor(String),

    /// The presented credential is not registered or does not match the
    /// identity claiming it.
    #[error("credential for auditor {0} is not valid")]
    InvalidCredential(String),

    /// The credential has expired as of the decision time.
    #[error("credential for auditor {0} expired at {1}")]
    CredentialExpired(String, i64),

    /// A grant was defined without any scopes and without the `all` scope —
    /// it can never authorize anything, which is almost certainly a
    /// configuration error.
    #[error("grant for auditor {0} has no scopes")]
    EmptyGrant(String),

    /// A scope could not be built from the supplied parts.
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    /// The requested scope is not representable as a stable label.
    #[error("scope label rejected: {0}")]
    UnloggableScope(String),

    /// The authorizer was asked to record an access entry it could not
    /// persist (e.g. the store rejected the audit-access record).
    #[error("access entry could not be recorded: {0}")]
    AccessLogFailure(String),

    /// An internal invariant was violated (e.g. a grant table with an
    /// inconsistent role). This is a bug, not a policy outcome.
    #[error("internal authorization error: {0}")]
    Internal(String),
}

/// Convenience result alias for the authorization crate.
pub type AuthorizationResult<T> = Result<T, AuthorizationError>;
