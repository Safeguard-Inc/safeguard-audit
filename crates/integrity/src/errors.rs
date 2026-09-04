//! Error surface for the integrity crate.
//!
//! Most integrity operations report through the core vocabulary
//! ([`IntegrityStatus`], [`VerificationOutcome`],
//! [`VerificationFailure`]) rather than errors — a digest mismatch is a
//! *result*, not a failure to verify. Errors here are reserved for the
//! operations that cannot run at all: building a manifest over an
//! incoherent range, or serializing a record that cannot be canonicalized.

use safeguard_audit_core::AuditError;

/// A failure to perform an integrity operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// A manifest range or argument was incoherent.
    #[error("invalid integrity arguments: {0}")]
    InvalidArguments(String),

    /// A record could not be canonicalized (should never happen for the
    /// domain types; surfaced rather than hidden).
    #[error("cannot canonicalize record {0}: {1}")]
    Canonicalization(String, String),
}

impl IntegrityError {
    /// Maps onto the core taxonomy.
    pub fn into_core(self) -> AuditError {
        match self {
            Self::InvalidArguments(d) => AuditError::ValidationFailure(d),
            Self::Canonicalization(id, d) => AuditError::SerializationFailure(format!("{id}: {d}")),
        }
    }
}

/// A result alias for integrity crate operations.
pub type IntegrityResult<T> = Result<T, IntegrityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_onto_the_core_taxonomy() {
        assert!(matches!(
            IntegrityError::InvalidArguments("start > end".into()).into_core(),
            AuditError::ValidationFailure(_)
        ));
        assert!(matches!(
            IntegrityError::Canonicalization("rec_x".into(), "boom".into()).into_core(),
            AuditError::SerializationFailure(_)
        ));
    }
}
