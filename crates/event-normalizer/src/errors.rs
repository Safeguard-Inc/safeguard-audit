//! Structured error taxonomy for the normalizer.
//!
//! Normalization fails in distinguishable ways and the pipeline must react
//! to the *kind* of failure: a malformed payload on one page is a skip or a
//! quarantine, while an unsupported scheme is a configuration problem.
//! Every variant therefore carries the scheme label it concerns, and the
//! whole taxonomy maps onto the core [`AuditError`] classes so the indexer
//! can treat all pipeline errors uniformly.
//!
//! ## Privacy rule
//!
//! Error messages carry identifiers and short descriptions — never payload
//! contents that could hold protected values. A malformed *envelope* is
//! reported with a code and a structural description, not the offending
//! JSON.
//!
//! [`AuditError`]: safeguard_audit_core::AuditError

use safeguard_audit_core::AuditError;

/// The structured error type for normalization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizerError {
    /// The item named a scheme this build does not implement.
    #[error("unsupported scheme `{0}`")]
    UnsupportedScheme(String),

    /// The scheme is known but the payload version is not supported.
    #[error("unsupported {scheme} payload version {version}: {detail}")]
    UnsupportedVersion {
        /// The scheme label.
        scheme: &'static str,
        /// The version the payload declared.
        version: String,
        /// Why it is unsupported (expected range).
        detail: String,
    },

    /// The payload was not decodable JSON or not the expected shape.
    #[error("malformed {scheme} payload: {detail}")]
    MalformedPayload {
        /// The scheme label.
        scheme: &'static str,
        /// Structural description of what was wrong.
        detail: String,
    },

    /// The payload decoded but violated semantic rules.
    #[error("invalid {scheme} payload: {detail}")]
    ValidationFailed {
        /// The scheme label.
        scheme: &'static str,
        /// Which rule was violated.
        detail: String,
    },

    /// The payload was valid but could not be projected onto the envelope.
    #[error("cannot classify {scheme} payload: {detail}")]
    ClassificationFailed {
        /// The scheme label.
        scheme: &'static str,
        /// Why projection failed.
        detail: String,
    },
}

impl NormalizerError {
    /// Maps onto the core error taxonomy for uniform pipeline handling.
    pub fn into_core(self) -> AuditError {
        match self {
            Self::UnsupportedScheme(s) => {
                AuditError::UnsupportedEvent(format!("ingestion scheme `{s}` is not supported"))
            }
            Self::UnsupportedVersion {
                scheme,
                version,
                detail,
            } => AuditError::UnsupportedEventVersion(format!(
                "{scheme} payload version {version}: {detail}"
            )),
            Self::MalformedPayload { scheme, detail } => {
                AuditError::InvalidEvent(format!("malformed {scheme} payload: {detail}"))
            }
            Self::ValidationFailed { scheme, detail } => {
                AuditError::InvalidEvent(format!("invalid {scheme} payload: {detail}"))
            }
            Self::ClassificationFailed { scheme, detail } => {
                AuditError::InvalidEvent(format!("cannot classify {scheme} payload: {detail}"))
            }
        }
    }
}

/// A result alias for normalization operations.
pub type NormalizerResult<T> = Result<T, NormalizerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_map_onto_the_core_taxonomy() {
        assert!(matches!(
            NormalizerError::UnsupportedScheme("rpc-events".into()).into_core(),
            AuditError::UnsupportedEvent(_)
        ));
        assert!(matches!(
            NormalizerError::UnsupportedVersion {
                scheme: "audit-envelope",
                version: "9".into(),
                detail: "supported: 1".into(),
            }
            .into_core(),
            AuditError::UnsupportedEventVersion(_)
        ));
        assert!(matches!(
            NormalizerError::MalformedPayload {
                scheme: "hooks-state-event",
                detail: "not valid JSON".into(),
            }
            .into_core(),
            AuditError::InvalidEvent(_)
        ));
        assert!(matches!(
            NormalizerError::ValidationFailed {
                scheme: "hooks-state-event",
                detail: "unknown type".into(),
            }
            .into_core(),
            AuditError::InvalidEvent(_)
        ));
        assert!(matches!(
            NormalizerError::ClassificationFailed {
                scheme: "audit-envelope",
                detail: "kind not supported".into(),
            }
            .into_core(),
            AuditError::InvalidEvent(_)
        ));
    }

    #[test]
    fn errors_are_comparable_for_tests() {
        let a = NormalizerError::ValidationFailed {
            scheme: "audit-envelope",
            detail: "missing event_id".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(
            a,
            NormalizerError::ValidationFailed {
                scheme: "audit-envelope",
                detail: "different failure".into(),
            }
        );
    }
}
