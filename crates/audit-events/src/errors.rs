//! Error taxonomy for the semantic event layer.
//!
//! These errors describe *interpretation* failures — the event exists but
//! this layer could not parse, classify, or project it. They map onto the
//! core [`AuditError`] classes so the pipeline can treat them uniformly.

use safeguard_audit_core::AuditError;

/// An error produced while interpreting a raw event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// The event type is not in the supported registry.
    #[error("unsupported event type: {0}")]
    UnsupportedEventType(String),

    /// The event's version predates or postdates this build.
    #[error("unsupported event version: {0}")]
    UnsupportedEventVersion(String),

    /// The event payload is structurally malformed.
    #[error("malformed event payload: {0}")]
    MalformedPayload(String),

    /// A required field is absent.
    #[error("missing field: {0}")]
    MissingField(String),

    /// A field has an invalid value.
    #[error("invalid value for {field}: {detail}")]
    InvalidFieldValue {
        /// Which field failed.
        field: String,
        /// Why.
        detail: String,
    },

    /// Ordering metadata is ambiguous or contradictory.
    #[error("ambiguous ordering: {0}")]
    AmbiguousOrder(String),

    /// The event cannot be derived from the given sources.
    #[error("not derivable: {0}")]
    NotDerivable(String),
}

impl EventError {
    /// Maps an event-layer error onto the core error taxonomy.
    pub fn into_core(self) -> AuditError {
        match self {
            Self::UnsupportedEventType(d) => AuditError::UnsupportedEvent(d),
            Self::UnsupportedEventVersion(d) => AuditError::UnsupportedEventVersion(d),
            Self::MalformedPayload(d) | Self::MissingField(d) | Self::AmbiguousOrder(d) => {
                AuditError::InvalidEvent(d)
            }
            Self::InvalidFieldValue { field, detail } => {
                AuditError::InvalidEvent(format!("invalid value for {field}: {detail}"))
            }
            Self::NotDerivable(d) => AuditError::InvalidEvent(d),
        }
    }
}

/// A result alias for the event layer.
pub type EventResult<T> = Result<T, EventError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_onto_the_core_taxonomy() {
        assert!(matches!(
            EventError::UnsupportedEventType("x".into()).into_core(),
            AuditError::UnsupportedEvent(_)
        ));
        assert!(matches!(
            EventError::UnsupportedEventVersion("2".into()).into_core(),
            AuditError::UnsupportedEventVersion(_)
        ));
        assert!(matches!(
            EventError::MissingField("token".into()).into_core(),
            AuditError::InvalidEvent(_)
        ));
        assert!(matches!(
            EventError::InvalidFieldValue {
                field: "index".into(),
                detail: "negative".into()
            }
            .into_core(),
            AuditError::InvalidEvent(_)
        ));
    }
}
