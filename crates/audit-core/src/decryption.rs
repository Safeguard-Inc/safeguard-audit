//! The decryption boundary: legitimate view-key access behind a door.
//!
//! Confidential Token systems can expose private balances and transfer
//! amounts through an auditor/view-key mechanism. This repository never
//! invents that cryptography. What it *does* need is a narrow, neutral
//! door so that when the upstream Confidential Token architecture is
//! verified, an authorized integration can decrypt *permitted* data
//! through a [`DecryptionProvider`] — returning the minimum requested
//! information, never more, with every access attributable.
//!
//! ## Contract
//!
//! * A [`DecryptionRequest`] names the requester, the target, and exactly
//!   the fields requested; nothing is decrypted that was not requested.
//! * The provider authorizes the request against the upstream view-key
//!   scheme *before* decrypting anything; a refusal is an explicit error,
//!   never a silent empty result that a caller could mistake for success.
//! * A [`DecryptionResponse`] carries only granted fields. Decrypted
//!   values are transient: nothing here persists them, logs them, or
//!   places them on an audit record — private data does not belong in
//!   history, only the attributable fact that access occurred.
//!
//! ## What this module is not
//!
//! There is no key material, no decryption algorithm, and no mock that
//! pretends to be a security boundary. Implementations arrive only after
//! the upstream protocol is verified; until then the door stays closed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::errors::AuditError;
use crate::identifiers::{AuditorId, RequestId};
use crate::timestamps::Timestamp;

/// A request to decrypt specific fields of a target through the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionRequest {
    request_id: RequestId,
    requester: AuditorId,
    /// What the request targets (a record id, an evidence id, a token).
    target: String,
    /// Why the data is needed (an investigation id, a case reference).
    purpose: String,
    /// The fields requested, sorted and deduplicated.
    requested_fields: Vec<String>,
    /// When the request was made.
    requested_at: Timestamp,
}

impl DecryptionRequest {
    /// Builds a request, validating the labels and normalizing the field
    /// list to a sorted, duplicate-free set.
    ///
    /// `requested_fields` must name between 1 and 16 fields, each a
    /// 1-64 char non-space printable label. `target` is a bounded
    /// reference label (an identifier, not prose); `purpose` is bounded
    /// human-readable text naming a case or reason — never a secret.
    pub fn new(
        request_id: RequestId,
        requester: AuditorId,
        target: &str,
        purpose: &str,
        requested_fields: Vec<String>,
        requested_at: Timestamp,
    ) -> Result<Self, DecryptionError> {
        validate_label("target", target, 256)?;
        validate_purpose(purpose)?;
        if requested_fields.is_empty() || requested_fields.len() > 16 {
            return Err(DecryptionError::InvalidRequest(
                "requested_fields must name between 1 and 16 fields".into(),
            ));
        }
        let mut requested_fields = requested_fields;
        for field in &requested_fields {
            validate_label("field", field, 64)?;
        }
        requested_fields.sort();
        requested_fields.dedup();
        Ok(Self {
            request_id,
            requester,
            target: target.to_owned(),
            purpose: purpose.to_owned(),
            requested_fields,
            requested_at,
        })
    }

    /// The request id (echoed back in the response for correlation).
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Who requested the decryption.
    pub fn requester(&self) -> &AuditorId {
        &self.requester
    }

    /// What the request targets.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Why the data was requested.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The requested fields, sorted and duplicate-free.
    pub fn requested_fields(&self) -> &[String] {
        &self.requested_fields
    }

    /// When the request was made.
    pub fn requested_at(&self) -> Timestamp {
        self.requested_at
    }
}

fn validate_label(kind: &str, value: &str, max: usize) -> Result<(), DecryptionError> {
    let valid = (1..=max).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"');
    if valid {
        Ok(())
    } else {
        Err(DecryptionError::InvalidRequest(format!(
            "{kind} must be 1-{max} non-space printable ASCII chars"
        )))
    }
}

fn validate_purpose(purpose: &str) -> Result<(), DecryptionError> {
    let valid = (1..=512).contains(&purpose.len())
        && !purpose.trim().is_empty()
        && purpose.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if valid {
        Ok(())
    } else {
        Err(DecryptionError::InvalidRequest(
            "purpose must be 1-512 printable ASCII chars and not blank".into(),
        ))
    }
}

/// The minimum information a provider returned for a request.
///
/// The map carries only granted fields — the provider answers exactly the
/// requested set it authorized, nothing more. Decrypted values are
/// transient by contract: the audit layer never records them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionResponse {
    request_id: RequestId,
    fields: BTreeMap<String, String>,
}

impl DecryptionResponse {
    /// Builds a response echoing `request_id` with the granted fields.
    pub fn new(request_id: RequestId, fields: BTreeMap<String, String>) -> Self {
        Self { request_id, fields }
    }

    /// The request this responds to.
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The granted fields (keys are a subset of the requested fields).
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }
}

/// Errors raised by the decryption boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecryptionError {
    /// The request violated the boundary contract.
    #[error("invalid decryption request: {0}")]
    InvalidRequest(String),

    /// The requester is not an authorized view-key holder.
    #[error("decryption not authorized: {0}")]
    NotAuthorized(String),

    /// The request was authorized but the provider refused this access.
    #[error("decryption denied: {0}")]
    Denied(String),

    /// The provider could not complete the request.
    #[error("decryption failed: {0}")]
    Failed(String),
}

impl DecryptionError {
    /// Maps onto the core error taxonomy for uniform handling.
    pub fn into_core(self) -> AuditError {
        match self {
            Self::InvalidRequest(detail) => AuditError::ValidationFailure(detail),
            Self::NotAuthorized(detail) | Self::Denied(detail) => {
                AuditError::DecryptionAuthorizationFailure(detail)
            }
            Self::Failed(detail) => AuditError::Internal(detail),
        }
    }
}

/// A result alias for decryption operations.
pub type DecryptionResult<T> = Result<T, DecryptionError>;

/// A provider of legitimate view-key decryption.
///
/// Implementations are supplied by the verified upstream Confidential
/// Token architecture — never by this repository. A provider must
/// authorize the request before decrypting anything, return only the
/// granted subset of the requested fields, and never persist or log
/// decrypted values. The caller is responsible for attributing the
/// access (recording that it happened) through the audit-access
/// machinery; the fact of access is auditable, the decrypted data is not.
pub trait DecryptionProvider {
    /// The provider's own error type (usually [`DecryptionError`]).
    type Error: std::error::Error;

    /// A stable provider label, e.g. `confidential-token-view-key`.
    fn provider_name(&self) -> &str;

    /// Decrypts the authorized subset of `request.requested_fields` for
    /// `request.target`, returning exactly the minimum information the
    /// requester was granted.
    fn decrypt(&self, request: &DecryptionRequest) -> Result<DecryptionResponse, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::RequestId;

    fn request(fields: &[&str]) -> Result<DecryptionRequest, DecryptionError> {
        DecryptionRequest::new(
            RequestId::derive(&["req"]),
            AuditorId::derive(&["auditor-1"]),
            "rec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "investigation case-1",
            fields.iter().map(|f| (*f).to_owned()).collect(),
            Timestamp::from_unix_seconds(100),
        )
    }

    #[test]
    fn requests_validate_labels_and_purpose() {
        assert!(request(&["amount"]).is_ok());
        // Empty or over-long field lists are rejected.
        assert!(matches!(
            request(&[]),
            Err(DecryptionError::InvalidRequest(_))
        ));
        let many: Vec<String> = (0..17).map(|i| format!("f{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(request(&many).is_err());
        // Labels cannot carry spaces; purpose can be prose.
        assert!(request(&["has space"]).is_err());
        let empty_purpose = DecryptionRequest::new(
            RequestId::derive(&["r"]),
            AuditorId::derive(&["a"]),
            "rec_x",
            "   ",
            vec!["amount".into()],
            Timestamp::from_unix_seconds(0),
        );
        assert!(empty_purpose.is_err());
    }

    #[test]
    fn requested_fields_are_sorted_and_deduplicated() {
        let r = request(&["zeta", "amount", "alpha", "amount"]).unwrap();
        assert_eq!(r.requested_fields(), &["alpha", "amount", "zeta"]);
    }

    #[test]
    fn responses_echo_the_request() {
        let request_id = RequestId::derive(&["req-9"]);
        let response = DecryptionResponse::new(
            request_id.clone(),
            BTreeMap::from([("amount".into(), "1.5".into())]),
        );
        assert_eq!(response.request_id(), &request_id);
        assert_eq!(response.fields().len(), 1);
    }

    #[test]
    fn boundary_errors_map_onto_the_core_taxonomy() {
        assert!(matches!(
            DecryptionError::NotAuthorized("no view key".into()).into_core(),
            AuditError::DecryptionAuthorizationFailure(_)
        ));
        assert!(matches!(
            DecryptionError::Denied("policy".into()).into_core(),
            AuditError::DecryptionAuthorizationFailure(_)
        ));
        assert!(matches!(
            DecryptionError::InvalidRequest("bad".into()).into_core(),
            AuditError::ValidationFailure(_)
        ));
    }

    /// A request echo used only to exercise the trait. This is a test
    /// double for *typing* the boundary, not a security boundary: it
    /// performs no authorization and must never be used outside tests.
    struct EchoProvider;

    impl DecryptionProvider for EchoProvider {
        type Error = DecryptionError;
        fn provider_name(&self) -> &str {
            "test-echo"
        }
        fn decrypt(&self, request: &DecryptionRequest) -> DecryptionResult<DecryptionResponse> {
            let fields = request
                .requested_fields()
                .iter()
                .map(|f| (f.clone(), "granted".to_owned()))
                .collect();
            Ok(DecryptionResponse::new(
                request.request_id().clone(),
                fields,
            ))
        }
    }

    #[test]
    fn the_trait_is_implementable_over_the_boundary_types() {
        let provider = EchoProvider;
        let r = request(&["amount", "balance"]).unwrap();
        let response = provider.decrypt(&r).unwrap();
        assert_eq!(response.request_id(), r.request_id());
        let granted: Vec<&str> = response.fields().keys().map(String::as_str).collect();
        let requested: Vec<&str> = r.requested_fields().iter().map(String::as_str).collect();
        assert_eq!(granted, requested);
    }
}
