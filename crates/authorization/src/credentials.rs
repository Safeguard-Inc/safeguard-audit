//! Auditor credentials.
//!
//! An [`AuditorIdentity`] says *who is acting*; a [`Credential`] proves
//! they may still act. This crate does not implement credential
//! cryptography — signatures, keys, and tokens are validated by an
//! upstream identity provider. What the authorizer needs from a credential
//! is a small, verifiable contract:
//!
//! * it is registered for the claiming auditor,
//! * it has not expired as of the decision time,
//! * it is not revoked, and
//! * it can be presented as a stable reference for access logging.
//!
//! Expiry is checked against an injected clock, never the wall clock
//! directly, so decisions stay reproducible in tests and replay.

use safeguard_audit_core::{AuditorId, Timestamp};

use crate::errors::{AuthorizationError, AuthorizationResult};

/// A registered credential for an auditor.
///
/// `material` is deliberately opaque: it is whatever the upstream identity
/// provider issued (a token id, a key fingerprint, a reference). The
/// authorizer never interprets it, and it is never written to an audit
/// record — only the credential's stable reference may be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    auditor: AuditorId,
    /// Opaque material issued by the identity provider.
    material: String,
    /// The instant after which this credential no longer authorizes.
    expires_at: Timestamp,
    /// Whether an administrator has revoked it (revocation is checked
    /// before expiry: a revoked credential fails even if unexpired).
    revoked: bool,
}

impl Credential {
    /// Registers a credential valid until `expires_at`.
    pub fn new(auditor: AuditorId, material: impl Into<String>, expires_at: Timestamp) -> Self {
        Self {
            auditor,
            material: material.into(),
            expires_at,
            revoked: false,
        }
    }

    /// Marks the credential revoked.
    pub fn revoke(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// The auditor this credential belongs to.
    pub fn auditor(&self) -> &AuditorId {
        &self.auditor
    }

    /// The stable reference usable in access logs (never the material
    /// itself).
    pub fn reference(&self) -> String {
        // A hash of the material identifies *which* credential was used
        // without ever exposing the credential itself.
        safeguard_audit_core::identifiers::sha256_hex(self.material.as_bytes())
    }

    /// When this credential expires.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Whether this credential is currently valid at `now`.
    ///
    /// A credential is valid when registered, not revoked, and not
    /// expired. No other conditions exist here — stronger checks belong to
    /// the upstream identity provider.
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        !self.revoked && !self.expired_at(now)
    }

    /// Whether the credential has expired at `now`.
    pub fn expired_at(&self, now: Timestamp) -> bool {
        now.is_at_or_after(self.expires_at)
    }

    /// Whether the credential was revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Validates the credential for `claiming` auditor at `now`.
    ///
    /// Returns a descriptive error so a caller can distinguish a wrong
    /// credential from an expired one. A *valid* result means: belongs to
    /// `claiming`, not revoked, not expired.
    pub fn verify(&self, claiming: &AuditorId, now: Timestamp) -> AuthorizationResult<()> {
        if &self.auditor != claiming {
            return Err(AuthorizationError::InvalidCredential(
                self.auditor.as_str().to_owned(),
            ));
        }
        if self.revoked {
            return Err(AuthorizationError::InvalidCredential(
                self.auditor.as_str().to_owned(),
            ));
        }
        if self.expired_at(now) {
            return Err(AuthorizationError::CredentialExpired(
                self.auditor.as_str().to_owned(),
                self.expires_at.as_unix_seconds(),
            ));
        }
        Ok(())
    }
}

/// The credential verification outcome, kept for the access log so an
/// auditor can later explain *why* an access was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential verified at the decision time.
    Valid,
    /// No credential was presented.
    Absent,
    /// The credential belongs to a different auditor.
    Mismatch,
    /// The credential was revoked.
    Revoked,
    /// The credential expired at the decision time.
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{AuditorId, Timestamp};

    fn aud(n: &str) -> AuditorId {
        AuditorId::derive(&[n])
    }

    #[test]
    fn valid_credentials_verify() {
        let now = Timestamp::from_unix_seconds(1_000);
        let cred = Credential::new(
            aud("a1"),
            "token-material",
            Timestamp::from_unix_seconds(2_000),
        );
        assert!(cred.verify(&aud("a1"), now).is_ok());
        assert_eq!(cred.expires_at().as_unix_seconds(), 2_000);
        assert!(cred.is_valid_at(now));
    }

    #[test]
    fn expiry_is_checked_against_now() {
        let expiry = Timestamp::from_unix_seconds(1_000);
        let cred = Credential::new(aud("a1"), "material", expiry);
        // At the expiry instant the credential is already expired.
        assert!(cred.verify(&aud("a1"), expiry).is_err());
        assert!(cred.expired_at(expiry));
        assert!(cred
            .verify(&aud("a1"), Timestamp::from_unix_seconds(999))
            .is_ok());
    }

    #[test]
    fn revocation_wins_over_expiry_and_identity() {
        let cred =
            Credential::new(aud("a1"), "material", Timestamp::from_unix_seconds(2_000)).revoke();
        assert!(cred.is_revoked());
        assert!(cred
            .verify(&aud("a1"), Timestamp::from_unix_seconds(1_000))
            .is_err());
    }

    #[test]
    fn wrong_auditor_cannot_use_the_credential() {
        let now = Timestamp::from_unix_seconds(1_000);
        let cred = Credential::new(aud("a1"), "material", Timestamp::from_unix_seconds(2_000));
        assert!(cred.verify(&aud("a2"), now).is_err());
        assert_eq!(
            cred.verify(&aud("a2"), now).unwrap_err(),
            AuthorizationError::InvalidCredential(aud("a1").as_str().to_owned())
        );
    }

    #[test]
    fn references_never_expose_material() {
        let cred = Credential::new(
            aud("a1"),
            "super-secret-token",
            Timestamp::from_unix_seconds(2_000),
        );
        let reference = cred.reference();
        assert!(!reference.contains("secret"));
        assert_eq!(reference.len(), 64); // sha256 hex
                                         // The same material derives the same reference.
        let again = Credential::new(
            aud("a1"),
            "super-secret-token",
            Timestamp::from_unix_seconds(2_000),
        );
        assert_eq!(again.reference(), reference);
    }
}
