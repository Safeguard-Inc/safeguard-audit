//! The authorizer: identity + action + scope + credential → decision.
//!
//! [`Authorizer`] composes the registry, the role matrix, scope
//! containment, and credential verification into one call:
//!
//! ```text
//! authorize(auditor, action, requested_scope)
//!   1. credential valid (registered, unexpired, unrevoked)?
//!   2. role grants the action?
//!   3. a granted scope contains the requested scope?
//!   ──► AuthorizationDecision (granted / denied / out-of-scope)
//! ```
//!
//! The order matters and is the API contract:
//!
//! 1. **Credential first.** An expired or missing credential is `Denied`
//!    regardless of permissions — identity lapses before policy is even
//!    consulted.
//! 2. **Action next.** If the role does not grant the action, the decision
//!    is `Denied` — no scope can rescue an action the role may not take.
//! 3. **Scope last.** If the action is allowed but the requested scope is
//!    outside every granted scope, the decision is `OutOfScope` — a
//!    distinct, meaningful outcome, not a blanket denial.
//!
//! Every decision is attributed (`decided_by`, `decided_at` via the
//! injected clock) so it can be recorded as an `audit-access` event. The
//! authorizer itself never writes to a store — recording the decision is
//! the access log's job, keeping this service pure and testable.

use safeguard_audit_core::{
    AccessAction, AccessEntryId, AccessScope, AuditAccessEntry, AuditorId, AuthorizationDecision,
    Clock, Timestamp,
};

use crate::credentials::CredentialStatus;
use crate::errors::{AuthorizationError, AuthorizationResult};
use crate::registry::Registry;
use crate::scopes;

/// Stable reason codes attached to decisions.
pub mod reason {
    /// The credential was valid and the decision was a grant.
    pub const GRANTED: &str = "GRANTED";
    /// No registered credential could be verified.
    pub const CREDENTIAL_INVALID: &str = "CREDENTIAL_INVALID";
    /// The credential expired before the decision time.
    pub const CREDENTIAL_EXPIRED: &str = "CREDENTIAL_EXPIRED";
    /// The role does not grant the requested action.
    pub const ACTION_DENIED: &str = "ACTION_DENIED";
    /// The action is allowed but no granted scope contains the request.
    pub const SCOPE_OUT_OF_BOUNDS: &str = "SCOPE_OUT_OF_BOUNDS";
    /// The auditor is not registered.
    pub const UNKNOWN_AUDITOR: &str = "UNKNOWN_AUDITOR";
}

/// What happened to the credential during a decision, for logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCheck {
    /// Whether a credential was registered for the auditor.
    pub present: bool,
    /// The verification outcome (meaningful only when `present`).
    pub status: CredentialStatus,
}

/// The authorization service.
pub struct Authorizer {
    registry: Registry,
    clock: Box<dyn Clock>,
}

impl Authorizer {
    /// Builds an authorizer over `registry`, stamping decisions with
    /// `clock` (deterministic in tests, wall-clock in production).
    pub fn new(registry: Registry, clock: impl Clock + 'static) -> Self {
        Self {
            registry,
            clock: Box::new(clock),
        }
    }

    /// The registry backing this authorizer.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Evaluates one access request to an attributed decision.
    ///
    /// Never panics on unknown auditors or expired credentials — those are
    /// `Denied` outcomes with distinct reasons. The decision is *pure*:
    /// nothing is recorded; callers pass it to an access log when they
    /// want the audit-access event.
    pub fn authorize(
        &self,
        auditor: &AuditorId,
        action: AccessAction,
        requested_scope: &AccessScope,
    ) -> AuthorizationResult<AuthorizationDecision> {
        let now = Timestamp::now(self.clock.as_ref());
        let scope_label = requested_scope.describe();

        // 1. Identity + credential.
        let grant = match self.registry.grant(auditor) {
            Ok(g) => g,
            Err(AuthorizationError::UnknownAuditor(_)) => {
                return Ok(decision(
                    false,
                    action,
                    &scope_label,
                    Some(auditor.clone()),
                    now,
                    reason::UNKNOWN_AUDITOR,
                ));
            }
            Err(e) => return Err(e),
        };

        let credential_check = match &grant.credential {
            Some(cred) => {
                let status = match cred.verify(auditor, now) {
                    Ok(()) => CredentialStatus::Valid,
                    Err(AuthorizationError::CredentialExpired(..)) => CredentialStatus::Expired,
                    Err(_) => CredentialStatus::Mismatch,
                };
                CredentialCheck {
                    present: true,
                    status,
                }
            }
            None => CredentialCheck {
                present: false,
                status: CredentialStatus::Absent,
            },
        };

        if credential_check.status != CredentialStatus::Valid {
            let reason = match credential_check.status {
                CredentialStatus::Expired => reason::CREDENTIAL_EXPIRED,
                _ => reason::CREDENTIAL_INVALID,
            };
            return Ok(decision(
                false,
                action,
                &scope_label,
                Some(auditor.clone()),
                now,
                reason,
            ));
        }

        // 2. Action within the role's permission set.
        if !grant.permissions().allows(action) {
            return Ok(decision(
                false,
                action,
                &scope_label,
                Some(auditor.clone()),
                now,
                reason::ACTION_DENIED,
            ));
        }

        // 3. Scope containment.
        if !scopes::any_contains(&grant.scopes, requested_scope) {
            return Ok(decision(
                false,
                action,
                &scope_label,
                Some(auditor.clone()),
                now,
                reason::SCOPE_OUT_OF_BOUNDS,
            ));
        }

        Ok(decision(
            true,
            action,
            &scope_label,
            Some(auditor.clone()),
            now,
            reason::GRANTED,
        ))
    }

    /// The credential state for an auditor, used by the access log to
    /// explain denied decisions.
    pub fn credential_status(&self, auditor: &AuditorId) -> AuthorizationResult<CredentialCheck> {
        let now = Timestamp::now(self.clock.as_ref());
        let grant = self.registry.grant(auditor)?;
        match &grant.credential {
            Some(cred) => {
                let status = match cred.verify(auditor, now) {
                    Ok(()) => CredentialStatus::Valid,
                    Err(AuthorizationError::CredentialExpired(..)) => CredentialStatus::Expired,
                    Err(_) => CredentialStatus::Mismatch,
                };
                Ok(CredentialCheck {
                    present: true,
                    status,
                })
            }
            None => Ok(CredentialCheck {
                present: false,
                status: CredentialStatus::Absent,
            }),
        }
    }

    /// Builds the `audit-access` entry for a decision.
    ///
    /// The entry id is derived deterministically from the actor, action,
    /// scope, and decision time, so replaying the same decision produces
    /// the same entry id (idempotent access logging).
    pub fn entry_for_decision(
        &self,
        decision: &AuthorizationDecision,
        target: Option<&str>,
    ) -> AuthorizationResult<AuditAccessEntry> {
        let auditor = decision
            .decided_by()
            .ok_or_else(|| AuthorizationError::Internal("decision lacks attribution".into()))?;
        let entry_id = AccessEntryId::derive(&[
            auditor.as_str(),
            decision.action().as_str(),
            decision.scope(),
            &decision.decided_at().as_unix_seconds().to_string(),
        ]);
        let result = if decision.allowed() {
            safeguard_audit_core::AccessResult::Granted
        } else if decision.reason() == Some(reason::SCOPE_OUT_OF_BOUNDS) {
            safeguard_audit_core::AccessResult::OutOfScope
        } else {
            safeguard_audit_core::AccessResult::Denied
        };
        Ok(AuditAccessEntry::new(
            entry_id,
            auditor.clone(),
            decision.action(),
            decision.scope().to_owned(),
            target.map(str::to_owned),
            result,
            decision.decided_at(),
        ))
    }
}

/// Builds an attributed decision.
fn decision(
    allowed: bool,
    action: AccessAction,
    scope: &str,
    decided_by: Option<AuditorId>,
    decided_at: Timestamp,
    reason: &'static str,
) -> AuthorizationDecision {
    AuthorizationDecision::new(allowed, action, scope.to_owned(), decided_by, decided_at)
        .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Credential;
    use crate::registry::{Grant, Registry};
    use safeguard_audit_core::{
        AccessScope, AuditorId, AuditorRole, FixedClock, NetworkId, Timestamp,
    };

    fn aud(n: &str) -> AuditorId {
        AuditorId::derive(&[n])
    }

    fn net() -> AccessScope {
        AccessScope::Network(NetworkId::new(NetworkId::TESTNET).unwrap())
    }

    fn other_net() -> AccessScope {
        AccessScope::Network(NetworkId::new(NetworkId::MAINNET).unwrap())
    }

    fn clock_at(secs: i64) -> impl Clock {
        FixedClock::at(Timestamp::from_unix_seconds(secs))
    }

    fn authorizer_with(grant: Grant, now: i64) -> Authorizer {
        let mut registry = Registry::new();
        registry.register(grant).unwrap();
        Authorizer::new(registry, clock_at(now))
    }

    fn grant_with_credential(n: &str, role: AuditorRole, expiry: i64) -> Grant {
        Grant::new(aud(n), role)
            .with_scope(net())
            .with_credential(Credential::new(
                aud(n),
                "material",
                Timestamp::from_unix_seconds(expiry),
            ))
    }

    #[test]
    fn grants_within_scope() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Auditor, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::ReadRecord, &net())
            .unwrap();
        assert!(decision.allowed());
        assert_eq!(decision.reason(), Some(reason::GRANTED));
        assert_eq!(decision.decided_by(), Some(&aud("a1")));
    }

    #[test]
    fn denies_actions_the_role_may_not_take() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::ReadOnlyReviewer, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::GenerateReport, &net())
            .unwrap();
        assert!(!decision.allowed());
        assert_eq!(decision.reason(), Some(reason::ACTION_DENIED));
    }

    #[test]
    fn out_of_scope_is_distinct_from_denied() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Auditor, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::ReadRecord, &other_net())
            .unwrap();
        assert!(!decision.allowed());
        assert_eq!(decision.reason(), Some(reason::SCOPE_OUT_OF_BOUNDS));
    }

    #[test]
    fn expired_credentials_deny_before_scope_is_consulted() {
        // Credential expires at 2_000; decision time is 3_000.
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Administrator, 2_000),
            3_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::ReadRecord, &net())
            .unwrap();
        assert!(!decision.allowed());
        assert_eq!(decision.reason(), Some(reason::CREDENTIAL_EXPIRED));
    }

    #[test]
    fn unknown_auditors_are_denied_not_errors() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Auditor, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("ghost"), AccessAction::ReadRecord, &net())
            .unwrap();
        assert!(!decision.allowed());
        assert_eq!(decision.reason(), Some(reason::UNKNOWN_AUDITOR));
    }

    #[test]
    fn entries_are_deterministic_and_attributed() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Auditor, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::ReadRecord, &net())
            .unwrap();
        let entry = authorizer
            .entry_for_decision(&decision, Some("rec_abcd"))
            .unwrap();
        let again = authorizer
            .entry_for_decision(&decision, Some("rec_abcd"))
            .unwrap();
        assert_eq!(entry.entry_id(), again.entry_id());
        assert_eq!(entry.auditor(), &aud("a1"));
        assert_eq!(entry.action(), AccessAction::ReadRecord);
        assert_eq!(entry.target(), Some("rec_abcd"));
    }

    #[test]
    fn out_of_scope_decisions_record_out_of_scope_results() {
        let authorizer = authorizer_with(
            grant_with_credential("a1", AuditorRole::Auditor, 5_000),
            1_000,
        );
        let decision = authorizer
            .authorize(&aud("a1"), AccessAction::ReadRecord, &other_net())
            .unwrap();
        let entry = authorizer.entry_for_decision(&decision, None).unwrap();
        assert_eq!(
            entry.result(),
            safeguard_audit_core::AccessResult::OutOfScope
        );
    }
}
