//! The auditor registry: who holds which role, scopes, and credentials.
//!
//! The registry is the authorizer's source of truth. It answers three
//! questions:
//!
//! * Does this identity exist, and which role does it hold?
//! * Which scopes are granted to it?
//! * Which credential may it present?
//!
//! Grants and revocations are recorded here *and* surface as
//! `authorization-changed` events via `audit-events`, so role history is
//! itself auditable. The registry is deliberately in-memory: persistence
//! of the grant table is a deployment concern (the audit store records the
//! *history*; the registry holds the *current* state).

use std::collections::BTreeMap;

use safeguard_audit_core::{AccessScope, AuditorId, AuditorRole};

use crate::credentials::Credential;
use crate::errors::{AuthorizationError, AuthorizationResult};
use crate::permissions::PermissionSet;

/// One auditor's effective authorization: role-derived permissions plus
/// explicitly granted scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The identity this grant belongs to.
    pub auditor: AuditorId,
    /// The role the identity holds (baseline for permissions).
    pub role: AuditorRole,
    /// The scopes the identity may operate within.
    pub scopes: Vec<AccessScope>,
    /// The registered credential, when one exists.
    pub credential: Option<Credential>,
}

impl Grant {
    /// Builds a grant with no scopes (which the registry rejects at
    /// insertion — a scope-less grant can never authorize anything).
    pub fn new(auditor: AuditorId, role: AuditorRole) -> Self {
        Self {
            auditor,
            role,
            scopes: Vec::new(),
            credential: None,
        }
    }

    /// Adds a scope to the grant.
    pub fn with_scope(mut self, scope: AccessScope) -> Self {
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
        }
        self
    }

    /// Attaches a credential.
    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// The effective permission set for this grant.
    pub fn permissions(&self) -> PermissionSet {
        PermissionSet::from_role(self.role)
    }
}

/// The in-memory grant table.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    grants: BTreeMap<AuditorId, Grant>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces the grant for an auditor.
    ///
    /// A grant must carry at least one scope — an auditor with no scopes
    /// could never be authorized, which is a configuration error, not a
    /// policy outcome.
    pub fn register(&mut self, grant: Grant) -> AuthorizationResult<()> {
        if grant.scopes.is_empty() {
            return Err(AuthorizationError::EmptyGrant(
                grant.auditor.as_str().to_owned(),
            ));
        }
        grant.permissions().validate()?;
        self.grants.insert(grant.auditor.clone(), grant);
        Ok(())
    }

    /// Revokes an auditor's grant entirely.
    ///
    /// Returns whether the auditor was previously registered.
    pub fn revoke(&mut self, auditor: &AuditorId) -> bool {
        self.grants.remove(auditor).is_some()
    }

    /// Fetches the grant for an auditor.
    pub fn grant(&self, auditor: &AuditorId) -> AuthorizationResult<&Grant> {
        self.grants
            .get(auditor)
            .ok_or_else(|| AuthorizationError::UnknownAuditor(auditor.as_str().to_owned()))
    }

    /// Fetches the grant mutably (used by the authorizer's access log).
    pub fn grant_mut(&mut self, auditor: &AuditorId) -> AuthorizationResult<&mut Grant> {
        self.grants
            .get_mut(auditor)
            .ok_or_else(|| AuthorizationError::UnknownAuditor(auditor.as_str().to_owned()))
    }

    /// Whether an auditor is registered.
    pub fn contains(&self, auditor: &AuditorId) -> bool {
        self.grants.contains_key(auditor)
    }

    /// The number of registered auditors.
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no auditors are registered.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Iterates all grants in stable auditor-id order.
    pub fn iter(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{AccessScope, AuditorId, AuditorRole, NetworkId};

    fn aud(n: &str) -> AuditorId {
        AuditorId::derive(&[n])
    }

    fn net() -> AccessScope {
        AccessScope::Network(NetworkId::new(NetworkId::TESTNET).unwrap())
    }

    #[test]
    fn grants_require_at_least_one_scope() {
        let mut registry = Registry::new();
        assert!(registry
            .register(Grant::new(aud("a1"), AuditorRole::Auditor))
            .is_err());
        assert!(registry
            .register(Grant::new(aud("a1"), AuditorRole::Auditor).with_scope(net()))
            .is_ok());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn grants_are_replaceable_and_revocable() {
        let mut registry = Registry::new();
        registry
            .register(Grant::new(aud("a1"), AuditorRole::Auditor).with_scope(net()))
            .unwrap();
        registry
            .register(Grant::new(aud("a1"), AuditorRole::SeniorAuditor).with_scope(net()))
            .unwrap();
        assert_eq!(
            registry.grant(&aud("a1")).unwrap().role,
            AuditorRole::SeniorAuditor
        );
        assert!(registry.revoke(&aud("a1")));
        assert!(!registry.revoke(&aud("a1")));
        assert!(registry.grant(&aud("a1")).is_err());
    }

    #[test]
    fn unknown_auditors_are_reported_cleanly() {
        let registry = Registry::new();
        assert!(registry.grant(&aud("ghost")).is_err());
    }

    #[test]
    fn permissions_follow_the_role_baseline() {
        let mut registry = Registry::new();
        registry
            .register(Grant::new(aud("a1"), AuditorRole::ReadOnlyReviewer).with_scope(net()))
            .unwrap();
        let perms = registry.grant(&aud("a1")).unwrap().permissions();
        assert!(perms.allows(safeguard_audit_core::AccessAction::ReadRecord));
        assert!(!perms.allows(safeguard_audit_core::AccessAction::GenerateReport));
    }
}
