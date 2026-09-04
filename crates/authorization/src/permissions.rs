//! Per-identity permission sets.
//!
//! A [`PermissionSet`] answers one question: "may this identity perform
//! this action?" Sets are seeded from the role matrix (`roles`) and may
//! carry explicit per-identity overrides. Overrides are strictly
//! *additive* or *subtractive* grants applied to the role baseline — the
//! set always knows its role, so audit tooling can explain *why* an action
//! is allowed (role baseline vs. override) rather than presenting an
//! opaque boolean.

use safeguard_audit_core::{AccessAction, AuditorRole};

use crate::errors::{AuthorizationError, AuthorizationResult};

/// The actions an identity may perform, derived from a role baseline plus
/// explicit overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSet {
    role: AuditorRole,
    /// Actions explicitly added beyond the role baseline.
    additions: Vec<AccessAction>,
    /// Actions explicitly removed from the role baseline.
    removals: Vec<AccessAction>,
}

impl PermissionSet {
    /// Seeds a set from the default role matrix.
    pub fn from_role(role: AuditorRole) -> Self {
        Self {
            role,
            additions: Vec::new(),
            removals: Vec::new(),
        }
    }

    /// The role this set is based on.
    pub fn role(&self) -> AuditorRole {
        self.role
    }

    /// Adds an action beyond the role baseline.
    pub fn allow(mut self, action: AccessAction) -> Self {
        self.removals.retain(|a| *a != action);
        if !self.additions.contains(&action) {
            self.additions.push(action);
        }
        self
    }

    /// Removes an action from the effective set, even if the role baseline
    /// grants it.
    pub fn deny(mut self, action: AccessAction) -> Self {
        self.additions.retain(|a| *a != action);
        // A removal entry only matters when the role baseline grants the
        // action; denying an action the role never granted just cancels
        // any prior addition.
        if crate::roles::role_allows(self.role, action) && !self.removals.contains(&action) {
            self.removals.push(action);
        }
        self
    }

    /// Whether the action is permitted.
    pub fn allows(&self, action: AccessAction) -> bool {
        if self.removals.contains(&action) {
            return false;
        }
        self.additions.contains(&action)
            || crate::roles::actions_for_role(self.role).contains(&action)
    }

    /// Every action currently permitted, in stable (label) order.
    pub fn effective(&self) -> Vec<AccessAction> {
        let mut set: Vec<AccessAction> = crate::roles::actions_for_role(self.role).to_vec();
        for action in &self.additions {
            if !set.contains(action) {
                set.push(*action);
            }
        }
        for action in &self.removals {
            set.retain(|a| a != action);
        }
        set.sort_by_key(AccessAction::as_str);
        set
    }

    /// Explains why an action is or is not permitted, for audit tooling.
    pub fn explain(&self, action: AccessAction) -> PermissionReason {
        if self.removals.contains(&action) {
            return PermissionReason::ExplicitlyDenied;
        }
        if self.additions.contains(&action) {
            return PermissionReason::GrantedByOverride;
        }
        if crate::roles::role_allows(self.role, action) {
            return PermissionReason::GrantedByRole;
        }
        PermissionReason::NotGranted
    }

    /// Validates the set: overrides that duplicate the role baseline are
    /// rejected as noise (an add of a baseline action or a remove of an
    /// action the role never granted).
    pub fn validate(&self) -> AuthorizationResult<()> {
        for action in &self.additions {
            if crate::roles::role_allows(self.role, *action) {
                return Err(AuthorizationError::Internal(format!(
                    "action {:?} is already granted by role {}",
                    action,
                    self.role.as_str()
                )));
            }
        }
        for action in &self.removals {
            if !crate::roles::role_allows(self.role, *action) {
                return Err(AuthorizationError::Internal(format!(
                    "action {:?} is not granted by role {} and cannot be removed",
                    action,
                    self.role.as_str()
                )));
            }
        }
        Ok(())
    }
}

/// Why a permission check returned what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionReason {
    /// The role baseline grants the action.
    GrantedByRole,
    /// An explicit per-identity override granted it.
    GrantedByOverride,
    /// An explicit per-identity override revoked it.
    ExplicitlyDenied,
    /// Neither the role nor any override grants it.
    NotGranted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{AccessAction, AuditorRole};

    #[test]
    fn role_baseline_is_the_default() {
        let set = PermissionSet::from_role(AuditorRole::Auditor);
        assert!(set.allows(AccessAction::ReadRecord));
        assert!(set.allows(AccessAction::InspectDenied));
        assert!(!set.allows(AccessAction::GenerateReport));
        assert_eq!(
            set.explain(AccessAction::ReadRecord),
            PermissionReason::GrantedByRole
        );
        assert_eq!(
            set.explain(AccessAction::GenerateReport),
            PermissionReason::NotGranted
        );
    }

    #[test]
    fn overrides_are_strictly_additive_and_subtractive() {
        let set = PermissionSet::from_role(AuditorRole::Auditor)
            .allow(AccessAction::GenerateReport)
            .deny(AccessAction::InspectDenied);
        set.validate().unwrap();
        assert!(set.allows(AccessAction::GenerateReport));
        assert!(!set.allows(AccessAction::InspectDenied));
        assert_eq!(
            set.explain(AccessAction::GenerateReport),
            PermissionReason::GrantedByOverride
        );
        assert_eq!(
            set.explain(AccessAction::InspectDenied),
            PermissionReason::ExplicitlyDenied
        );
    }

    #[test]
    fn effective_list_is_stable_and_complete() {
        let set = PermissionSet::from_role(AuditorRole::ReadOnlyReviewer)
            .allow(AccessAction::GenerateReport);
        let effective = set.effective();
        assert!(effective.contains(&AccessAction::ReadRecord));
        assert!(effective.contains(&AccessAction::GenerateReport));
        assert!(!effective.contains(&AccessAction::ExportRecords));
        // Stable order regardless of insertion order.
        let again = set.effective();
        assert_eq!(effective, again);
    }

    #[test]
    fn contradictory_overrides_are_rejected() {
        // Add then deny the same action cancels out; the validator accepts.
        let set = PermissionSet::from_role(AuditorRole::Auditor)
            .allow(AccessAction::GenerateReport)
            .deny(AccessAction::GenerateReport);
        set.validate().unwrap();
        assert!(!set.allows(AccessAction::GenerateReport));
        // But a redundant addition (already in the role baseline) is noise.
        let redundant =
            PermissionSet::from_role(AuditorRole::Auditor).allow(AccessAction::ReadRecord);
        assert!(redundant.validate().is_err());
    }
}
