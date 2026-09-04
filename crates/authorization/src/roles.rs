//! The role-to-permission matrix.
//!
//! Roles are coarse (the identity a human or service holds); permissions
//! are the fine-grained operations. The default matrix below is the
//! **least-privilege baseline** the registry seeds from: an identity gains
//! the actions its role grants, nothing more, and anything finer must be an
//! explicit per-identity override, never a silent default.
//!
//! The matrix is intentionally small and auditable — a single table, not
//! scattered checks. Changing a role's permissions here changes the
//! baseline for every identity holding that role.

use safeguard_audit_core::{AccessAction, AuditorRole};

/// Returns the actions `role` may perform under the default matrix.
///
/// The sets are ordered from most restricted to most powerful and are
/// cumulative: `senior-auditor` may do everything `auditor` may, plus the
/// evidence/report generation and export powers that distinguish senior
/// review from routine reading. `administrator` is the only role with the
/// full action set, matching its exclusive authority over identities and
/// scopes.
pub fn actions_for_role(role: AuditorRole) -> &'static [AccessAction] {
    use AccessAction::*;
    match role {
        // Read-only review: observe, query, and verify. Deliberately no
        // denied-operation inspection (that surfaces enforcement details)
        // and no generation or export.
        AuditorRole::ReadOnlyReviewer => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            VerifyIntegrity,
        ],
        // A working auditor: adds inspection of denied operations and
        // investigation viewing — read powers over enforcement outcomes.
        AuditorRole::Auditor => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            InspectDenied,
            ViewInvestigation,
            VerifyIntegrity,
        ],
        // A senior auditor: the auditor set plus evidence and report
        // generation and export, still within granted scopes.
        AuditorRole::SeniorAuditor => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            InspectDenied,
            ViewInvestigation,
            GenerateEvidence,
            GenerateReport,
            ExportRecords,
            VerifyIntegrity,
        ],
        // An investigator: read powers plus case creation. Evidence can be
        // generated to support an investigation; reports are a senior/
        // officer function.
        AuditorRole::Investigator => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            InspectDenied,
            CreateInvestigation,
            ViewInvestigation,
            GenerateEvidence,
            VerifyIntegrity,
        ],
        // A compliance officer: senior powers plus protected-data requests —
        // the oversight role may ask for decrypted material under a
        // dedicated authorization.
        AuditorRole::ComplianceOfficer => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            InspectDenied,
            ViewInvestigation,
            GenerateEvidence,
            GenerateReport,
            ExportRecords,
            RequestProtectedData,
            VerifyIntegrity,
        ],
        // The only full set. Administration is a distinct privilege, and
        // the authorizer additionally requires an `all` scope for it.
        AuditorRole::Administrator => &[
            ReadRecord,
            Query,
            InspectTransaction,
            InspectPolicy,
            InspectDenied,
            CreateInvestigation,
            ViewInvestigation,
            GenerateEvidence,
            GenerateReport,
            ExportRecords,
            RequestProtectedData,
            VerifyIntegrity,
        ],
    }
}

/// Whether `role` may perform `action` under the default matrix.
pub fn role_allows(role: AuditorRole, action: AccessAction) -> bool {
    actions_for_role(role).contains(&action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::AccessAction;

    #[test]
    fn matrix_is_cumulative() {
        for action in actions_for_role(AuditorRole::Auditor) {
            assert!(
                role_allows(AuditorRole::SeniorAuditor, *action),
                "senior-auditor must inherit {action:?}"
            );
        }
        for action in actions_for_role(AuditorRole::SeniorAuditor) {
            assert!(
                role_allows(AuditorRole::ComplianceOfficer, *action),
                "compliance-officer must inherit {action:?}"
            );
        }
        for action in actions_for_role(AuditorRole::Investigator) {
            assert!(
                role_allows(AuditorRole::Administrator, *action),
                "administrator must inherit {action:?}"
            );
        }
    }

    #[test]
    fn least_privilege_boundaries() {
        // Read-only reviewers cannot inspect denied operations or generate.
        assert!(role_allows(
            AuditorRole::ReadOnlyReviewer,
            AccessAction::ReadRecord
        ));
        assert!(!role_allows(
            AuditorRole::ReadOnlyReviewer,
            AccessAction::InspectDenied
        ));
        assert!(!role_allows(
            AuditorRole::ReadOnlyReviewer,
            AccessAction::GenerateReport
        ));
        // Only investigators and administrators create cases by default.
        assert!(role_allows(
            AuditorRole::Investigator,
            AccessAction::CreateInvestigation
        ));
        assert!(role_allows(
            AuditorRole::Administrator,
            AccessAction::CreateInvestigation
        ));
        assert!(!role_allows(
            AuditorRole::Auditor,
            AccessAction::CreateInvestigation
        ));
        // Protected-data requests are officer+ by default.
        assert!(role_allows(
            AuditorRole::ComplianceOfficer,
            AccessAction::RequestProtectedData
        ));
        assert!(role_allows(
            AuditorRole::Administrator,
            AccessAction::RequestProtectedData
        ));
        assert!(!role_allows(
            AuditorRole::SeniorAuditor,
            AccessAction::RequestProtectedData
        ));
    }

    #[test]
    fn every_role_has_a_nonempty_defined_set() {
        for role in [
            AuditorRole::ReadOnlyReviewer,
            AuditorRole::Auditor,
            AuditorRole::SeniorAuditor,
            AuditorRole::Investigator,
            AuditorRole::ComplianceOfficer,
            AuditorRole::Administrator,
        ] {
            assert!(
                !actions_for_role(role).is_empty(),
                "role {role:?} must define actions"
            );
        }
    }
}
