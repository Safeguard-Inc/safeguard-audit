//! Authorization and auditor-identity domain models.
//!
//! Access to audit data must be explicit, scoped, attributable, and itself
//! auditable. This module defines the models; the authorization crate
//! implements the *decisions* (role → permission → scope evaluation).
//!
//! ## Least privilege
//!
//! Roles are intentionally coarse (the identity a human or service holds);
//! *permissions* are the fine-grained operations a role may perform; and
//! *scopes* bound a permission to a token, contract, network, case, time
//! range, event kind, or classification. An auditor authorized for one
//! scope must never automatically receive another.
//!
//! ## Auditability
//!
//! Every protected-data access is represented as an [`AuditAccessEntry`]
//! and becomes an `audit-access` derived event. The audit trail auditing
//! itself stops there — access events are recorded once, and the entry
//! model deliberately holds no pointer back to a meta-audit of the audit.

use serde::{Deserialize, Serialize};

use crate::errors::AuditResult;
use crate::identifiers::{AccessEntryId, AuditorId};
use crate::privacy::DataClassification;
use crate::timestamps::Timestamp;

/// The roles an auditor identity can hold.
///
/// Roles are ordered by increasing authority so `>=` comparisons answer
/// "does this role outrank that one?". Permission *evaluation* (which
/// actions each role may take) lives in the authorization crate, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditorRole {
    /// May read audit records within granted scopes.
    ReadOnlyReviewer,
    /// A working auditor with scoped read and investigation powers.
    Auditor,
    /// A senior auditor who can also generate evidence and reports.
    SeniorAuditor,
    /// An investigator focused on cases and timelines.
    Investigator,
    /// A compliance officer overseeing the program.
    ComplianceOfficer,
    /// System administration of auditor identities and scopes.
    Administrator,
}

impl AuditorRole {
    /// The stable label for this role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnlyReviewer => "read-only-reviewer",
            Self::Auditor => "auditor",
            Self::SeniorAuditor => "senior-auditor",
            Self::Investigator => "investigator",
            Self::ComplianceOfficer => "compliance-officer",
            Self::Administrator => "administrator",
        }
    }
}

/// The identity of an authorized auditor or compliance operator.
///
/// Identities are references, not credentials: the identity names who is
/// acting; the *credential* proving they are who they claim is handled by
/// the authorization crate's credentials module and is never stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditorIdentity {
    auditor_id: AuditorId,
    role: AuditorRole,
}

impl AuditorIdentity {
    /// Builds an identity.
    pub fn new(auditor_id: AuditorId, role: AuditorRole) -> Self {
        Self { auditor_id, role }
    }

    /// The auditor id.
    pub fn auditor_id(&self) -> &AuditorId {
        &self.auditor_id
    }

    /// The role this identity holds.
    pub fn role(&self) -> AuditorRole {
        self.role
    }
}

/// A fine-grained operation an auditor may (or may not) perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessAction {
    /// Read a specific audit record.
    ReadRecord,
    /// Run a query over audit records.
    Query,
    /// Inspect transaction metadata.
    InspectTransaction,
    /// Inspect a policy reference (historical, never re-evaluation).
    InspectPolicy,
    /// Inspect denied operations.
    InspectDenied,
    /// Create an investigation case.
    CreateInvestigation,
    /// View an investigation case.
    ViewInvestigation,
    /// Generate an evidence artifact.
    GenerateEvidence,
    /// Generate a report.
    GenerateReport,
    /// Export records or evidence.
    ExportRecords,
    /// Request protected (decrypted) data.
    RequestProtectedData,
    /// Verify record or evidence integrity.
    VerifyIntegrity,
}

impl AccessAction {
    /// The stable label for this action.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadRecord => "read-record",
            Self::Query => "query",
            Self::InspectTransaction => "inspect-transaction",
            Self::InspectPolicy => "inspect-policy",
            Self::InspectDenied => "inspect-denied",
            Self::CreateInvestigation => "create-investigation",
            Self::ViewInvestigation => "view-investigation",
            Self::GenerateEvidence => "generate-evidence",
            Self::GenerateReport => "generate-report",
            Self::ExportRecords => "export-records",
            Self::RequestProtectedData => "request-protected-data",
            Self::VerifyIntegrity => "verify-integrity",
        }
    }
}

/// The outcome of an authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessResult {
    /// The request was authorized within scope.
    Granted,
    /// The requester is not authorized for the action.
    Denied,
    /// The requester is authorized for the action but not this scope.
    OutOfScope,
}

impl AccessResult {
    /// The stable label for this result.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::OutOfScope => "out-of-scope",
        }
    }
}

/// A bound on where an action may apply: a token, contract, network,
/// account class, investigation, time range, event kind, or data
/// classification.
///
/// This is the *logic* type used by the authorization crate's evaluator;
/// records and access logs carry a stable [`AccessScope::describe`] label
/// instead of the full structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessScope {
    /// Everything (granted only to administrators by explicit policy).
    All,
    /// One network.
    Network(crate::identifiers::NetworkId),
    /// One token (contract or classic asset).
    Token(crate::correlation::TokenReference),
    /// One contract.
    Contract(crate::correlation::ContractReference),
    /// One account class (an adapter-defined label).
    AccountClass(String),
    /// One investigation case.
    Investigation(crate::identifiers::CaseId),
    /// A time range.
    TimeRange(crate::timestamps::TimeRange),
    /// One event kind.
    EventKind(crate::event::EventKind),
    /// Data up to a classification.
    Classification(DataClassification),
}

impl AccessScope {
    /// A stable, URL-safe description used in access logs and audit-access
    /// events.
    pub fn describe(&self) -> String {
        match self {
            Self::All => "all".to_owned(),
            Self::Network(n) => format!("network:{n}"),
            Self::Token(t) => format!("token:{}", t.display()),
            Self::Contract(c) => format!("contract:{c}"),
            Self::AccountClass(c) => format!("account-class:{c}"),
            Self::Investigation(c) => format!("case:{c}"),
            Self::TimeRange(r) => match (r.start(), r.end()) {
                (Some(a), Some(b)) => {
                    format!("time:{}..{}", a.as_unix_seconds(), b.as_unix_seconds())
                }
                (Some(a), None) => format!("time:{}..", a.as_unix_seconds()),
                (None, Some(b)) => format!("time:..{}", b.as_unix_seconds()),
                (None, None) => "time:all".to_owned(),
            },
            Self::EventKind(k) => format!("kind:{k}"),
            Self::Classification(c) => format!("classification:{}", c.as_str()),
        }
    }
}

/// The decision an authorizer reached for one request.
///
/// `allowed` is the single question callers need answered; the rest exists
/// so the decision can be recorded as an audit-access event without
/// re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Whether the request may proceed.
    allowed: bool,
    /// The action that was requested.
    action: AccessAction,
    /// Stable description of the scope the decision applies to.
    scope: String,
    /// Optional machine-readable reason code.
    reason: Option<String>,
    /// Who/what the decision is attributed to.
    decided_by: Option<AuditorId>,
    /// When the decision was made.
    decided_at: Timestamp,
}

impl AuthorizationDecision {
    /// Builds a decision.
    pub fn new(
        allowed: bool,
        action: AccessAction,
        scope: String,
        decided_by: Option<AuditorId>,
        decided_at: Timestamp,
    ) -> Self {
        Self {
            allowed,
            action,
            scope,
            reason: None,
            decided_by,
            decided_at,
        }
    }

    /// Attaches a machine-readable reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Whether the request may proceed.
    pub fn allowed(&self) -> bool {
        self.allowed
    }

    /// The requested action.
    pub fn action(&self) -> AccessAction {
        self.action
    }

    /// The scope label the decision applies to.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The reason code, when set.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The attributed actor.
    pub fn decided_by(&self) -> Option<&AuditorId> {
        self.decided_by.as_ref()
    }

    /// When the decision was made.
    pub fn decided_at(&self) -> Timestamp {
        self.decided_at
    }
}

/// One recorded access to audit data.
///
/// Access entries feed `audit-access` derived events. The scope is stored
/// as the stable label produced by [`AccessScope::describe`] so the log
/// stays small and serializable; full scope structures live only in the
/// authorizer's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAccessEntry {
    entry_id: AccessEntryId,
    auditor: AuditorId,
    action: AccessAction,
    scope: String,
    /// Target reference (record id, case id, transaction...) as a label.
    target: Option<String>,
    result: AccessResult,
    accessed_at: Timestamp,
    /// Highest classification touched, when the access involved protected
    /// data.
    classification: Option<DataClassification>,
}

impl AuditAccessEntry {
    /// Builds an access entry.
    pub fn new(
        entry_id: AccessEntryId,
        auditor: AuditorId,
        action: AccessAction,
        scope: String,
        target: Option<String>,
        result: AccessResult,
        accessed_at: Timestamp,
    ) -> Self {
        Self {
            entry_id,
            auditor,
            action,
            scope,
            target,
            result,
            accessed_at,
            classification: None,
        }
    }

    /// Records the highest data classification the access touched.
    pub fn with_classification(mut self, classification: DataClassification) -> Self {
        self.classification = Some(classification);
        self
    }

    /// The entry id.
    pub fn entry_id(&self) -> &AccessEntryId {
        &self.entry_id
    }

    /// Who accessed.
    pub fn auditor(&self) -> &AuditorId {
        &self.auditor
    }

    /// What they did.
    pub fn action(&self) -> AccessAction {
        self.action
    }

    /// The scope label.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The target reference label, when present.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// The access result.
    pub fn result(&self) -> AccessResult {
        self.result
    }

    /// When the access happened.
    pub fn accessed_at(&self) -> Timestamp {
        self.accessed_at
    }
}

/// Validates that a scope description is safe to log (bounded, printable).
pub fn validate_scope_label(label: &str) -> AuditResult<()> {
    let valid =
        (1..=256).contains(&label.len()) && label.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if valid {
        Ok(())
    } else {
        Err(crate::errors::AuditError::invalid_identifier(
            "scope label",
            "must be 1-256 printable ASCII chars",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{CaseId, NetworkId};

    #[test]
    fn roles_are_ordered_and_labeled() {
        assert!(AuditorRole::ReadOnlyReviewer < AuditorRole::Administrator);
        assert_eq!(
            AuditorRole::ComplianceOfficer.as_str(),
            "compliance-officer"
        );
        assert_eq!(AuditorRole::SeniorAuditor.as_str(), "senior-auditor");
        assert_eq!(AuditorRole::Investigator.as_str(), "investigator");
        assert_eq!(AuditorRole::Auditor.as_str(), "auditor");
        assert_eq!(AuditorRole::Administrator.as_str(), "administrator");
        assert_eq!(AuditorRole::ReadOnlyReviewer.as_str(), "read-only-reviewer");
    }

    #[test]
    fn scopes_describe_stably() {
        let net = NetworkId::new(NetworkId::TESTNET).unwrap();
        assert_eq!(AccessScope::All.describe(), "all");
        assert_eq!(AccessScope::Network(net).describe(), "network:testnet");
        assert_eq!(
            AccessScope::EventKind(crate::event::EventKind::AuditAccess).describe(),
            "kind:audit-access"
        );
        assert!(AccessScope::Investigation(CaseId::derive(&["c1"]))
            .describe()
            .starts_with("case:case_"));
        assert_eq!(
            AccessScope::Classification(DataClassification::Restricted).describe(),
            "classification:restricted"
        );
    }

    #[test]
    fn decisions_carry_their_attribution() {
        let auditor = AuditorIdentity::new(AuditorId::derive(&["aud-1"]), AuditorRole::Auditor);
        let decision = AuthorizationDecision::new(
            false,
            AccessAction::ExportRecords,
            AccessScope::All.describe(),
            Some(auditor.auditor_id().clone()),
            Timestamp::from_unix_seconds(100),
        )
        .with_reason("denied-by-policy");
        assert!(!decision.allowed());
        assert_eq!(decision.action(), AccessAction::ExportRecords);
        assert_eq!(decision.reason(), Some("denied-by-policy"));
        assert_eq!(decision.decided_by(), Some(auditor.auditor_id()));
    }

    #[test]
    fn access_entries_record_the_whole_story() {
        let auditor = AuditorId::derive(&["aud-2"]);
        let entry = AuditAccessEntry::new(
            AccessEntryId::derive(&["e1"]),
            auditor.clone(),
            AccessAction::RequestProtectedData,
            AccessScope::Classification(DataClassification::HighlyRestricted).describe(),
            Some("rec_abcd".into()),
            AccessResult::OutOfScope,
            Timestamp::from_unix_seconds(200),
        )
        .with_classification(DataClassification::HighlyRestricted);
        assert_eq!(entry.auditor(), &auditor);
        assert_eq!(entry.result(), AccessResult::OutOfScope);
        assert_eq!(entry.action().as_str(), "request-protected-data");
        assert_eq!(AccessResult::Denied.as_str(), "denied");
    }

    #[test]
    fn scope_labels_validate() {
        assert!(validate_scope_label("network:testnet").is_ok());
        assert!(validate_scope_label(&"x".repeat(300)).is_err());
    }
}
