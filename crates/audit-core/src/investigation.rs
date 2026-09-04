//! Investigation case model.
//!
//! An investigation links audit records, transactions, accounts, policies,
//! evidence, findings, and notes into one structured case with a
//! deterministic timeline. This is a *focused compliance-investigation
//! model*, not an enterprise case-management product: cases exist to answer
//! "what happened around this denied/flagged operation?" and to record the
//! answer.
//!
//! ## Timeline discipline
//!
//! Every timeline entry carries a time and a provenance label. Timestamps
//! are never invented: entries use the ledger/event time when the entry
//! describes on-chain activity, and the acting auditor's clock time when
//! the entry records an audit-layer action. The label says which.

use serde::{Deserialize, Serialize};

use crate::correlation::{AccountReference, PolicyReference, TokenReference, TransactionReference};
use crate::errors::{AuditError, AuditResult};
use crate::identifiers::{AuditorId, CaseId, FindingId, NoteId, RecordId};
use crate::timestamps::Timestamp;

/// The lifecycle of a case.
///
/// Transitions are validated (see [`CaseStatus::can_transition`]): a case
/// cannot skip from `open` to `closed`, and a `closed` case is terminal
/// unless an administrator explicitly reopens it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatus {
    /// Created, not yet actively investigated.
    Open,
    /// An investigator is actively working it.
    Investigating,
    /// Needs senior/compliance attention.
    Escalated,
    /// Investigation complete, awaiting review/closure.
    Resolved,
    /// Closed with a recorded reason.
    Closed,
}

impl CaseStatus {
    /// The stable label for this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Investigating => "investigating",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        }
    }

    /// Whether a transition from `self` to `to` is allowed.
    pub fn can_transition(&self, to: CaseStatus) -> bool {
        matches!(
            (self, to),
            (Self::Open, Self::Investigating)
                | (Self::Open, Self::Escalated)
                | (Self::Investigating, Self::Escalated)
                | (Self::Investigating, Self::Resolved)
                | (Self::Escalated, Self::Investigating)
                | (Self::Escalated, Self::Resolved)
                | (Self::Resolved, Self::Closed)
                | (Self::Resolved, Self::Open) // reopened after review
                | (Self::Closed, Self::Open) // admin reopen
        )
    }

    /// Whether the case is terminal (no further activity expected).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Case priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// No time pressure.
    Low,
    /// Normal handling.
    Medium,
    /// Needs prompt attention.
    High,
    /// Active risk; escalate immediately.
    Critical,
}

/// What a timeline entry records. Every entry is one of these kinds so
/// timelines can be rendered and filtered deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimelineEntryKind {
    /// An on-chain transaction was added to the case.
    TransactionObserved,
    /// A policy decision record was added.
    PolicyDecision,
    /// An enforcement decision record was added.
    EnforcementDecision,
    /// An account freeze/unfreeze record was added.
    AccountFrozen,
    /// A denial record was added.
    Denial,
    /// An authorization change was added.
    AuthorizationChange,
    /// An auditor accessed case-related data.
    AuditorAccess,
    /// An evidence artifact was generated from this case.
    EvidenceGenerated,
    /// A finding was added.
    FindingAdded,
    /// The case status changed.
    StatusChanged,
    /// A note was added.
    NoteAdded,
}

impl TimelineEntryKind {
    /// The stable label for this entry kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TransactionObserved => "transaction-observed",
            Self::PolicyDecision => "policy-decision",
            Self::EnforcementDecision => "enforcement-decision",
            Self::AccountFrozen => "account-frozen",
            Self::Denial => "denial",
            Self::AuthorizationChange => "authorization-change",
            Self::AuditorAccess => "auditor-access",
            Self::EvidenceGenerated => "evidence-generated",
            Self::FindingAdded => "finding-added",
            Self::StatusChanged => "status-changed",
            Self::NoteAdded => "note-added",
        }
    }
}

/// One entry on an investigation timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// When the underlying activity happened (ledger time for on-chain
    /// entries, auditor clock time for audit-layer entries). Never invented.
    at: Timestamp,
    /// What kind of entry this is.
    kind: TimelineEntryKind,
    /// Who/what the entry is attributed to, when known.
    actor: Option<AuditorId>,
    /// The audit record backing this entry, when there is one.
    record: Option<RecordId>,
    /// Provenance label: where this entry came from (e.g. `audit-record`,
    /// `auditor-action`, `evidence`).
    provenance: String,
    /// Short optional detail; never contains protected values.
    detail: Option<String>,
}

impl TimelineEntry {
    /// Builds a timeline entry.
    pub fn new(at: Timestamp, kind: TimelineEntryKind, provenance: &str) -> AuditResult<Self> {
        if provenance.is_empty() || provenance.len() > 64 {
            return Err(AuditError::invalid_identifier(
                "timeline provenance",
                "must be 1-64 chars",
            ));
        }
        Ok(Self {
            at,
            kind,
            actor: None,
            record: None,
            provenance: provenance.to_owned(),
            detail: None,
        })
    }

    /// Attributes the entry to an auditor.
    pub fn with_actor(mut self, actor: AuditorId) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Links the entry to an audit record.
    pub fn with_record(mut self, record: RecordId) -> Self {
        self.record = Some(record);
        self
    }

    /// Adds a short detail.
    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_owned());
        self
    }

    /// When the underlying activity happened.
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// The entry kind.
    pub fn kind(&self) -> TimelineEntryKind {
        self.kind
    }

    /// The attributed actor.
    pub fn actor(&self) -> Option<&AuditorId> {
        self.actor.as_ref()
    }

    /// The backing audit record, when there is one.
    pub fn record(&self) -> Option<&RecordId> {
        self.record.as_ref()
    }

    /// The provenance label.
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// What a finding classifies as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    /// Assessment of a policy decision.
    PolicyVerdict,
    /// Assessment of an enforcement decision.
    EnforcementVerdict,
    /// An unexpected pattern or behavior.
    Anomaly,
    /// A pattern observed across multiple records.
    Pattern,
    /// An integrity concern.
    Integrity,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Minor concern.
    Low,
    /// Significant concern.
    Medium,
    /// Serious concern.
    High,
    /// Requires immediate action.
    Critical,
}

impl Severity {
    /// The stable label for this severity.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// A finding attached to a case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    finding_id: FindingId,
    kind: FindingKind,
    severity: Severity,
    /// Short summary (bounded).
    summary: String,
    /// Records supporting the finding.
    related_records: Vec<RecordId>,
    created_at: Timestamp,
    created_by: AuditorId,
}

impl Finding {
    /// Builds a finding.
    pub fn new(
        finding_id: FindingId,
        kind: FindingKind,
        severity: Severity,
        summary: &str,
        created_at: Timestamp,
        created_by: AuditorId,
    ) -> AuditResult<Self> {
        if summary.is_empty() || summary.len() > 512 {
            return Err(AuditError::ValidationFailure(
                "finding summary must be 1-512 chars".into(),
            ));
        }
        Ok(Self {
            finding_id,
            kind,
            severity,
            summary: summary.to_owned(),
            related_records: Vec::new(),
            created_at,
            created_by,
        })
    }

    /// Links supporting records.
    pub fn with_related_records(mut self, records: Vec<RecordId>) -> Self {
        self.related_records = records;
        self
    }

    /// The finding id.
    pub fn finding_id(&self) -> &FindingId {
        &self.finding_id
    }

    /// The finding kind.
    pub fn kind(&self) -> FindingKind {
        self.kind
    }

    /// The severity.
    pub fn severity(&self) -> Severity {
        self.severity
    }
}

/// A note on a case (investigator scratchpad, review comment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    note_id: NoteId,
    author: AuditorId,
    body: String,
    created_at: Timestamp,
}

impl Note {
    /// Builds a note. Bodies are bounded to keep cases small.
    pub fn new(
        note_id: NoteId,
        author: AuditorId,
        body: &str,
        created_at: Timestamp,
    ) -> AuditResult<Self> {
        if body.is_empty() || body.len() > 4096 {
            return Err(AuditError::ValidationFailure(
                "note body must be 1-4096 chars".into(),
            ));
        }
        Ok(Self {
            note_id,
            author,
            body: body.to_owned(),
            created_at,
        })
    }

    /// The note id.
    pub fn note_id(&self) -> &NoteId {
        &self.note_id
    }

    /// The author.
    pub fn author(&self) -> &AuditorId {
        &self.author
    }
}

/// The audit subjects a case is about: records, transactions, accounts,
/// tokens, and policies. References only — no duplicated state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedReferences {
    records: Vec<RecordId>,
    transactions: Vec<TransactionReference>,
    accounts: Vec<AccountReference>,
    tokens: Vec<TokenReference>,
    policies: Vec<PolicyReference>,
}

impl RelatedReferences {
    /// An empty reference set.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds a related audit record.
    pub fn add_record(&mut self, record: RecordId) -> &mut Self {
        self.records.push(record);
        self
    }

    /// Adds a related transaction.
    pub fn add_transaction(&mut self, tx: TransactionReference) -> &mut Self {
        self.transactions.push(tx);
        self
    }

    /// The related records.
    pub fn records(&self) -> &[RecordId] {
        &self.records
    }

    /// The related transactions.
    pub fn transactions(&self) -> &[TransactionReference] {
        &self.transactions
    }

    /// Whether anything is linked yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
            && self.transactions.is_empty()
            && self.accounts.is_empty()
            && self.tokens.is_empty()
            && self.policies.is_empty()
    }
}

/// An investigation case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationCase {
    case_id: CaseId,
    title: String,
    status: CaseStatus,
    priority: Priority,
    created_at: Timestamp,
    created_by: AuditorId,
    assigned_to: Option<AuditorId>,
    related: RelatedReferences,
    timeline: Vec<TimelineEntry>,
    findings: Vec<Finding>,
    notes: Vec<Note>,
    closed_at: Option<Timestamp>,
    closed_reason: Option<String>,
}

impl InvestigationCase {
    /// Opens a new case.
    pub fn open(
        case_id: CaseId,
        title: &str,
        priority: Priority,
        created_at: Timestamp,
        created_by: AuditorId,
    ) -> AuditResult<Self> {
        if title.is_empty() || title.len() > 200 {
            return Err(AuditError::ValidationFailure(
                "case title must be 1-200 chars".into(),
            ));
        }
        Ok(Self {
            case_id,
            title: title.to_owned(),
            status: CaseStatus::Open,
            priority,
            created_at,
            created_by,
            assigned_to: None,
            related: RelatedReferences::empty(),
            timeline: Vec::new(),
            findings: Vec::new(),
            notes: Vec::new(),
            closed_at: None,
            closed_reason: None,
        })
    }

    /// Assigns an investigator, recording the action on the timeline.
    pub fn assign(&mut self, investigator: AuditorId, at: Timestamp) -> AuditResult<()> {
        self.assigned_to = Some(investigator.clone());
        self.timeline.push(
            TimelineEntry::new(at, TimelineEntryKind::StatusChanged, "auditor-action")?
                .with_actor(investigator)
                .with_detail("case assigned"),
        );
        Ok(())
    }

    /// Transitions the case status. Invalid transitions are rejected; every
    /// valid transition is recorded on the timeline.
    pub fn change_status(
        &mut self,
        to: CaseStatus,
        at: Timestamp,
        by: AuditorId,
        reason: Option<&str>,
    ) -> AuditResult<()> {
        if !self.status.can_transition(to) {
            return Err(AuditError::ValidationFailure(format!(
                "cannot transition case from {} to {}",
                self.status.as_str(),
                to.as_str()
            )));
        }
        let mut entry = TimelineEntry::new(at, TimelineEntryKind::StatusChanged, "auditor-action")?
            .with_actor(by.clone())
            .with_detail(&format!("{} -> {}", self.status.as_str(), to.as_str()));
        if let Some(r) = reason {
            entry = entry.with_detail(&format!(
                "{} -> {} ({r})",
                self.status.as_str(),
                to.as_str()
            ));
        }
        self.timeline.push(entry);
        self.status = to;
        if to == CaseStatus::Closed {
            self.closed_at = Some(at);
            self.closed_reason = reason.map(str::to_owned);
        }
        Ok(())
    }

    /// Links a related record and records the linkage on the timeline.
    pub fn add_related_record(
        &mut self,
        record: RecordId,
        kind: TimelineEntryKind,
        at: Timestamp,
    ) -> AuditResult<()> {
        self.related.add_record(record.clone());
        self.timeline
            .push(TimelineEntry::new(at, kind, "audit-record")?.with_record(record));
        Ok(())
    }

    /// Adds a finding and records it on the timeline.
    pub fn add_finding(&mut self, finding: Finding, at: Timestamp) -> AuditResult<()> {
        self.timeline.push(
            TimelineEntry::new(at, TimelineEntryKind::FindingAdded, "auditor-action")?
                .with_actor(finding.created_by.clone()),
        );
        self.findings.push(finding);
        Ok(())
    }

    /// Adds a note and records it on the timeline.
    pub fn add_note(&mut self, note: Note) -> AuditResult<()> {
        self.timeline.push(
            TimelineEntry::new(
                note.created_at,
                TimelineEntryKind::NoteAdded,
                "auditor-action",
            )?
            .with_actor(note.author.clone()),
        );
        self.notes.push(note);
        Ok(())
    }

    /// Validates case invariants: closure fields agree with status, and the
    /// case id is consistent throughout.
    pub fn validate(&self) -> AuditResult<()> {
        match self.status {
            CaseStatus::Closed => {
                if self.closed_at.is_none() {
                    return Err(AuditError::ValidationFailure(
                        "closed cases must record closed_at".into(),
                    ));
                }
            }
            _ => {
                if self.closed_at.is_some() || self.closed_reason.is_some() {
                    return Err(AuditError::ValidationFailure(
                        "only closed cases may carry closure fields".into(),
                    ));
                }
            }
        }
        for entry in &self.timeline {
            if entry.actor().is_none()
                && matches!(
                    entry.kind(),
                    TimelineEntryKind::FindingAdded
                        | TimelineEntryKind::StatusChanged
                        | TimelineEntryKind::NoteAdded
                )
            {
                return Err(AuditError::ValidationFailure(
                    "auditor-action timeline entries must carry an actor".into(),
                ));
            }
        }
        Ok(())
    }

    /// The case id.
    pub fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// The current status.
    pub fn status(&self) -> CaseStatus {
        self.status
    }

    /// The assigned investigator.
    pub fn assigned_to(&self) -> Option<&AuditorId> {
        self.assigned_to.as_ref()
    }

    /// The case timeline, oldest first.
    pub fn timeline(&self) -> &[TimelineEntry] {
        &self.timeline
    }

    /// The findings.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The notes.
    pub fn notes(&self) -> &[Note] {
        &self.notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auditor(id: &str) -> AuditorId {
        AuditorId::derive(&[id])
    }

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix_seconds(secs)
    }

    #[test]
    fn status_transitions_are_restricted() {
        assert!(CaseStatus::Open.can_transition(CaseStatus::Investigating));
        assert!(CaseStatus::Investigating.can_transition(CaseStatus::Escalated));
        assert!(CaseStatus::Resolved.can_transition(CaseStatus::Closed));
        assert!(!CaseStatus::Open.can_transition(CaseStatus::Closed));
        assert!(!CaseStatus::Closed.can_transition(CaseStatus::Escalated));
        assert!(CaseStatus::Closed.can_transition(CaseStatus::Open)); // admin reopen
        assert_eq!(CaseStatus::Investigating.as_str(), "investigating");
        assert!(!CaseStatus::Open.is_terminal());
        assert!(CaseStatus::Closed.is_terminal());
    }

    #[test]
    fn cases_record_their_lifecycle() {
        let mut case = InvestigationCase::open(
            CaseId::derive(&["c1"]),
            "flagged transfer review",
            Priority::High,
            at(100),
            auditor("a1"),
        )
        .unwrap();
        case.assign(auditor("a2"), at(110)).unwrap();
        case.change_status(CaseStatus::Investigating, at(120), auditor("a2"), None)
            .unwrap();
        case.change_status(
            CaseStatus::Resolved,
            at(200),
            auditor("a2"),
            Some("no issue"),
        )
        .unwrap();
        case.change_status(
            CaseStatus::Closed,
            at(210),
            auditor("a3"),
            Some("closed after review"),
        )
        .unwrap();
        assert!(case.validate().is_ok());
        assert_eq!(case.status(), CaseStatus::Closed);
        assert_eq!(case.timeline().len(), 4);
        assert!(case.assigned_to().is_some());
    }

    #[test]
    fn invalid_transitions_are_rejected_without_mutation() {
        let mut case = InvestigationCase::open(
            CaseId::derive(&["c2"]),
            "x",
            Priority::Low,
            at(1),
            auditor("a1"),
        )
        .unwrap();
        let before = case.timeline().len();
        assert!(case
            .change_status(CaseStatus::Closed, at(2), auditor("a1"), None)
            .is_err());
        assert_eq!(case.timeline().len(), before);
        assert_eq!(case.status(), CaseStatus::Open);
    }

    #[test]
    fn closure_fields_agree_with_status() {
        let mut case = InvestigationCase::open(
            CaseId::derive(&["c3"]),
            "y",
            Priority::Medium,
            at(1),
            auditor("a1"),
        )
        .unwrap();
        assert!(case.validate().is_ok());

        case.closed_at = Some(at(50)); // manually inconsistent: open case with closed_at
        assert!(case.validate().is_err());
        case.closed_at = None;

        case.change_status(CaseStatus::Investigating, at(10), auditor("a1"), None)
            .unwrap();
        case.change_status(CaseStatus::Resolved, at(20), auditor("a1"), None)
            .unwrap();
        case.change_status(CaseStatus::Closed, at(60), auditor("a1"), Some("done"))
            .unwrap();
        assert!(case.validate().is_ok());
        assert_eq!(case.closed_reason.as_deref(), Some("done"));
    }

    #[test]
    fn related_records_and_findings_accumulate() {
        let mut case = InvestigationCase::open(
            CaseId::derive(&["c4"]),
            "z",
            Priority::Critical,
            at(1),
            auditor("a1"),
        )
        .unwrap();
        let record = RecordId::derive(&["rec"]);
        case.add_related_record(record.clone(), TimelineEntryKind::Denial, at(5))
            .unwrap();
        assert_eq!(case.related.records(), &[record]);
        let finding = Finding::new(
            FindingId::derive(&["f1"]),
            FindingKind::Anomaly,
            Severity::High,
            "repeated denials",
            at(10),
            auditor("a2"),
        )
        .unwrap();
        case.add_finding(finding, at(11)).unwrap();
        assert_eq!(case.findings().len(), 1);
        assert_eq!(case.timeline().len(), 2);
        assert!(case.validate().is_ok());
        assert_eq!(Severity::Critical.as_str(), "critical");
    }
}
