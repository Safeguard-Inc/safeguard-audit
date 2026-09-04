//! Report models.
//!
//! A report is a *reproducible, bounded summary* of audit history: it names
//! its kind, its query configuration, the generator version that produced
//! it, and summary counts — never an unbounded dump of private data. Two
//! runs with the same records and the same request must produce the same
//! report, which is why the request is captured *inside* the report as the
//! reproducibility record.
//!
//! The reporting crate assembles concrete report bodies (rows of public
//! references, count tables) from these shapes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::correlation::{DecisionResult, TokenReference, TransactionReference, VersionLabel};
use crate::errors::{AuditError, AuditResult};
use crate::event::EventKind;
use crate::identifiers::{AccountId, AuditorId, ReportId};
use crate::integrity::IntegrityDigest;
use crate::privacy::DataClassification;
use crate::timestamps::{TimeRange, Timestamp};

/// The current schema version of the report format.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// What kind of report was requested/generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportKind {
    /// Compliance activity over a range.
    ComplianceActivity,
    /// Approved transactions.
    ApprovedTransactions,
    /// Denied transactions.
    DeniedTransactions,
    /// Flagged transactions.
    FlaggedTransactions,
    /// Enforcement activity (hook results).
    EnforcementActivity,
    /// One account's activity.
    AccountActivity,
    /// One token's activity.
    TokenActivity,
    /// Investigation status and summaries.
    Investigations,
    /// Incident (denied/flagged/escalated) summaries.
    Incidents,
    /// Evidence summaries.
    EvidenceSummary,
    /// Integrity verification results.
    IntegrityVerification,
}

impl std::fmt::Display for ReportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ReportKind {
    /// The stable label for this report kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ComplianceActivity => "compliance-activity",
            Self::ApprovedTransactions => "approved-transactions",
            Self::DeniedTransactions => "denied-transactions",
            Self::FlaggedTransactions => "flagged-transactions",
            Self::EnforcementActivity => "enforcement-activity",
            Self::AccountActivity => "account-activity",
            Self::TokenActivity => "token-activity",
            Self::Investigations => "investigations",
            Self::Incidents => "incidents",
            Self::EvidenceSummary => "evidence-summary",
            Self::IntegrityVerification => "integrity-verification",
        }
    }
}

/// The query configuration a report was generated from.
///
/// Captured inside the report so the report can be reproduced: given the
/// same store and this query, a generator of the recorded version must
/// produce the same normalized output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportQuery {
    /// Time range covered, when bounded.
    pub time_range: Option<TimeRange>,
    /// Network filter, when bounded.
    pub network: Option<String>,
    /// Token scope (empty = all tokens in scope for the requester).
    pub tokens: Vec<TokenReference>,
    /// Event-kind filter (empty = all kinds).
    pub event_kinds: Vec<EventKind>,
    /// Outcome filter (e.g. only denied).
    pub outcome: Option<DecisionResult>,
    /// Single-account filter.
    pub account: Option<AccountId>,
    /// Classification ceiling: rows at or above this sensitivity are
    /// excluded from the report body.
    pub classification_ceiling: Option<DataClassification>,
}

impl ReportQuery {
    /// An empty query (no filters).
    pub fn all() -> Self {
        Self {
            time_range: None,
            network: None,
            tokens: Vec::new(),
            event_kinds: Vec::new(),
            outcome: None,
            account: None,
            classification_ceiling: None,
        }
    }

    /// A query filtered to one outcome (e.g. denied transactions).
    pub fn with_outcome(outcome: DecisionResult) -> Self {
        Self {
            outcome: Some(outcome),
            ..Self::all()
        }
    }
}

/// Version information recorded for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorVersions {
    /// Schema version of the report format.
    pub report_schema: u32,
    /// Version of the parser/normalizer that produced the source records.
    pub parser_version: VersionLabel,
    /// Version of the report generator.
    pub generator_version: VersionLabel,
}

/// Counts summarizing a report's covered records.
///
/// Counts only — never rows of protected data. The concrete rows (public
/// references) live in the report body assembled by the reporting crate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total records covered.
    pub total_records: u64,
    /// Records by outcome (allowed/denied/flagged).
    pub by_outcome: BTreeMap<DecisionResult, u64>,
    /// Records by event kind.
    pub by_kind: BTreeMap<EventKind, u64>,
    /// Records by reason code label, when recorded.
    pub by_reason: BTreeMap<String, u64>,
}

/// A generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    report_id: ReportId,
    kind: ReportKind,
    generated_at: Timestamp,
    generated_by: Option<AuditorId>,
    schema_version: u32,
    /// The query this report was generated from (reproducibility record).
    query: ReportQuery,
    /// Version information.
    versions: GeneratorVersions,
    /// Rows of public references (record ids, transaction hashes) included
    /// in the report body.
    record_refs: Vec<TransactionReference>,
    /// Summary counts.
    summary: ReportSummary,
    /// Digest over the canonical report content, when computed.
    digest: Option<IntegrityDigest>,
}

impl Report {
    /// Builds a report with empty content; populate rows, summary, and
    /// attribution through the builder methods.
    pub fn new(
        report_id: ReportId,
        kind: ReportKind,
        generated_at: Timestamp,
        query: ReportQuery,
        versions: GeneratorVersions,
    ) -> Self {
        Self {
            report_id,
            kind,
            generated_at,
            generated_by: None,
            schema_version: REPORT_SCHEMA_VERSION,
            query,
            versions,
            record_refs: Vec::new(),
            summary: ReportSummary::default(),
            digest: None,
        }
    }

    /// Attributes generation to an auditor.
    pub fn with_generated_by(mut self, auditor: AuditorId) -> Self {
        self.generated_by = Some(auditor);
        self
    }

    /// Sets the body rows (public transaction references only).
    pub fn with_rows(mut self, rows: Vec<TransactionReference>) -> Self {
        self.record_refs = rows;
        self
    }

    /// Sets the summary counts.
    pub fn with_summary(mut self, summary: ReportSummary) -> Self {
        self.summary = summary;
        self
    }

    /// Attaches the content digest.
    pub fn with_digest(mut self, digest: IntegrityDigest) -> Self {
        self.digest = Some(digest);
        self
    }

    /// Validates the report's schema version.
    pub fn validate(&self) -> AuditResult<()> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(format!(
                "report schema version {} is not supported (expected {REPORT_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if self.versions.report_schema != REPORT_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(
                "report versions disagree with the report schema".into(),
            ));
        }
        Ok(())
    }

    /// The report id.
    pub fn report_id(&self) -> &ReportId {
        &self.report_id
    }

    /// The report kind.
    pub fn kind(&self) -> ReportKind {
        self.kind
    }

    /// When the report was generated.
    pub fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    /// The query configuration (reproducibility record).
    pub fn query(&self) -> &ReportQuery {
        &self.query
    }

    /// The summary counts.
    pub fn summary(&self) -> &ReportSummary {
        &self.summary
    }

    /// The body rows (public transaction references).
    pub fn rows(&self) -> &[TransactionReference] {
        &self.record_refs
    }

    /// The content digest, once computed.
    pub fn digest(&self) -> Option<&IntegrityDigest> {
        self.digest.as_ref()
    }

    /// Canonical bytes for the report's *content* — the deterministic
    /// input to its content digest.
    ///
    /// The digest slot is excluded by construction: the digest is attached
    /// *after* the content is hashed, so it can never be part of the
    /// content it certifies. The generator hashes these bytes and a
    /// verifier recomputes them from the stored report, so both paths
    /// agree without field-stripping hacks.
    pub fn canonical_bytes(&self) -> AuditResult<Vec<u8>> {
        let mut content = self.clone();
        content.digest = None;
        crate::serialization::canonical_json(&content)
    }
}

/// A report request: what an authorized caller asked for.
///
/// Requests are validated and then captured inside the resulting report as
/// its query configuration, so reports and requests can never drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    report_id: Option<ReportId>,
    kind: ReportKind,
    query: ReportQuery,
    requested_by: AuditorId,
    requested_at: Timestamp,
}

impl ReportRequest {
    /// Builds a request.
    pub fn new(
        kind: ReportKind,
        query: ReportQuery,
        requested_by: AuditorId,
        requested_at: Timestamp,
    ) -> Self {
        Self {
            report_id: None,
            kind,
            query,
            requested_by,
            requested_at,
        }
    }

    /// The requested kind.
    pub fn kind(&self) -> ReportKind {
        self.kind
    }

    /// The query.
    pub fn query(&self) -> &ReportQuery {
        &self.query
    }

    /// Who requested the report.
    pub fn requested_by(&self) -> &AuditorId {
        &self.requested_by
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::NetworkId;

    #[test]
    fn report_kinds_are_stable_and_round_trip() {
        for kind in [
            ReportKind::ComplianceActivity,
            ReportKind::DeniedTransactions,
            ReportKind::IntegrityVerification,
            ReportKind::Incidents,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ReportKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
        assert_eq!(
            ReportKind::FlaggedTransactions.as_str(),
            "flagged-transactions"
        );
    }

    #[test]
    fn reports_capture_their_query_for_reproducibility() {
        let query = ReportQuery::with_outcome(DecisionResult::Denied);
        let versions = GeneratorVersions {
            report_schema: REPORT_SCHEMA_VERSION,
            parser_version: VersionLabel::new("1.4.0").unwrap(),
            generator_version: VersionLabel::new("0.2.0").unwrap(),
        };
        let summary = ReportSummary {
            total_records: 3,
            by_outcome: BTreeMap::from([(DecisionResult::Denied, 3)]),
            by_kind: BTreeMap::from([(EventKind::TransferDenied, 2)]),
            ..ReportSummary::default()
        };
        let report = Report::new(
            ReportId::derive(&["r"]),
            ReportKind::DeniedTransactions,
            Timestamp::from_unix_seconds(100),
            query.clone(),
            versions,
        )
        .with_generated_by(AuditorId::derive(&["a"]))
        .with_summary(summary.clone());
        assert!(report.validate().is_ok());
        assert_eq!(report.query(), &query);
        assert_eq!(report.summary().total_records, 3);
        assert_eq!(report.summary().by_outcome[&DecisionResult::Denied], 3);

        let request = ReportRequest::new(
            ReportKind::DeniedTransactions,
            query,
            AuditorId::derive(&["a"]),
            Timestamp::from_unix_seconds(99),
        );
        assert_eq!(request.kind(), ReportKind::DeniedTransactions);
        assert_eq!(request.query().outcome, Some(DecisionResult::Denied));
    }

    #[test]
    fn summary_counts_serialize_with_stable_keys() {
        let mut summary = ReportSummary::default();
        summary.by_kind.insert(EventKind::TransferDenied, 2);
        summary.by_kind.insert(EventKind::TransferAuthorized, 5);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"transfer-denied\":2"));
        assert!(json.contains("\"transfer-authorized\":5"));
    }

    #[test]
    fn schema_version_agreement_is_enforced() {
        let report = Report::new(
            ReportId::derive(&["r"]),
            ReportKind::EvidenceSummary,
            Timestamp::from_unix_seconds(0),
            ReportQuery::all(),
            GeneratorVersions {
                report_schema: 99,
                parser_version: VersionLabel::new("1").unwrap(),
                generator_version: VersionLabel::new("1").unwrap(),
            },
        );
        assert!(report.validate().is_err());
        let _ = NetworkId::new(NetworkId::MAINNET);
    }

    #[test]
    fn canonical_bytes_exclude_the_digest_slot() {
        let report = Report::new(
            ReportId::derive(&["r"]),
            ReportKind::ComplianceActivity,
            Timestamp::from_unix_seconds(100),
            ReportQuery::all(),
            GeneratorVersions {
                report_schema: REPORT_SCHEMA_VERSION,
                parser_version: VersionLabel::new("1").unwrap(),
                generator_version: VersionLabel::new("1").unwrap(),
            },
        );
        let digest = IntegrityDigest::sha256("aa".repeat(32)).unwrap();
        let sealed = report.clone().with_digest(digest);
        // Sealing never changes the canonical content: the digest is
        // attached after content hashing, not part of it.
        assert_eq!(
            report.canonical_bytes().unwrap(),
            sealed.canonical_bytes().unwrap()
        );
        // And content bytes are deterministic.
        assert_eq!(
            report.canonical_bytes().unwrap(),
            report.canonical_bytes().unwrap()
        );
    }
}
