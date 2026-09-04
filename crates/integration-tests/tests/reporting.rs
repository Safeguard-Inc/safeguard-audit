//! The reporting workflow over the real pipeline.
//!
//! A denial, an approval, and a freeze are ingested from the hooks
//! fixtures; a senior auditor requests a denied-transactions report; the
//! generator scans the range, counts only the denials, rows their public
//! transaction references, seals the report with a digest, and records a
//! `report-generated` event. Re-running the same request reproduces the
//! same report.

use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessScope, AuditorId, AuditorRole, DecisionResult, EventKind, EventSource, FixedClock,
    NetworkId, PageRequest, RawEventItem, ReportKind, ReportQuery, ReportRequest, SourcePage,
    SourceResult, Timestamp, VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_reporting::ReportService;
use safeguard_audit_storage::{AuditQuery, EventStore};

const DENIED_FIXTURE: &str = include_str!("../../../fixtures/events/denied-transfer/event.json");
const APPROVED_FIXTURE: &str = include_str!("../../../fixtures/events/approved-transfer/event.json");
const FROZEN_FIXTURE: &str = include_str!("../../../fixtures/events/frozen-account/event.json");

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:reporting"
    }
    fn fetch_after(&mut self, after: Option<&str>, limit: usize) -> SourceResult<SourcePage> {
        let start = match after {
            None => 0,
            Some(pos) => {
                self.items
                    .iter()
                    .position(|i| i.position() == pos)
                    .ok_or_else(|| {
                        safeguard_audit_core::SourceError::InvalidPosition(pos.to_owned())
                    })?
                    + 1
            }
        };
        let end = (start + limit).min(self.items.len());
        let items = self.items[start..end].to_vec();
        let next = if end < self.items.len() {
            Some(self.items[end - 1].position().to_owned())
        } else {
            None
        };
        Ok(SourcePage::new(items, next))
    }
}

fn net() -> NetworkId {
    NetworkId::new(NetworkId::TESTNET).unwrap()
}

fn clock() -> FixedClock {
    FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500))
}

fn auditor(name: &str) -> AuditorId {
    AuditorId::derive(&[name])
}

fn authorizer(actor: &AuditorId) -> Authorizer {
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(actor.clone(), AuditorRole::SeniorAuditor)
                .with_scope(AccessScope::Network(net()))
                .with_credential(Credential::new(
                    actor.clone(),
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    Authorizer::new(registry, clock())
}

fn ingest() -> MemoryEventStore {
    let normalizer = Normalizer::new(NormalizeConfig::new(
        net(),
        "safeguard-hooks",
        VersionLabel::new("1.0.0").unwrap(),
    ));
    let indexer = Indexer::new(
        normalizer,
        clock(),
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        100,
    )
    .unwrap();
    let mut checkpoints = InMemoryCheckpointStore::new();
    let mut store = MemoryEventStore::new();
    // Order by each fixture's internal ledger sequence (420, 421, 423).
    let mut source = FixtureSource {
        items: vec![
            RawEventItem::new("audit-envelope", APPROVED_FIXTURE, "ledger:430").unwrap(),
            RawEventItem::new("audit-envelope", DENIED_FIXTURE, "ledger:431").unwrap(),
            RawEventItem::new("audit-envelope", FROZEN_FIXTURE, "ledger:432").unwrap(),
        ],
    };
    indexer
        .run_once(&mut source, &mut checkpoints, &mut store)
        .unwrap();
    store
}

#[test]
fn denied_transactions_report_over_pipeline_records_is_sealed_and_reproducible() {
    let mut audit = ingest();
    let senior = auditor("senior-1");
    let service = ReportService::new(
        net(),
        safeguard_audit_reporting::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.5.0").unwrap(),
        clock(),
        authorizer(&senior),
    );

    // 1. Request a denied-transactions report.
    let request = ReportRequest::new(
        ReportKind::DeniedTransactions,
        ReportQuery::with_outcome(DecisionResult::Denied),
        senior.clone(),
        Timestamp::from_unix_seconds(1_700_000_499),
    );
    let report = service.generate(&mut audit, &request).unwrap();

    // 2. Only the denial is covered: one record, one denied outcome, one
    //    transfer-denied kind, and one public row (the denial's
    //    transaction reference).
    assert_eq!(report.summary().total_records, 1);
    assert_eq!(report.summary().by_outcome[&DecisionResult::Denied], 1);
    assert_eq!(report.summary().by_kind[&EventKind::TransferDenied], 1);
    assert_eq!(report.rows().len(), 1);
    assert!(report.digest().is_some());
    assert!(report.validate().is_ok());

    // 3. The report's captured query is exactly what was requested
    //    (the reproducibility record).
    assert_eq!(report.query().outcome, Some(DecisionResult::Denied));

    // 4. The generation is itself recorded on the trail.
    let page = audit
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(100).unwrap(),
        )
        .unwrap();
    let generation = page
        .items()
        .iter()
        .find(|r| r.event.kind == EventKind::ReportGenerated)
        .expect("the generation is recorded");
    assert_eq!(
        generation.event.details.get("kind").map(String::as_str),
        Some("denied-transactions")
    );
    assert_eq!(
        generation.event.details.get("records").map(String::as_str),
        Some("1")
    );

    // 5. The same request reproduces the identical report (same store
    //    state, fixed clock): same id, same digest, same content.
    let second = service.generate(&mut audit, &request).unwrap();
    assert_eq!(report, second);
    assert_eq!(report.report_id(), second.report_id());
}

#[test]
fn compliance_activity_report_counts_the_whole_range() {
    let mut audit = ingest();
    let senior = auditor("senior-1");
    let service = ReportService::new(
        net(),
        safeguard_audit_reporting::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.5.0").unwrap(),
        clock(),
        authorizer(&senior),
    );
    let request = ReportRequest::new(
        ReportKind::ComplianceActivity,
        ReportQuery::all(),
        senior.clone(),
        Timestamp::from_unix_seconds(1_700_000_499),
    );
    let report = service.generate(&mut audit, &request).unwrap();
    assert_eq!(report.summary().total_records, 3);
    assert_eq!(report.rows().len(), 3);
    assert_eq!(
        report.summary().by_kind[&EventKind::AccountFrozen],
        1
    );
}

#[test]
fn read_only_reviewers_cannot_generate_reports() {
    let mut audit = ingest();
    let reviewer = auditor("reviewer-1");
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(reviewer.clone(), AuditorRole::ReadOnlyReviewer)
                .with_scope(AccessScope::Network(net()))
                .with_credential(Credential::new(
                    reviewer.clone(),
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    let service = ReportService::new(
        net(),
        safeguard_audit_reporting::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.5.0").unwrap(),
        clock(),
        Authorizer::new(registry, clock()),
    );
    let request = ReportRequest::new(
        ReportKind::ComplianceActivity,
        ReportQuery::all(),
        reviewer.clone(),
        Timestamp::from_unix_seconds(1_700_000_499),
    );
    let err = service.generate(&mut audit, &request).unwrap_err();
    assert!(matches!(
        err,
        safeguard_audit_reporting::ReportingError::NotAuthorized(..)
    ));
}