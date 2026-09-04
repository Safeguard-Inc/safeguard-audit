//! `generate-report` — a runnable walk-through of the reporting workflow.
//!
//! Ingests an approval, a denial, and a freeze from the hooks fixtures,
//! a senior auditor requests a denied-transactions report, and the
//! generator counts only the denial, rows its public transaction
//! reference, seals the report with a content digest, records a
//! `report-generated` event, and reproduces the identical report from the
//! same request.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example generate-report
//! ```
//!
//! This is a demonstration harness, not a production binary: the audit
//! store and registry are in-memory, and the credential is opaque test
//! material (no real identity provider is involved).

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

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:reporting-demo"
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

fn read_fixture(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(format!("fixtures/events/{name}"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

fn main() {
    let network = NetworkId::new(NetworkId::TESTNET).unwrap();
    let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500));
    let senior = AuditorId::derive(&["senior-auditor-01"]);

    // --- Registry: one senior auditor with a valid credential. --------
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(senior.clone(), AuditorRole::SeniorAuditor)
                .with_scope(AccessScope::Network(network.clone()))
                .with_credential(Credential::new(
                    senior.clone(),
                    "issued-senior-credential",
                    Timestamp::from_unix_seconds(1_900_000_000),
                )),
        )
        .expect("senior grant is valid");
    let authorizer = Authorizer::new(registry, clock);

    let service = ReportService::new(
        network.clone(),
        safeguard_audit_reporting::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.5.0").unwrap(),
        clock,
        authorizer,
    );

    // --- Audit store: ingest three on-chain envelopes. ----------------
    let normalizer = Normalizer::new(NormalizeConfig::new(
        network.clone(),
        "safeguard-audit",
        VersionLabel::new("1.0.0").unwrap(),
    ));
    let indexer = Indexer::new(
        normalizer,
        clock,
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        100,
    )
    .expect("indexer config is valid");

    let mut checkpoints = InMemoryCheckpointStore::new();
    let mut audit_store = MemoryEventStore::new();
    let mut source = FixtureSource {
        items: vec![
            RawEventItem::new(
                "audit-envelope",
                read_fixture("approved-transfer/event.json"),
                "ledger:430",
            )
            .unwrap(),
            RawEventItem::new(
                "audit-envelope",
                read_fixture("denied-transfer/event.json"),
                "ledger:431",
            )
            .unwrap(),
            RawEventItem::new(
                "audit-envelope",
                read_fixture("frozen-account/event.json"),
                "ledger:432",
            )
            .unwrap(),
        ],
    };
    indexer
        .run_once(&mut source, &mut checkpoints, &mut audit_store)
        .expect("ingest succeeds");
    println!("Ingested 3 records (approved, denied, frozen).");

    // --- Request and generate a denied-transactions report. -----------
    let request = ReportRequest::new(
        ReportKind::DeniedTransactions,
        ReportQuery::with_outcome(DecisionResult::Denied),
        senior.clone(),
        Timestamp::from_unix_seconds(1_700_000_499),
    );
    let report = service
        .generate(&mut audit_store, &request)
        .expect("report generates");
    println!(
        "Report {} ({}) over {} record(s): {} denied, {} row(s), digest {}",
        report.report_id(),
        report.kind().as_str(),
        report.summary().total_records,
        report.summary().by_outcome.get(&DecisionResult::Denied).copied().unwrap_or(0),
        report.rows().len(),
        report.digest().map(|d| d.value()).unwrap_or("-")
    );

    // --- The generation is itself recorded. ---------------------------
    let page = audit_store
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
    println!(
        "Recorded report-generated event (kind {}, records {})",
        generation.event.details.get("kind").map(String::as_str).unwrap_or("?"),
        generation.event.details.get("records").map(String::as_str).unwrap_or("?")
    );

    // --- The same request reproduces the identical report. ------------
    let reproduced = service
        .generate(&mut audit_store, &request)
        .expect("report reproduces");
    assert_eq!(report, reproduced, "same request reproduces the identical report");
    println!(
        "Reproduced identical report {} (digest {}).",
        reproduced.report_id(),
        reproduced.digest().map(|d| d.value()).unwrap_or("-")
    );
    println!("\nOK: the report is sealed, its generation is on the trail, and it reproduces.");
}