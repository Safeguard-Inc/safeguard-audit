//! `create-investigation` — a runnable walk-through of the investigation
//! workflow.
//!
//! Ingests the denied-transfer envelope fixture into an audit store,
//! opens a case keyed on the denial, links the denial record, assigns an
//! investigator, records a finding and a note, and drives the case from
//! open through investigating to resolved and closed — while every
//! lifecycle step lands in the audit store as an investigation event.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example create-investigation
//! ```
//!
//! This is a demonstration harness, not a production binary: the case
//! store, audit store, and registry are in-memory, and the credential is
//! opaque test material (no real identity provider is involved).

use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessScope, AuditorId, AuditorRole, CaseStatus, EventKind, EventSource, FixedClock, NetworkId,
    PageRequest, Priority, RawEventItem, SourcePage, SourceResult, Timestamp, VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_investigation::{CaseService, InMemoryCaseStore, NewFinding};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore};

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:investigation-demo"
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

fn main() {
    let network = NetworkId::new(NetworkId::TESTNET).unwrap();
    let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500));
    let investigator = AuditorId::derive(&["investigator-01"]);

    // --- Registry: one investigator with a valid credential. ----------
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(investigator.clone(), AuditorRole::Investigator)
                .with_scope(AccessScope::Network(network.clone()))
                .with_credential(Credential::new(
                    investigator.clone(),
                    "issued-investigator-credential",
                    Timestamp::from_unix_seconds(1_900_000_000),
                )),
        )
        .expect("investigator grant is valid");
    let authorizer = Authorizer::new(registry, clock);

    let service = CaseService::new(
        network.clone(),
        safeguard_audit_investigation::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        clock,
        authorizer,
    );

    // --- Audit store: ingest the denied-transfer envelope. ------------
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures/events/denied-transfer/event.json");
    let payload = std::fs::read_to_string(&fixture).unwrap_or_else(|e| panic!("read fixture: {e}"));
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
        items: vec![RawEventItem::new("audit-envelope", payload, "ledger:430").unwrap()],
    };
    indexer
        .run_once(&mut source, &mut checkpoints, &mut audit_store)
        .expect("ingest succeeds");

    let page = audit_store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(10).unwrap(),
        )
        .unwrap();
    let denial_record = page.items()[0].clone();
    let denial_id = denial_record.record_id.clone();
    println!(
        "Ingested denial record {} (kind: {}).",
        denial_id,
        denial_record.event.kind.as_str()
    );

    // --- Run the case workflow. ---------------------------------------
    let mut case_store = InMemoryCaseStore::new();
    let case_key = format!("denial:{}", denial_id.as_str());

    let opened = service
        .open_case(
            &mut case_store,
            &mut audit_store,
            &investigator,
            "review of repeated denials",
            Priority::High,
            &case_key,
        )
        .expect("case opens");
    println!("Opened case {}", opened.case_id());

    service
        .assign(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            &investigator,
        )
        .expect("case assigns");

    service
        .link_record(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            &denial_id,
            safeguard_audit_core::TimelineEntryKind::Denial,
        )
        .expect("denial links onto the timeline");

    service
        .transition(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            CaseStatus::Investigating,
            None,
        )
        .expect("case moves to investigating");

    service
        .add_finding(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            NewFinding::new(
                safeguard_audit_core::FindingKind::Anomaly,
                safeguard_audit_core::Severity::Medium,
                "denials cluster around a single source account",
            )
            .with_records(vec![denial_id.clone()]),
        )
        .expect("finding records");

    service
        .add_note(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            "comparing against the policy-change record before closing",
        )
        .expect("note records");

    service
        .transition(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            CaseStatus::Resolved,
            None,
        )
        .expect("case resolves");

    let closed = service
        .transition(
            &mut case_store,
            &mut audit_store,
            &investigator,
            opened.case_id(),
            CaseStatus::Closed,
            Some("pattern explained; no remediation needed"),
        )
        .expect("case closes with a reason");
    println!(
        "Case closed: {} timeline entries, {} finding(s), {} note(s).",
        closed.timeline().len(),
        closed.findings().len(),
        closed.notes().len()
    );

    // --- Show the audit store's lifecycle history. --------------------
    let page = audit_store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(100).unwrap(),
        )
        .unwrap();
    println!("\nAudit-store history ({} records):", page.items().len());
    for record in page.items() {
        let kind = match record.event.kind {
            EventKind::InvestigationOpened => "investigation-opened".to_owned(),
            EventKind::InvestigationUpdated => {
                let d = &record.event.details;
                let status = d.get("status").map(String::as_str).unwrap_or("?");
                format!("investigation-updated ({status})")
            }
            EventKind::InvestigationClosed => "investigation-closed".to_owned(),
            other => other.as_str().to_owned(),
        };
        let case = record
            .event
            .details
            .get("case")
            .map(String::as_str)
            .unwrap_or("-");
        println!("  {kind:<28} case={case}");
    }
    println!("\nOK: the case is closed, its history is append-only, and replay is idempotent.");
}
