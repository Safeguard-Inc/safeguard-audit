//! The investigation workflow over the real pipeline.
//!
//! The scenario a case exists for: a denied transfer is ingested from the
//! hooks fixture, an investigator opens a case keyed on it, links the
//! denial record, adds a finding, escalates, and closes with a reason —
//! while the audit store records every lifecycle step and the case store
//! keeps current state. Both views are asserted at the end.

use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessScope, AuditorId, AuditorRole, CaseId, CaseStatus, EventKind, EventSource, FixedClock,
    NetworkId, PageRequest, Priority, RawEventItem, SourcePage, SourceResult, Timestamp,
    VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_investigation::{CaseService, CaseStore, InMemoryCaseStore, NewFinding};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore};

const DENIED_FIXTURE: &str = include_str!("../../../fixtures/events/denied-transfer/event.json");

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:investigation"
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

fn authorizer() -> Authorizer {
    let mut registry = Registry::new();
    let inv = auditor("investigator-1");
    registry
        .register(
            Grant::new(inv.clone(), AuditorRole::Investigator)
                .with_scope(AccessScope::Network(net()))
                .with_credential(Credential::new(
                    inv,
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    Authorizer::new(registry, clock())
}

/// Ingests the denied-transfer fixture into a fresh audit store, returning
/// the store plus the record id of the denial.
fn ingest_denial() -> (MemoryEventStore, safeguard_audit_core::RecordId) {
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
    let mut source = FixtureSource {
        items: vec![RawEventItem::new("audit-envelope", DENIED_FIXTURE, "ledger:430").unwrap()],
    };
    indexer
        .run_once(&mut source, &mut checkpoints, &mut store)
        .unwrap();

    let page = store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(10).unwrap(),
        )
        .unwrap();
    let record = page.items()[0].clone();
    (store, record.record_id.clone())
}

#[test]
fn denied_transfer_becomes_a_case_with_a_verifiable_timeline() {
    let (audit_store, denial_record) = ingest_denial();
    let mut case_store = InMemoryCaseStore::new();

    let service = CaseService::new(
        net(),
        safeguard_audit_investigation::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        clock(),
        authorizer(),
    );

    // 1. Open a case keyed on the denial.
    let mut audit = audit_store;
    let opened = service
        .open_case(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            "repeated denial review",
            Priority::High,
            "denial:tx-flagged",
        )
        .unwrap();
    let case_id = opened.case_id().clone();
    assert_eq!(
        case_id,
        CaseId::derive(&[net().as_str(), "denial:tx-flagged"]),
        "case id derives deterministically from network and key"
    );

    // 2. Link the actual denial record from the audit store.
    let linked = service
        .link_record(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            &denial_record,
            safeguard_audit_core::TimelineEntryKind::Denial,
        )
        .unwrap();
    assert_eq!(linked.timeline().len(), 1);
    assert_eq!(linked.timeline()[0].record(), Some(&denial_record));

    // 3. Assign, move to investigating, and record a finding.
    service
        .assign(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            &auditor("investigator-1"),
        )
        .unwrap();
    service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Investigating,
            None,
        )
        .unwrap();
    let with_finding = service
        .add_finding(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            NewFinding::new(
                safeguard_audit_core::FindingKind::Anomaly,
                safeguard_audit_core::Severity::High,
                "the same source account was denied three times",
            )
            .with_records(vec![denial_record.clone()]),
        )
        .unwrap();
    assert_eq!(with_finding.findings().len(), 1);

    // 4. Resolve and close with a reason.
    service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Resolved,
            None,
        )
        .unwrap();
    let closed = service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Closed,
            Some("no violation; pattern explained by policy change"),
        )
        .unwrap();
    assert_eq!(closed.status(), CaseStatus::Closed);
    assert!(closed.validate().is_ok());

    // 5. The case store holds the final state.
    let stored = case_store.get(&case_id).unwrap();
    assert_eq!(stored.status(), CaseStatus::Closed);
    assert_eq!(stored.findings().len(), 1);
    // Six mutations after opening each add one timeline entry: link,
    // assign, investigating, finding, resolved, closed.
    assert_eq!(stored.timeline().len(), 6);

    // 6. The audit store holds the full lifecycle history: the original
    //    denial record plus the opened event and one event per mutation
    //    (5 updates + 1 close).
    let page = audit
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(100).unwrap(),
        )
        .unwrap();
    let records = page.items();
    // 1 denial + 1 open + 5 updates + 1 close = 8 total.
    assert_eq!(records.len(), 8);
    let lifecycle: Vec<EventKind> = records
        .iter()
        .map(|r| r.event.kind)
        .filter(|k| *k != EventKind::TransferDenied)
        .collect();
    assert_eq!(lifecycle[0], EventKind::InvestigationOpened);
    assert!(lifecycle.contains(&EventKind::InvestigationClosed));
    // Every step after the first is an update, never a second open.
    assert_eq!(
        lifecycle
            .iter()
            .filter(|k| **k == EventKind::InvestigationOpened)
            .count(),
        1
    );
}

#[test]
fn closing_is_irreversible_without_administrator_reopen() {
    // An investigator who closes a case cannot reopen it; only an
    // administrator with the all-powerful role may.
    let (audit_store, denial_record) = ingest_denial();
    let mut case_store = InMemoryCaseStore::new();
    let mut audit = audit_store;

    let service = CaseService::new(
        net(),
        safeguard_audit_investigation::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        clock(),
        authorizer(),
    );
    let opened = service
        .open_case(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            "review",
            Priority::Low,
            "denial:tx-close",
        )
        .unwrap();
    let case_id = opened.case_id().clone();
    service
        .link_record(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            &denial_record,
            safeguard_audit_core::TimelineEntryKind::Denial,
        )
        .unwrap();
    service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Investigating,
            None,
        )
        .unwrap();
    service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Resolved,
            None,
        )
        .unwrap();
    service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Closed,
            Some("done"),
        )
        .unwrap();

    // A closed case is terminal: no further mutation by an investigator.
    let err = service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Investigating,
            None,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        safeguard_audit_investigation::InvestigationError::ClosedCase(_)
    ));

    // Reopening requires an administrator.
    let err = service
        .transition(
            &mut case_store,
            &mut audit,
            &auditor("investigator-1"),
            &case_id,
            CaseStatus::Open,
            None,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        safeguard_audit_investigation::InvestigationError::NotAuthorized(..)
    ));
}
