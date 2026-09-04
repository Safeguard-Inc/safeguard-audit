//! The evidence workflow over the real pipeline.
//!
//! Two on-chain events (a denial and a freeze) are ingested from the
//! hooks fixtures, a senior auditor seals an evidence package over them,
//! the generation is itself recorded as an `evidence-generated` event,
//! and the package verifies — while a tampered artifact or a mismatched
//! manifest is caught by structure and store-backed verification.

use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessScope, AuditorId, AuditorRole, EventKind, EventSource, EvidenceKind, FixedClock,
    NetworkId, PageRequest, RawEventItem, SourcePage, SourceResult, Timestamp, VersionLabel,
};
use safeguard_audit_evidence::{EvidenceBuildOptions, EvidenceBuilder};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore};

const DENIED_FIXTURE: &str = include_str!("../../../fixtures/events/denied-transfer/event.json");
const FROZEN_FIXTURE: &str = include_str!("../../../fixtures/events/frozen-account/event.json");

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:evidence"
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

/// Ingests both fixtures into a fresh audit store and returns the store
/// plus every record id (history order).
fn ingest() -> (MemoryEventStore, Vec<safeguard_audit_core::RecordId>) {
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
        items: vec![
            RawEventItem::new("audit-envelope", DENIED_FIXTURE, "ledger:430").unwrap(),
            RawEventItem::new("audit-envelope", FROZEN_FIXTURE, "ledger:431").unwrap(),
        ],
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
    let ids = page.items().iter().map(|r| r.record_id.clone()).collect();
    (store, ids)
}

#[test]
fn evidence_over_pipeline_records_seals_verifies_and_detects_tampering() {
    let (mut audit, record_ids) = ingest();
    let senior = auditor("senior-1");
    let builder = EvidenceBuilder::new(
        net(),
        safeguard_audit_evidence::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.4.0").unwrap(),
        clock(),
        authorizer(&senior),
    );

    // 1. Seal evidence over both ingested records.
    let options = EvidenceBuildOptions::new(
        EvidenceKind::TransactionEvidence,
        record_ids.clone(),
        senior.clone(),
    )
    .unwrap();
    let package = builder.build(&mut audit, &options).unwrap();
    assert_eq!(package.artifact().kind(), EvidenceKind::TransactionEvidence);
    assert_eq!(package.manifest().record_count(), 2);
    assert!(package.artifact().digest().is_some());
    assert_eq!(
        package.manifest().artifact(),
        package.artifact().evidence_id(),
        "the manifest certifies the artifact it ships with"
    );

    // 2. The store records the generation itself.
    let page = audit
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(100).unwrap(),
        )
        .unwrap();
    let records = page.items();
    assert_eq!(records.len(), 3, "2 sources + 1 evidence-generated");
    let generation = records
        .iter()
        .find(|r| r.event.kind == EventKind::EvidenceGenerated)
        .expect("the generation is recorded");
    assert_eq!(
        generation.event.details.get("kind").map(String::as_str),
        Some("transaction-evidence")
    );
    assert_eq!(
        generation.event.details.get("records").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        generation.event.details.get("evidence").map(String::as_str),
        Some(package.artifact().evidence_id().as_str())
    );

    // 3. The freshly built package verifies at both depths.
    assert!(safeguard_audit_evidence::verify_package_structure(&package)
        .unwrap()
        .verified());
    let full = safeguard_audit_evidence::verify_package(&package, &audit).unwrap();
    assert!(full.verified());
    assert_eq!(full.records().len(), 2);

    // 4. A tampered artifact digest is caught without the store. The
    //    tampering is done at the wire level (JSON), as a corrupted export
    //    would present it.
    let mut value = serde_json::to_value(&package).unwrap();
    value["artifact"]["digest"]["value"] = serde_json::Value::String("ee".repeat(32));
    let wrong: safeguard_audit_evidence::EvidencePackage = serde_json::from_value(value).unwrap();
    let structure = safeguard_audit_evidence::verify_package_structure(&wrong).unwrap();
    assert!(!structure.verified());
    assert!(!structure.artifact_verified());

    // 5. A tampered manifest entry is caught by store-backed verification.
    let mut value = serde_json::to_value(&package).unwrap();
    value["manifest"]["entries"][1]["digest"]["value"] = serde_json::Value::String("dd".repeat(32));
    let tampered: safeguard_audit_evidence::EvidencePackage =
        serde_json::from_value(value).unwrap();
    let full = safeguard_audit_evidence::verify_package(&tampered, &audit).unwrap();
    assert!(!full.verified());
}

#[test]
fn evidence_generation_is_reproducible_with_a_fixed_clock() {
    let (mut audit, record_ids) = ingest();
    let senior = auditor("senior-1");
    let builder = EvidenceBuilder::new(
        net(),
        safeguard_audit_evidence::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.4.0").unwrap(),
        clock(),
        authorizer(&senior),
    );
    let options = EvidenceBuildOptions::new(
        EvidenceKind::TransactionEvidence,
        record_ids,
        senior.clone(),
    )
    .unwrap();
    let first = builder.build(&mut audit, &options).unwrap();
    let second = builder.build(&mut audit, &options).unwrap();
    assert_eq!(
        first, second,
        "same sources and configuration produce the identical package"
    );
}

#[test]
fn read_only_reviewers_cannot_generate_evidence() {
    let (mut audit, record_ids) = ingest();
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
    let builder = EvidenceBuilder::new(
        net(),
        safeguard_audit_evidence::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.4.0").unwrap(),
        clock(),
        Authorizer::new(registry, clock()),
    );
    let options = EvidenceBuildOptions::new(
        EvidenceKind::TransactionEvidence,
        record_ids,
        reviewer.clone(),
    )
    .unwrap();
    let err = builder.build(&mut audit, &options).unwrap_err();
    assert!(matches!(
        err,
        safeguard_audit_evidence::EvidenceError::NotAuthorized(..)
    ));
}
