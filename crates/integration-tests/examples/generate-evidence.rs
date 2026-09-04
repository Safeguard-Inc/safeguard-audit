//! `generate-evidence` — a runnable walk-through of the evidence
//! workflow.
//!
//! Ingests the denied-transfer and frozen-account envelope fixtures into
//! an audit store, a senior auditor seals an evidence package over both
//! records, the generation is recorded as an `evidence-generated` event,
//! the package verifies at both depths, and a wire-level tamper of the
//! artifact digest is caught.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example generate-evidence
//! ```
//!
//! This is a demonstration harness, not a production binary: the audit
//! store and registry are in-memory, and the credential is opaque test
//! material (no real identity provider is involved).

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

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:evidence-demo"
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

    let builder = EvidenceBuilder::new(
        network.clone(),
        safeguard_audit_evidence::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.4.0").unwrap(),
        clock,
        authorizer,
    );

    // --- Audit store: ingest two on-chain envelopes. ------------------
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
                read_fixture("denied-transfer/event.json"),
                "ledger:430",
            )
            .unwrap(),
            RawEventItem::new(
                "audit-envelope",
                read_fixture("frozen-account/event.json"),
                "ledger:431",
            )
            .unwrap(),
        ],
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
    let record_ids: Vec<_> = page
        .items()
        .iter()
        .map(|r| r.record_id.clone())
        .collect();
    println!(
        "Ingested {} records: {}",
        record_ids.len(),
        page.items()
            .iter()
            .map(|r| r.event.kind.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // --- Seal an evidence package over the ingested records. ----------
    let options = EvidenceBuildOptions::new(
        EvidenceKind::TransactionEvidence,
        record_ids,
        senior.clone(),
    )
    .expect("evidence options are valid");
    let package = builder
        .build(&mut audit_store, &options)
        .expect("evidence seals");
    println!(
        "Sealed evidence {} ({} records, manifest {}, digest {})",
        package.artifact().evidence_id(),
        package.manifest().record_count(),
        package.manifest().manifest_id(),
        package
            .artifact()
            .digest()
            .map(|d| d.value())
            .unwrap_or("-")
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
        .find(|r| r.event.kind == EventKind::EvidenceGenerated)
        .expect("the generation is recorded");
    println!(
        "Recorded evidence-generated event (kind {}, records {})",
        generation.event.details.get("kind").map(String::as_str).unwrap_or("?"),
        generation.event.details.get("records").map(String::as_str).unwrap_or("?")
    );

    // --- Verify at both depths. ---------------------------------------
    let structure = safeguard_audit_evidence::verify_package_structure(&package)
        .expect("structure verification runs");
    let full = safeguard_audit_evidence::verify_package(&package, &audit_store)
        .expect("store-backed verification runs");
    println!(
        "Verified: structure={} records={}",
        structure.verified(),
        full.verified()
    );

    // --- Tamper at the wire level and show the detection. -------------
    let mut value = serde_json::to_value(&package).unwrap();
    value["artifact"]["digest"]["value"] = serde_json::Value::String("ee".repeat(32));
    let tampered: safeguard_audit_evidence::EvidencePackage =
        serde_json::from_value(value).expect("tampered package still deserializes");
    let structure = safeguard_audit_evidence::verify_package_structure(&tampered)
        .expect("verification runs on the tampered package");
    println!(
        "Tampered artifact digest detected: verified={} artifact={}",
        structure.verified(),
        structure.artifact_verified()
    );
    println!("\nOK: the package verifies, its generation is on the trail, and tampering is detectable.");
}