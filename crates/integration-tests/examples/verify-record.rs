//! `verify-record` — a runnable walk-through of integrity verification.
//!
//! Ingests the committed hooks-state fixtures, seals the recorded history
//! into a chained digest sequence, verifies the chain, and — with the
//! `--tamper` flag — demonstrates that a record altered at the
//! persistence boundary is detected and named.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example verify-record
//! cargo run -p safeguard-audit-integration-tests --example verify-record -- --tamper
//! ```
//!
//! This is a demonstration harness, not a production binary: the store,
//! checkpoint, and records are in-memory.

use safeguard_audit_core::PageRequest;
use safeguard_audit_core::{
    EventSource, FixedClock, NetworkId, RawEventItem, SourcePage, SourceResult, Timestamp,
    VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_integrity::{locate_tampering, seal_chain, verify_chain};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::{AuditQuery, EventStore};

struct FixtureSource {
    items: Vec<RawEventItem>,
}

impl EventSource for FixtureSource {
    type Error = safeguard_audit_core::SourceError;
    fn source_name(&self) -> &str {
        "fixture:demo"
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

fn fixture(name: &str, position: &str) -> RawEventItem {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("events")
        .join(name);
    let payload =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    RawEventItem::new("hooks-state-event", payload, position)
        .expect("fixture satisfies the contract")
}

fn main() {
    let tamper_demo = std::env::args().any(|a| a == "--tamper");

    let normalizer = Normalizer::new(NormalizeConfig::new(
        NetworkId::new(NetworkId::TESTNET).unwrap(),
        "safeguard-hooks",
        VersionLabel::new("1.0.0").unwrap(),
    ));
    let indexer = Indexer::new(
        normalizer,
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_500)),
        DedupPolicy::SkipDuplicates,
        MalformedItemPolicy::AbortOnMalformed,
        100,
    )
    .expect("indexer config is valid");

    let mut checkpoints = InMemoryCheckpointStore::new();
    let mut store = MemoryEventStore::new();
    let mut source = FixtureSource {
        items: vec![
            fixture("bound-token/observed-hooks-event.json", "ledger:415"),
            fixture("config-change/observed-hooks-event.json", "ledger:419"),
            fixture("frozen-account/observed-hooks-event.json", "ledger:423"),
        ],
    };
    indexer
        .run_once(&mut source, &mut checkpoints, &mut store)
        .expect("ingest succeeds");

    // Read history back in position order and seal it into a chain.
    let history = store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(1000).unwrap(),
        )
        .unwrap()
        .items()
        .to_vec();
    println!(
        "Sealing {} records into a chained digest sequence...",
        history.len()
    );

    let mut sealed = seal_chain(&history).expect("records canonicalize");

    verify_chain(&sealed).expect("the freshly sealed chain must verify");
    println!("  chain verified: every digest recomputes, every linkage holds.");

    if tamper_demo {
        // Simulate a record altered after sealing (as a corrupted database
        // would surface it) and show detection.
        sealed[1].recorded_at = Timestamp::from_unix_seconds(1_700_000_000 + 7);
        let found = locate_tampering(&sealed).expect("detection runs");
        assert_eq!(found.len(), 1, "exactly one record broke");
        println!(
            "  tamper demo:  record {} -> {} ({}).",
            found[0].record_id(),
            found[0].status().as_str(),
            found[0].detail().unwrap_or("")
        );
        println!("  Detection confirmed: the altered record is named, not merely flagged.");
    } else {
        println!("  Run with `-- --tamper` to see tamper detection in action.");
    }
    println!("OK: records are tamper-evident and verification is deterministic.");
}
