//! `ingest-event` — a runnable walk-through of the ingestion pipeline.
//!
//! Ingests the committed hooks-state fixtures through the real
//! normalizer, indexer, checkpoint, and store, reports what landed, then
//! re-runs the same window to demonstrate that ingestion is idempotent.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example ingest-event
//! ```
//!
//! This is a demonstration harness, not a production binary: the store
//! and checkpoint are in-memory and vanish on exit.

use std::path::PathBuf;

use safeguard_audit_core::{
    EventSource, FixedClock, NetworkId, RawEventItem, SourcePage, SourceResult, Timestamp,
    VersionLabel,
};
use safeguard_audit_indexer::{DedupPolicy, InMemoryCheckpointStore, Indexer, MalformedItemPolicy};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer};
use safeguard_audit_storage::EventStore;

/// The committed hooks fixtures, in ledger order (415, 419, 423).
const FIXTURES: &[(&str, &str)] = &[
    ("bound-token/observed-hooks-event.json", "ledger:415"),
    ("config-change/observed-hooks-event.json", "ledger:419"),
    ("frozen-account/observed-hooks-event.json", "ledger:423"),
];

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

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("events")
}

fn load_fixtures() -> Vec<RawEventItem> {
    FIXTURES
        .iter()
        .map(|(path, position)| {
            let full = fixture_root().join(path);
            let payload = std::fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("read {}: {e}", full.display()));
            RawEventItem::new("hooks-state-event", payload, *position)
                .expect("fixtures satisfy the item contract")
        })
        .collect()
}

fn main() {
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

    let items = load_fixtures();
    println!(
        "Ingesting {} fixture events from `hooks-state-event`...",
        items.len()
    );

    let mut source = FixtureSource {
        items: items.clone(),
    };
    let first = indexer
        .run_once(&mut source, &mut checkpoints, &mut store)
        .expect("first run ingests the window");
    println!("  first run:  {}", first);
    assert_eq!(store.len(), items.len(), "all fixtures recorded");

    // Re-run the same window from a fresh checkpoint: the store's
    // idempotent dedup means nothing is recorded twice.
    let mut replay_source = FixtureSource { items };
    let mut fresh_checkpoints = InMemoryCheckpointStore::new();
    let second = indexer
        .run_once(&mut replay_source, &mut fresh_checkpoints, &mut store)
        .expect("re-run is safe");
    println!("  re-run:     {}", second);
    println!(
        "Store holds {} records; re-ingestion added {} (idempotent).",
        store.len(),
        second.inserted
    );
    assert_eq!(second.inserted, 0, "re-ingestion must be idempotent");
    println!("OK: ingestion is checkpointed, ordered, and idempotent.");
}
