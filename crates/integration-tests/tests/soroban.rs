//! End-to-end exercise of the Soroban adapter stack: committed wire
//! fixtures feed a mock RPC client, which is adapted to the
//! `SorobanEventFeed` door, which drives the registry-gated
//! `SorobanEventSource` the ingestion pipeline consumes. Asserts the
//! whole chain holds its guarantees — admission by operator registry,
//! raw items positioned by their own TOID id, clean resumption with no
//! re-serves or duplicates, observable skip counts, and identities that
//! are deterministically derivable from network + position.

use std::path::{Path, PathBuf};

use safeguard_audit_core::{ContractId, EventId, EventSource, NetworkId};
use safeguard_audit_rpc::{EventsRpcFeed, MockEventsClient};
use safeguard_audit_soroban::{
    event_id, to_normalized, ContractLabel, ContractRegistry, SorobanEvent, SorobanEventSource,
    SorobanEventsResult,
};

/// The recognized hooks contract (the same id as the committed fixtures).
const HOOKS_CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("soroban")
}

fn load_page(name: &str) -> SorobanEventsResult {
    let raw = std::fs::read_to_string(fixtures_root().join(name)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn testnet() -> NetworkId {
    NetworkId::new(NetworkId::TESTNET).unwrap()
}

fn registry() -> ContractRegistry {
    let mut registry = ContractRegistry::new();
    registry.register(
        testnet(),
        ContractId::new(HOOKS_CONTRACT).unwrap(),
        ContractLabel::new("safeguard-hooks-testnet").unwrap(),
    );
    registry
}

/// Feeds both committed pages through the mock client and into a
/// registry-gated source, as a node would serve them in sequence.
fn source() -> SorobanEventSource<EventsRpcFeed<MockEventsClient>> {
    let mut all: Vec<SorobanEvent> = Vec::new();
    for name in ["hooks-transfer-page.json", "mixed-page.json"] {
        all.extend(load_page(name).events);
    }
    // The source rejects out-of-order pages; the fixture ids must
    // ascend across pages for the resumed pass to succeed.
    let ids: Vec<&str> = all.iter().map(|e| e.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "fixture ids must ascend across pages");

    let start_ledger = load_page("hooks-transfer-page.json")
        .oldest_ledger
        .map(|l| l as u32);
    let feed = EventsRpcFeed::new(MockEventsClient::new(all), start_ledger);
    SorobanEventSource::new("soroban-testnet", testnet(), registry(), feed)
}

#[test]
fn admitted_wire_events_flow_from_fixture_to_raw_items() {
    let mut source = source();

    // First page: the two recognized transfer events.
    let page1 = source.fetch_after(None, 2).unwrap();
    assert_eq!(page1.items().len(), 2);
    assert!(page1.has_more());
    assert_eq!(source.skipped(), 0);

    // Resumed pass over the mixed page: only the recognized contract's
    // event is admitted; the system and unregistered events are
    // skipped, observably.
    let page2 = source.fetch_after(page1.next_position(), 10).unwrap();
    assert_eq!(page2.items().len(), 1);
    assert!(!page2.has_more());
    assert_eq!(source.skipped(), 2);

    let mut positions: Vec<&str> = Vec::new();
    for page in [&page1, &page2] {
        for item in page.items() {
            // Each admitted event is stamped with its contract's label.
            assert_eq!(item.scheme(), "safeguard-hooks-testnet");
            // The payload round-trips onto the verified wire shape.
            let back: SorobanEvent = serde_json::from_str(item.payload()).unwrap();
            assert_eq!(back.contract_id.as_deref(), Some(HOOKS_CONTRACT));
            // The position is the event's own TOID id, never arrival
            // time — the same key the identity and checkpoint use.
            assert_eq!(item.position(), back.id.as_str());
            positions.push(item.position());
        }
    }
    assert_eq!(
        positions.len(),
        3,
        "two transfer events plus one mixed event"
    );
    positions.sort_unstable();
    positions.dedup();
    assert_eq!(positions.len(), 3, "no event is served twice");
}

#[test]
fn identities_are_stable_across_rebuilds_and_reproducible_from_positions() {
    let mut expected: Vec<(String, String)> = Vec::new();
    for _ in 0..2 {
        let mut source = source();
        let mut collected: Vec<(String, String)> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = source.fetch_after(after.as_deref(), 2).unwrap();
            for item in page.items() {
                let back: SorobanEvent = serde_json::from_str(item.payload()).unwrap();
                let id = event_id(&back, &testnet());
                // The identity is reproducible from the resume position
                // alone, so a checkpoint and the identity can never
                // disagree about what was consumed.
                let from_position = EventId::derive(&[testnet().as_str(), item.position()]);
                assert_eq!(id, from_position);
                collected.push((item.position().to_owned(), id.as_str().to_owned()));
            }
            match page.next_position() {
                Some(next) => after = Some(next.to_owned()),
                None => break,
            }
        }
        assert_eq!(collected.len(), 3);
        if expected.is_empty() {
            expected = collected;
        } else {
            assert_eq!(
                collected, expected,
                "identity must not change across stack rebuilds"
            );
        }
    }
}

#[test]
fn wire_metadata_maps_onto_normalized_references() {
    // A committed transfer event through the mapping a payload parser
    // will use: ledger order, close time, and transaction reference.
    let page = load_page("hooks-transfer-page.json");
    let event = &page.events[0];
    event.validate().unwrap();
    let parts = to_normalized(event, testnet()).unwrap();
    assert_eq!(parts.order.ledger_sequence, Some(3727845));
    assert_eq!(parts.order.event_index, Some(1));
    assert_eq!(parts.ledger.sequence(), 3727845);
    assert_eq!(
        parts.ledger.close_time().unwrap().to_rfc3339().unwrap(),
        "2026-07-21T18:01:10Z"
    );
    let tx = parts.transaction.as_ref().unwrap();
    assert_eq!(
        tx.hash().as_str(),
        "a5c9247b77eb04c0d857934a2e988c408167976c8acbdf3d8acf64c44deb3beb"
    );
}
