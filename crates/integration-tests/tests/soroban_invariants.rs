//! Cross-cutting invariants of the Soroban adapter stack.
//!
//! These properties span the mock RPC client, the feed door, and the
//! registry-gated source, so no single crate test owns them:
//!
//! * **Served-set invariance under page size.** Whatever page size the
//!   indexer asks for, the union of admitted events served across a
//!   drain is identical: same events, same order, no duplicates. Page
//!   boundaries may fall anywhere — including inside a run of skipped
//!   events — without changing what eventually gets ingested.
//! * **Skipping never corrupts the resume stream.** A page that admits
//!   nothing must still advance the cursor (or a run of unregistered
//!   events would wedge the indexer forever), and events after the run
//!   must still be served exactly once.
//! * **Byte determinism.** Two independent drains of the same feed and
//!   registry yield byte-identical raw payloads, so the checkpointed
//!   history is reproducible bit-for-bit.

use safeguard_audit_core::{ContractId, EventSource, NetworkId};
use safeguard_audit_rpc::{EventsRpcFeed, MockEventsClient};
use safeguard_audit_soroban::{
    ContractLabel, ContractRegistry, SorobanEvent, SorobanEventSource, SorobanEventType,
};

const REGISTERED: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const UNREGISTERED: &str = "CA3V4K3H5YQZ4P7VJ6U4VZC2TG7LB5WJH4Y2UQ5W2GQ4R2XU5V3T2HG";

/// A TOID id for ledger `n` above the fixture base.
fn toid(n: u32) -> String {
    format!(
        "{:019}-{n:010}",
        1_601_097_235_957_760_000u64 + u64::from(n)
    )
}

/// Whether one feed event is admitted (a registered contract), skipped
/// as a system emission, or skipped as unregistered.
#[derive(Clone, Copy)]
enum Kind {
    Reg,
    System,
    Unreg,
}

/// Builds a deterministic feed of `kinds` on ascending ledgers, each
/// event's id derived from its index.
fn feed_from(kinds: &[Kind]) -> Vec<SorobanEvent> {
    kinds
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            let (event_type, contract) = match kind {
                Kind::Reg => (SorobanEventType::Contract, Some(REGISTERED)),
                Kind::System => (SorobanEventType::System, None),
                Kind::Unreg => (SorobanEventType::Contract, Some(UNREGISTERED)),
            };
            SorobanEvent {
                event_type,
                ledger: 420 + i as i64,
                ledger_closed_at: None,
                contract_id: contract.map(str::to_owned),
                id: toid(i as u32),
                transaction_index: Some(0),
                operation_index: Some(0),
                in_successful_contract_call: Some(true),
                topic: vec!["AAAADwAAAAh0cmFuc2Zlcg==".into()],
                value: None,
                tx_hash: None,
            }
        })
        .collect()
}

/// The alternating fixture used by the page-size invariance test: every
/// `i % 4 == 1` event is a system emission and every `i % 4 == 2` event
/// comes from an unregistered contract, so skippable events sit between
/// admitted ones.
fn alternating_feed(count: u32) -> Vec<SorobanEvent> {
    let kinds: Vec<Kind> = (0..count)
        .map(|i| match i % 4 {
            1 => Kind::System,
            2 => Kind::Unreg,
            _ => Kind::Reg,
        })
        .collect();
    feed_from(&kinds)
}

/// A feed with a long consecutive run of unregistered events, so a page
/// can land entirely inside the run.
fn run_feed() -> Vec<SorobanEvent> {
    let mut kinds = vec![Kind::Reg; 3];
    kinds.extend(vec![Kind::Unreg; 8]); // indices 3..=10
    kinds.extend(vec![Kind::Reg; 2]);
    feed_from(&kinds)
}

fn testnet() -> NetworkId {
    NetworkId::new(NetworkId::TESTNET).unwrap()
}

fn registry() -> ContractRegistry {
    let mut registry = ContractRegistry::new();
    registry.register(
        testnet(),
        ContractId::new(REGISTERED).unwrap(),
        ContractLabel::new("safeguard-hooks-testnet").unwrap(),
    );
    registry
}

fn source(events: Vec<SorobanEvent>) -> SorobanEventSource<EventsRpcFeed<MockEventsClient>> {
    let feed = EventsRpcFeed::new(MockEventsClient::new(events), Some(420));
    SorobanEventSource::new("soroban-testnet", testnet(), registry(), feed)
}

/// Drains `source` with the given page size, returning the served
/// positions in order plus the final skip count.
fn drain(
    source: &mut SorobanEventSource<EventsRpcFeed<MockEventsClient>>,
    page_size: usize,
) -> (Vec<String>, u64) {
    let mut served = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = source.fetch_after(after.as_deref(), page_size).unwrap();
        for item in page.items() {
            served.push(item.position().to_owned());
        }
        match page.next_position() {
            Some(next) => after = Some(next.to_owned()),
            None => break,
        }
    }
    (served, source.skipped())
}

#[test]
fn the_served_set_is_invariant_under_page_size() {
    // 13 events: admitted at indices {0,3,4,7,8,11,12}, skipped at the
    // system ({1,5,9}) and unregistered ({2,6,10}) indices.
    let admitted = [0u32, 3, 4, 7, 8, 11, 12];
    let expected: Vec<String> = admitted.iter().map(|&i| toid(i)).collect();

    let mut reference: Option<Vec<String>> = None;
    for page_size in [1usize, 2, 3, 5, 7, 100] {
        let mut source = source(alternating_feed(13));
        let (served, skipped) = drain(&mut source, page_size);
        // Same events, same order, no matter where the boundaries fall.
        assert_eq!(served, expected, "page size {page_size} altered the set");
        assert_eq!(skipped, 6, "page size {page_size} altered the skip count");
        assert_eq!(served.len(), admitted.len());
        served
            .windows(2)
            .for_each(|w| assert!(w[0] < w[1], "served order must ascend"));
        match &reference {
            None => reference = Some(served),
            Some(previous) => assert_eq!(*previous, served),
        }
    }
}

#[test]
fn a_fully_skipped_page_advances_and_loses_nothing() {
    // The long unregistered run at indices 3..=10 guarantees several
    // whole pages land inside it and admit nothing.
    let mut source = source(run_feed());
    let mut pages = 0usize;
    let mut empty_advancing_pages = 0usize;
    let mut served = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = source.fetch_after(after.as_deref(), 2).unwrap();
        pages += 1;
        if page.items().is_empty() && page.has_more() {
            // A page that admits nothing must still advance, never wedge.
            empty_advancing_pages += 1;
            assert!(
                page.next_position().is_some(),
                "an empty page that has more must carry a resume position"
            );
        }
        for item in page.items() {
            served.push(item.position().to_owned());
        }
        match page.next_position() {
            Some(next) => after = Some(next.to_owned()),
            None => break,
        }
    }
    assert!(
        empty_advancing_pages >= 3,
        "the fixture must exercise several empty pages, got {empty_advancing_pages}"
    );
    // Admitted events are indices 0..=2 and 11..=12 only.
    let expected: Vec<String> = [0u32, 1, 2, 11, 12].iter().map(|&i| toid(i)).collect();
    assert_eq!(
        served, expected,
        "events after a skipped run must not be lost"
    );
    assert_eq!(source.skipped(), 8);
    assert!(pages >= 7);
}

#[test]
fn drains_are_byte_deterministic() {
    // Two independent drains over the same feed and registry must yield
    // byte-identical payloads: reproducibility for the whole adapter.
    let mut payloads: Vec<String> = Vec::new();
    for _ in 0..2 {
        let mut source = source(alternating_feed(13));
        let mut collected = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = source.fetch_after(after.as_deref(), 3).unwrap();
            for item in page.items() {
                collected.push(item.payload().to_owned());
            }
            match page.next_position() {
                Some(next) => after = Some(next.to_owned()),
                None => break,
            }
        }
        if payloads.is_empty() {
            payloads = collected;
        } else {
            assert_eq!(payloads, collected, "drains must be byte-identical");
        }
    }
}
