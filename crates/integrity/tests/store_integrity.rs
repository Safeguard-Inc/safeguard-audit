//! Integrity across a real store boundary.
//!
//! Unit tests prove the primitives; these prove the *flow* an operator
//! cares about: seal records, persist them through an EventStore, read
//! them back in history order, and verify. Because the store is
//! append-only, tampering is exercised at the serialization boundary the
//! way it would reach a disk-backed database - bytes edited between
//! persistence and read-back - plus the deletions a real attacker or
//! corruption could cause.

use safeguard_audit_core::{
    AuditEvent, AuditRecord, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind,
    PageRequest, Timestamp, VersionLabel,
};
use safeguard_audit_integrity::{
    build_manifest, verify_chain, verify_manifest_records, ManifestOptions,
};
use safeguard_audit_integrity::{locate_tampering, seal_chain, verify_manifest_aggregate};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_storage::{AuditQuery, EventStore};
fn event(seed: &str, kind: EventKind, ledger: i64) -> AuditEvent {
    let network = NetworkId::new(NetworkId::TESTNET).unwrap();
    let provenance =
        EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap()).unwrap();
    let mut event = AuditEvent::new(
        safeguard_audit_core::EventId::derive(&["testnet", seed]),
        kind,
        network,
        provenance,
    );
    // Real indexer output carries on-chain placement, which is what the
    // store's position key orders history by.
    event.order.ledger_sequence = Some(ledger);
    event.order.operation_index = Some(0);
    event.order.event_index = Some(0);
    event
}

fn record(seed: &str, kind: EventKind, ledger: i64) -> AuditRecord {
    AuditRecord::from_event(
        event(seed, kind, ledger),
        &FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000)),
    )
    .unwrap()
}

fn fetch_all(store: &MemoryEventStore) -> Vec<AuditRecord> {
    store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(1000).unwrap(),
        )
        .unwrap()
        .items()
        .to_vec()
}

#[test]
fn sealed_history_survives_store_round_trip_and_verifies() {
    let history = vec![
        record("tx-1", EventKind::AccountFrozen, 415),
        record("tx-2", EventKind::TokenBound, 419),
        record("tx-3", EventKind::ConfigurationChanged, 423),
    ];
    let sealed = seal_chain(&history).unwrap();

    let mut store = MemoryEventStore::new();
    for rec in &sealed {
        store.insert(rec.clone()).unwrap();
    }
    assert_eq!(store.len(), 3);

    // Read back in history order and verify as a chain.
    let read_back = fetch_all(&store);
    assert!(verify_chain(&read_back).is_ok());
    assert!(locate_tampering(&read_back).unwrap().is_empty());
}

#[test]
fn tampering_between_persistence_and_read_back_is_detected() {
    let sealed = seal_chain(&[
        record("tx-1", EventKind::AccountFrozen, 415),
        record("tx-2", EventKind::TokenBound, 419),
    ])
    .unwrap();

    let mut store = MemoryEventStore::new();
    for rec in &sealed {
        store.insert(rec.clone()).unwrap();
    }

    // Simulate a disk-level edit: serialize a stored record, alter a body
    // field through the JSON layer, and read the tampered bytes back as if
    // from a corrupted database.
    let stored = fetch_all(&store);
    let json = serde_json::to_string(&stored[1]).unwrap();
    let tampered_json = json.replacen(
        &Timestamp::from_unix_seconds(1_700_000_000)
            .as_unix_seconds()
            .to_string(),
        "1700000123",
        1,
    );
    let mut read_back = fetch_all(&store);
    read_back[1] = serde_json::from_str(&tampered_json).unwrap();

    let failures = locate_tampering(&read_back).unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].status().as_str(), "digest-mismatch");
    assert_eq!(failures[0].record_id(), &read_back[1].record_id);
}

#[test]
fn a_deleted_middle_record_breaks_the_chain_on_read_back() {
    let sealed = seal_chain(&[
        record("tx-1", EventKind::AccountFrozen, 415),
        record("tx-2", EventKind::TokenBound, 419),
        record("tx-3", EventKind::ConfigurationChanged, 423),
    ])
    .unwrap();
    let mut store = MemoryEventStore::new();
    for rec in &sealed {
        store.insert(rec.clone()).unwrap();
    }

    // Corruption loses the middle record.
    let mut read_back = fetch_all(&store);
    read_back.remove(1);
    assert!(verify_chain(&read_back).is_err());
    let failures = locate_tampering(&read_back).unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].status().as_str(), "broken-chain");
}

#[test]
fn manifest_over_store_history_verifies_and_detects_export_tampering() {
    let sealed = seal_chain(&[
        record("tx-1", EventKind::AccountFrozen, 415),
        record("tx-2", EventKind::TokenBound, 419),
    ])
    .unwrap();
    let mut store = MemoryEventStore::new();
    for rec in &sealed {
        store.insert(rec.clone()).unwrap();
    }
    let read_back = fetch_all(&store);

    // Build the export manifest over the store's own read-back records.
    let manifest = build_manifest(
        &read_back,
        &ManifestOptions::new(Some(100), Some(101), "0.1.0").unwrap(),
        Timestamp::from_unix_seconds(1_700_000_100),
    )
    .unwrap();
    assert!(verify_manifest_records(&manifest, &read_back)
        .unwrap()
        .iter()
        .all(|o| o.status().is_verified()));
    assert_eq!(
        verify_manifest_aggregate(&manifest).unwrap().as_str(),
        "verified"
    );

    // The exported records themselves are tamper-evident: alter the JSON
    // of the export and the manifest catches it on import verification.
    let export_json = serde_json::to_string(&read_back).unwrap();
    let tampered_export: Vec<AuditRecord> =
        serde_json::from_str(&export_json.replacen("\"token-bound\"", "\"token-unbound\"", 1))
            .unwrap();
    let failures = verify_manifest_records(&manifest, &tampered_export).unwrap();
    assert!(failures.iter().any(|o| !o.status().is_verified()));
    assert_eq!(
        failures
            .iter()
            .filter(|o| !o.status().is_verified())
            .count(),
        1
    );
}
