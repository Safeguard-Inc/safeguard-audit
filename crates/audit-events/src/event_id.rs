//! Deterministic identity for source events.
//!
//! Duplicate ingestion must not create duplicate audit records, and replay
//! must reproduce the same records. Both properties rest on one rule:
//!
//! > An event's identity derives from **stable source identifiers**, never
//! > from arrival time.
//!
//! The identity parts follow the on-chain hierarchy where available —
//! network, contract/token, transaction hash, operation index, event index,
//! and a kind/discriminator label — so the same underlying event always
//! derives the same [`EventId`], regardless of when or how many times the
//! indexer observes it.
//!
//! If a source cannot supply ordering identity (no transaction, no index),
//! callers must supply an explicit discriminator that is stable for the
//! source position (e.g. a ledger sequence plus event position); deriving
//! identity from anything arrival-time-like is rejected by construction —
//! there is no clock anywhere in this module.

use safeguard_audit_core::{EventId, EventKind};

/// Derives the deterministic event id for a source event.
///
/// `parts` are the stable textual identity components in dependency order;
/// the first is always the network. This function only canonicalizes and
/// hashes them — it cannot invent identity when the caller has none.
pub fn derive_event_id(parts: &[&str]) -> EventId {
    EventId::derive(parts)
}

/// A convenience builder for the common on-chain identity shape: network,
/// transaction hash, operation index, event index, and a stable label
/// (kind or topic) that disambiguates multiple events from one operation.
///
/// Returns an error if no ordering identity is available at all (no
/// transaction/ledger position), since arrival-time identity is forbidden.
pub fn onchain_event_id(
    network: &str,
    tx_hash: Option<&str>,
    op_index: Option<u32>,
    event_index: Option<u32>,
    kind: EventKind,
) -> Result<EventId, crate::EventError> {
    let mut parts: Vec<String> = vec![network.to_owned()];
    match tx_hash {
        Some(tx) => parts.push(tx.to_owned()),
        None => {
            return Err(crate::EventError::NotDerivable(
                "an on-chain event identity requires a transaction hash".into(),
            ));
        }
    }
    if let Some(op) = op_index {
        parts.push(format!("op:{op}"));
    }
    if let Some(idx) = event_index {
        parts.push(format!("ev:{idx}"));
    }
    parts.push(kind.as_str().to_owned());
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    Ok(derive_event_id(&refs))
}

/// Derives identity for a *derived* (off-chain reconstructed) event.
///
/// Derived events describe activity that left no emittable event (denied
/// transfers, policy changes observed by an indexer). Their identity must
/// still be stable: it combines the network, the derivation method label,
/// and the stable source references the event was derived from. Running the
/// same derivation twice over the same source material yields the same id,
/// which keeps duplicate *derivations* idempotent too.
pub fn derived_event_id(network: &str, method: &str, source_refs: &[&str]) -> EventId {
    let mut parts = vec![network.to_owned(), format!("derived:{method}")];
    parts.extend(source_refs.iter().map(|s| (*s).to_owned()));
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    derive_event_id(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_source_parts_always_derive_the_same_id() {
        let a = onchain_event_id(
            "testnet",
            Some("tx-abc"),
            Some(1),
            Some(2),
            EventKind::AccountFrozen,
        )
        .unwrap();
        let b = onchain_event_id(
            "testnet",
            Some("tx-abc"),
            Some(1),
            Some(2),
            EventKind::AccountFrozen,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn identity_is_sensitive_to_every_part() {
        let base = |tx: &str, op: Option<u32>, idx: Option<u32>, kind: EventKind| {
            onchain_event_id("testnet", Some(tx), op, idx, kind).unwrap()
        };
        assert_ne!(
            base("tx-a", Some(1), Some(2), EventKind::AccountFrozen),
            base("tx-b", Some(1), Some(2), EventKind::AccountFrozen)
        );
        assert_ne!(
            base("tx-a", Some(1), Some(2), EventKind::AccountFrozen),
            base("tx-a", Some(2), Some(2), EventKind::AccountFrozen)
        );
        assert_ne!(
            base("tx-a", Some(1), Some(2), EventKind::AccountFrozen),
            base("tx-a", Some(1), Some(3), EventKind::AccountFrozen)
        );
        assert_ne!(
            base("tx-a", Some(1), Some(2), EventKind::AccountFrozen),
            base("tx-a", Some(1), Some(2), EventKind::AccountUnfrozen)
        );
    }

    #[test]
    fn onchain_identity_requires_a_transaction() {
        assert!(
            onchain_event_id("testnet", None, Some(0), Some(0), EventKind::AccountFrozen).is_err()
        );
    }

    #[test]
    fn arrival_time_cannot_enter_identity() {
        // Two ingestions at different wall-clock instants derive the same id.
        let a = derived_event_id("testnet", "failed-tx-analysis", &["tx-hash-1", "op:0"]);
        let b = derived_event_id("testnet", "failed-tx-analysis", &["tx-hash-1", "op:0"]);
        assert_eq!(a, b);
    }

    #[test]
    fn derived_identity_varies_with_method_and_source() {
        assert_ne!(
            derived_event_id("testnet", "method-a", &["tx-1"]),
            derived_event_id("testnet", "method-b", &["tx-1"])
        );
        assert_ne!(
            derived_event_id("testnet", "method-a", &["tx-1"]),
            derived_event_id("testnet", "method-a", &["tx-2"])
        );
    }

    #[test]
    fn onchain_and_derived_ids_never_collide_for_the_same_parts() {
        let onchain = onchain_event_id(
            "testnet",
            Some("tx-1"),
            Some(0),
            Some(0),
            EventKind::AccountFrozen,
        )
        .unwrap();
        let derived = derived_event_id(
            "testnet",
            "failed-tx-analysis",
            &["tx-1", "op:0", "account-frozen"],
        );
        assert_ne!(onchain, derived);
    }
}
