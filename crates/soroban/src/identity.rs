//! Deterministic event identity for Soroban wire events.
//!
//! A normalized event's [`EventId`] must derive from stable *source*
//! identity, never from arrival time. The TOID `id` on the Soroban wire
//! is exactly that: it encodes the event's ledger position, transaction
//! index, and event index in one opaque string, unique per network.
//! [`event_id`] therefore derives the identity from network + id.
//!
//! Two properties follow from that choice:
//!
//! * **Kind-independent.** The identity is the *source event's*, so
//!   re-normalizing the same event under a newer parser (which might
//!   classify it differently) still yields the same id, and the
//!   ingestion dedup keeps working across parser versions.
//! * **Lossless resume.** The source positions its raw items by the same
//!   id, so a replay that has only `network` and the resume position can
//!   re-derive the identical event id — the checkpoint and the identity
//!   can never disagree about what was already consumed.

use safeguard_audit_core::{EventId, NetworkId};

use crate::wire::SorobanEvent;

/// The normalized event id for `event` on `network`.
///
/// Deterministic and stable: the same wire event always derives the same
/// id, on every machine and across parser versions.
pub fn event_id(event: &SorobanEvent, network: &NetworkId) -> EventId {
    EventId::derive(&[network.as_str(), event.id.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::SorobanEventType;

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn mainnet() -> NetworkId {
        NetworkId::new(NetworkId::MAINNET).unwrap()
    }

    fn toid(index: u32) -> String {
        format!("0016010972359577600-{index:010}")
    }

    fn event(index: u32) -> SorobanEvent {
        SorobanEvent {
            event_type: SorobanEventType::Contract,
            ledger: 421,
            ledger_closed_at: None,
            contract_id: None,
            id: toid(index),
            transaction_index: Some(0),
            operation_index: Some(0),
            in_successful_contract_call: Some(true),
            topic: vec!["AAAADwAAAAh0cmFuc2Zlcg==".into()],
            value: None,
            tx_hash: None,
        }
    }

    #[test]
    fn identity_is_deterministic_and_arrival_time_independent() {
        let first = event_id(&event(7), &testnet());
        let second = event_id(&event(7), &testnet());
        assert_eq!(first, second);
        assert_ne!(first, event_id(&event(8), &testnet()));
        // The id has the normalized shape and prefix.
        assert!(first.as_str().starts_with("evt_"));
        assert_eq!(first.as_str().len(), "evt_".len() + 32);
    }

    #[test]
    fn identity_is_scoped_to_the_network() {
        // The same TOID on two networks is two different source events
        // and must never share an id.
        let on_testnet = event_id(&event(1), &testnet());
        let on_mainnet = event_id(&event(1), &mainnet());
        assert_ne!(on_testnet, on_mainnet);
    }

    #[test]
    fn identity_is_losslessly_reproducible_from_the_resume_position() {
        // The source positions raw items by the event id; a replay that
        // has only network + position re-derives the identical id.
        let e = event(3);
        let position = e.id.as_str();
        let from_event = event_id(&e, &testnet());
        let from_position = EventId::derive(&[testnet().as_str(), position]);
        assert_eq!(from_event, from_position);
    }
}
