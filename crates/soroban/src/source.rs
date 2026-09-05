//! The ingestion door over Soroban event pages.
//!
//! [`SorobanEventSource`] implements the audit-core [`EventSource`] trait
//! so Soroban pages can feed the normalizer exactly like any other
//! source. A caller supplies a [`SorobanEventFeed`] — the narrow fetch
//! operation, backed by an RPC client in production or a synthetic list
//! in tests — and the source turns each *admitted* wire event into a
//! [`RawEventItem`] whose position is the event's own TOID `id`.
//!
//! Admission is the operator registry's decision: the source is built
//! for one network and consults its [`ContractRegistry`] for every
//! contract event. A recognized contract's event becomes a raw item
//! whose scheme label is that contract's operator-chosen label (the
//! provenance breadcrumb a parser registry can later bind); system
//! events and events from unregistered contracts are skipped — never
//! silently admitted — and the skip is counted so a caller can observe
//! and log the drop instead of assuming the page was fully consumed.
//!
//! Positions are event ids, not arrival times, and the id is the same
//! dedup key the rest of the pipeline uses. The Stellar RPC page cursor
//! equals the id of the last event on the page (as observed in the
//! getEvents documentation), so resuming after a consumed item is sound:
//! the source passes that id back to the feed as `after`, and a
//! well-behaved feed serves only what comes after it.
//!
//! Two defensive guarantees hold even against a misbehaving feed: an
//! event whose id is at or before `after` is never re-served, and events
//! on one page must be strictly increasing (by id) or the page is
//! rejected as invalid rather than silently mis-ordered.

use safeguard_audit_core::source::RawEventItem;
use safeguard_audit_core::{EventSource, NetworkId, SourceError, SourcePage, SourceResult};

use crate::registry::ContractRegistry;
use crate::wire::{is_toid_id, SorobanEventsResult};

/// The maximum page the source will ask a feed for, mirroring the RPC's
/// hardcoded getEvents limit.
pub const MAX_PAGE_LIMIT: usize = 10_000;

/// A fetch of one page of Soroban events occurring after a position.
///
/// `after` is an event id in TOID form (`<19-digit TOID>-<10-digit
/// index>`) or `None` to start from the feed's configured start ledger.
/// Implementations translate it into their cursor semantics (an RPC
/// client sends it as `pagination.cursor`); a synthetic feed treats it
/// as the id of the last event already served.
pub trait SorobanEventFeed {
    /// Fetches up to `limit` events occurring after `after`, returning
    /// the page plus the RPC retention metadata.
    fn fetch_page(
        &mut self,
        after: Option<&str>,
        limit: usize,
    ) -> SourceResult<SorobanEventsResult>;
}

/// An [`EventSource`] over a [`SorobanEventFeed`], gated by the operator
/// contract registry.
///
/// `name` is the stable source label used in checkpoints and provenance
/// (e.g. `soroban-testnet`); `network` scopes registry admission and the
/// downstream identity, since the same contract address on testnet and
/// mainnet is a different contract.
pub struct SorobanEventSource<F> {
    name: String,
    network: NetworkId,
    registry: ContractRegistry,
    feed: F,
    /// Contract and system events skipped since construction, because
    /// they came from contracts the registry does not admit (or carried
    /// no contract at all). Read this to observe silent drops; the value
    /// is cumulative so a caller can take deltas between fetches.
    skipped: u64,
}

impl<F: SorobanEventFeed> SorobanEventSource<F> {
    /// Builds a source with a stable name, the network it audits, the
    /// operator registry admitting contracts on that network, and the
    /// backing feed.
    pub fn new(
        name: impl Into<String>,
        network: NetworkId,
        registry: ContractRegistry,
        feed: F,
    ) -> Self {
        Self {
            name: name.into(),
            network,
            registry,
            feed,
            skipped: 0,
        }
    }

    /// The network this source audits (registry admission and downstream
    /// identity are scoped to it).
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Events skipped since construction: system events and events from
    /// contracts the registry does not admit. Cumulative, so take a
    /// delta across fetches to learn what one page dropped.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl<F: SorobanEventFeed> EventSource for SorobanEventSource<F> {
    type Error = SourceError;

    fn source_name(&self) -> &str {
        &self.name
    }

    fn fetch_after(&mut self, after: Option<&str>, limit: usize) -> SourceResult<SourcePage> {
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(SourceError::LimitOutOfRange(limit));
        }
        // An `after` position is always an event id of the TOID shape; a
        // resume position of any other shape is invalid, not "start over".
        if let Some(position) = after {
            if !is_toid_id(position) {
                return Err(SourceError::InvalidPosition(position.to_owned()));
            }
        }

        let page = self.feed.fetch_page(after, limit)?;

        // Turn admitted wire events into raw items whose position is the
        // event id. Everything else is counted, never served.
        let mut items = Vec::with_capacity(page.events.len());
        let mut previous: Option<&str> = None;
        let mut skipped = 0u64;
        for event in &page.events {
            // Wire-level structural coherence is checked here, at the
            // door, via the single validate() entry point: a malformed
            // event (bad TOID id, non-positive ledger, wrong topic
            // count, malformed hash) never becomes a raw item.
            event.validate().map_err(SourceError::InvalidItem)?;
            let id = event.id.as_str();
            if let Some(after) = after {
                if id <= after {
                    // The feed re-served an event at or before the resume
                    // point; never hand it downstream again.
                    continue;
                }
            }
            if let Some(previous) = previous {
                if id <= previous {
                    return Err(SourceError::InvalidItem(format!(
                        "events out of order on one page: {previous} then {id}"
                    )));
                }
            }
            previous = Some(id);

            // Admission: only contract events from registered contracts
            // enter the pipeline. An event with no contract id (system
            // emissions, or a contract event the node did not name) and
            // an event from an unregistered contract are both skipped —
            // observably, not silently.
            let Some(contract) = event.contract_id.as_deref() else {
                skipped += 1;
                continue;
            };
            let Some(label) = self.registry.label(&self.network, contract) else {
                skipped += 1;
                continue;
            };
            let payload = serde_json::to_string(event).map_err(|e| {
                SourceError::InvalidItem(format!("event {id} does not serialize: {e}"))
            })?;
            items.push(RawEventItem::new(label.as_str(), payload, id)?);
        }
        self.skipped += skipped;

        Ok(SourcePage::new(items, page.cursor.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ContractLabel;
    use crate::wire::{SorobanEvent, SorobanEventType};
    use safeguard_audit_core::ContractId;

    /// The emitting contract used by the synthetic events below, from the
    /// Stellar documentation's own getEvents example.
    const CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    const OTHER_CONTRACT: &str = "CA3V4K3H5YQZ4P7VJ6U4VZC2TG7LB5WJH4Y2UQ5W2GQ4R2XU5V3T2HG";

    fn contract(value: &str) -> ContractId {
        ContractId::new(value).unwrap()
    }

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn registry() -> ContractRegistry {
        let mut registry = ContractRegistry::new();
        registry.register(
            testnet(),
            contract(CONTRACT),
            ContractLabel::new("safeguard-hooks-testnet").unwrap(),
        );
        registry
    }

    /// A synthetic feed over a fixed list of events. Test-only: it is
    /// not an RPC client and must never be treated as one.
    struct VecFeed {
        events: Vec<SorobanEvent>,
        /// Whether the feed misbehaves by re-serving events at or before
        /// the resume point.
        sloppy: bool,
    }

    impl SorobanEventFeed for VecFeed {
        fn fetch_page(
            &mut self,
            after: Option<&str>,
            limit: usize,
        ) -> SourceResult<SorobanEventsResult> {
            if limit == 0 || limit > MAX_PAGE_LIMIT {
                return Err(SourceError::LimitOutOfRange(limit));
            }
            let start = match after {
                None => 0,
                Some(position) => {
                    let idx = self
                        .events
                        .iter()
                        .position(|e| e.id == position)
                        .ok_or_else(|| SourceError::InvalidPosition(position.to_owned()))?
                        + 1;
                    // A sloppy feed includes the resume point itself.
                    if self.sloppy {
                        idx - 1
                    } else {
                        idx
                    }
                }
            };
            let end = (start + limit).min(self.events.len());
            let events = self.events[start..end].to_vec();
            let cursor = if end < self.events.len() {
                Some(self.events[end - 1].id.clone())
            } else {
                None
            };
            Ok(SorobanEventsResult {
                events,
                cursor,
                latest_ledger: Some(421),
                oldest_ledger: Some(100),
                latest_ledger_close_time: None,
                oldest_ledger_close_time: None,
            })
        }
    }

    fn toid(index: u32) -> String {
        format!("0016010972359577600-{index:010}")
    }

    fn event(index: u32) -> SorobanEvent {
        SorobanEvent {
            event_type: SorobanEventType::Contract,
            ledger: 421,
            ledger_closed_at: None,
            contract_id: Some(CONTRACT.to_owned()),
            id: toid(index),
            transaction_index: Some(0),
            operation_index: Some(0),
            in_successful_contract_call: Some(true),
            topic: vec!["AAAADwAAAAh0cmFuc2Zlcg==".into()],
            value: None,
            tx_hash: None,
        }
    }

    fn source(feed: VecFeed) -> SorobanEventSource<VecFeed> {
        SorobanEventSource::new("soroban-testnet", testnet(), registry(), feed)
    }

    #[test]
    fn sources_page_and_resume_without_gaps_or_duplicates() {
        let mut source = source(VecFeed {
            events: vec![event(1), event(2), event(3), event(4)],
            sloppy: false,
        });
        assert_eq!(source.source_name(), "soroban-testnet");
        assert_eq!(source.network(), &testnet());
        assert_eq!(source.skipped(), 0);

        let page1 = source.fetch_after(None, 2).unwrap();
        assert_eq!(page1.items().len(), 2);
        assert!(page1.has_more());
        assert_eq!(page1.items()[0].position(), toid(1));
        assert_eq!(page1.next_position(), Some(toid(2).as_str()));

        let page2 = source.fetch_after(page1.next_position(), 2).unwrap();
        assert_eq!(page2.items().len(), 2);
        assert!(!page2.has_more());
        let ids: Vec<&str> = page2.items().iter().map(|i| i.position()).collect();
        assert_eq!(ids, vec![toid(3), toid(4)]);
        assert_eq!(source.skipped(), 0);
    }

    #[test]
    fn raw_items_carry_the_contract_label_as_scheme() {
        let mut source = source(VecFeed {
            events: vec![event(1)],
            sloppy: false,
        });
        let page = source.fetch_after(None, 10).unwrap();
        let item = &page.items()[0];
        // The operator-chosen label is the item's scheme: the provenance
        // breadcrumb a parser registry can later bind to a real parser.
        assert_eq!(item.scheme(), "safeguard-hooks-testnet");
        let back: SorobanEvent = serde_json::from_str(item.payload()).unwrap();
        assert_eq!(back.id, toid(1));
        assert_eq!(back.contract_id.as_deref(), Some(CONTRACT));
    }

    #[test]
    fn sloppy_feeds_never_re_serve_consumed_events() {
        // Even a feed that re-includes the resume point cannot make the
        // source duplicate an already-consumed event.
        let mut source = source(VecFeed {
            events: vec![event(1), event(2), event(3)],
            sloppy: true,
        });
        let page1 = source.fetch_after(None, 1).unwrap();
        assert_eq!(page1.items()[0].position(), toid(1));
        let page2 = source.fetch_after(page1.next_position(), 10).unwrap();
        let ids: Vec<&str> = page2.items().iter().map(|i| i.position()).collect();
        assert_eq!(ids, vec![toid(2), toid(3)]);
    }

    #[test]
    fn unregistered_contracts_and_system_events_are_skipped_and_counted() {
        let mut unknown = event(1);
        unknown.contract_id = Some(OTHER_CONTRACT.to_owned());
        let mut system = event(2);
        system.event_type = SorobanEventType::System;
        system.contract_id = None;
        let mut source = source(VecFeed {
            events: vec![unknown, system, event(3)],
            sloppy: false,
        });

        let page = source.fetch_after(None, 10).unwrap();
        // Only the registered contract's event becomes an item.
        let ids: Vec<&str> = page.items().iter().map(|i| i.position()).collect();
        assert_eq!(ids, vec![toid(3)]);
        // The two skipped events are observable, never silent.
        assert_eq!(source.skipped(), 2);
    }

    #[test]
    fn an_empty_registry_admits_nothing_but_never_errors() {
        let mut source = SorobanEventSource::new(
            "soroban-testnet",
            testnet(),
            ContractRegistry::new(),
            VecFeed {
                events: vec![event(1), event(2)],
                sloppy: false,
            },
        );
        let page = source.fetch_after(None, 10).unwrap();
        assert!(page.items().is_empty());
        assert_eq!(source.skipped(), 2);
    }

    #[test]
    fn skipped_counts_accumulate_across_fetches() {
        let mut other = event(1);
        other.contract_id = Some(OTHER_CONTRACT.to_owned());
        let mut source = source(VecFeed {
            events: vec![other, event(2), event(3), event(4)],
            sloppy: false,
        });
        let page1 = source.fetch_after(None, 2).unwrap();
        // Page 1: event(1) skipped, event(2) admitted.
        assert_eq!(page1.items().len(), 1);
        assert_eq!(source.skipped(), 1);
        let page2 = source.fetch_after(page1.next_position(), 10).unwrap();
        assert_eq!(page2.items().len(), 2);
        assert_eq!(source.skipped(), 1);
    }

    #[test]
    fn limits_are_bounded_and_unknown_positions_error_cleanly() {
        let mut source = source(VecFeed {
            events: vec![event(1)],
            sloppy: false,
        });
        assert!(matches!(
            source.fetch_after(None, 0),
            Err(SourceError::LimitOutOfRange(_))
        ));
        assert!(matches!(
            source.fetch_after(None, MAX_PAGE_LIMIT + 1),
            Err(SourceError::LimitOutOfRange(_))
        ));
        assert!(matches!(
            source.fetch_after(Some("not-an-id"), 5),
            Err(SourceError::InvalidPosition(_))
        ));
        assert!(matches!(
            source.fetch_after(Some(&toid(99)), 5),
            Err(SourceError::InvalidPosition(_))
        ));
    }

    #[test]
    fn malformed_event_ids_are_rejected_as_invalid_items() {
        let mut bad = event(1);
        bad.id = "not-a-toid".into();
        let mut source = source(VecFeed {
            events: vec![bad],
            sloppy: false,
        });
        assert!(matches!(
            source.fetch_after(None, 5),
            Err(SourceError::InvalidItem(_))
        ));
    }

    #[test]
    fn out_of_order_pages_are_rejected() {
        let mut source = source(VecFeed {
            events: vec![event(3), event(2)],
            sloppy: false,
        });
        assert!(matches!(
            source.fetch_after(None, 5),
            Err(SourceError::InvalidItem(_))
        ));
    }
}
