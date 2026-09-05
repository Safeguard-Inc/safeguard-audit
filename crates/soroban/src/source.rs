//! The ingestion door over Soroban event pages.
//!
//! [`SorobanEventSource`] implements the audit-core [`EventSource`] trait
//! so Soroban pages can feed the normalizer exactly like any other
//! source. A caller supplies a [`SorobanEventFeed`] — the narrow fetch
//! operation, backed by an RPC client in production or a synthetic list
//! in tests — and the source turns each wire event into a
//! [`RawEventItem`] whose *position is the event's own TOID `id`*.
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
use safeguard_audit_core::{EventSource, SourceError, SourcePage, SourceResult};

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

/// An [`EventSource`] over a [`SorobanEventFeed`].
///
/// `name` is the stable source label used in checkpoints and provenance
/// (e.g. `soroban-testnet`); `scheme` labels the payloads so the
/// normalizer can pick a parser once that parser exists.
pub struct SorobanEventSource<F> {
    name: String,
    scheme: String,
    feed: F,
}

impl<F: SorobanEventFeed> SorobanEventSource<F> {
    /// Builds a source with a stable name, a payload scheme label, and
    /// the backing feed.
    pub fn new(name: impl Into<String>, scheme: impl Into<String>, feed: F) -> Self {
        Self {
            name: name.into(),
            scheme: scheme.into(),
            feed,
        }
    }

    /// The scheme label stamped on every raw item this source yields.
    pub fn scheme(&self) -> &str {
        &self.scheme
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

        // Turn wire events into raw items whose position is the event id,
        // refusing anything at or before the resume point and anything
        // that would break the strict ordering of the page.
        let mut items = Vec::with_capacity(page.events.len());
        let mut previous: Option<&str> = None;
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
            let payload = serde_json::to_string(event).map_err(|e| {
                SourceError::InvalidItem(format!("event {id} does not serialize: {e}"))
            })?;
            items.push(RawEventItem::new(&self.scheme, payload, id)?);
        }

        Ok(SourcePage::new(items, page.cursor.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{SorobanEvent, SorobanEventType};

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

    fn source(feed: VecFeed) -> SorobanEventSource<VecFeed> {
        SorobanEventSource::new("soroban-testnet", "soroban-event", feed)
    }

    #[test]
    fn sources_page_and_resume_without_gaps_or_duplicates() {
        let mut source = source(VecFeed {
            events: vec![event(1), event(2), event(3), event(4)],
            sloppy: false,
        });
        assert_eq!(source.source_name(), "soroban-testnet");
        assert_eq!(source.scheme(), "soroban-event");

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
    }

    #[test]
    fn raw_items_carry_the_scheme_and_a_round_trippable_payload() {
        let mut source = source(VecFeed {
            events: vec![event(1)],
            sloppy: false,
        });
        let page = source.fetch_after(None, 10).unwrap();
        let item = &page.items()[0];
        assert_eq!(item.scheme(), "soroban-event");
        let back: SorobanEvent = serde_json::from_str(item.payload()).unwrap();
        assert_eq!(back.id, toid(1));
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
