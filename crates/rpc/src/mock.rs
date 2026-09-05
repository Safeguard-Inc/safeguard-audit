//! A recorded-event mock and the bridge into the ingestion door.
//!
//! # MockEventsClient
//!
//! An [`EventsRpc`] implementation that serves a recorded list of
//! [`SorobanEvent`]s with real getEvents paging semantics (resume from
//! the opaque cursor, honor the page limit), plus an optional
//! transient-failure mode for exercising the retry policy.
//!
//! > **This implementation is for testing/development and must not be
//! > treated as a security boundary.** It performs no network I/O,
//! > serves only what it was constructed with, and is not an RPC node.
//!
//! # EventsRpcFeed
//!
//! The bridge an operator actually wires up: any [`EventsRpc`] client
//! (the mock, or a real HTTP transport implementing the contract) is
//! adapted to the [`SorobanEventFeed`] door that
//! [`SorobanEventSource`] consumes. The bridge translates the source's
//! resume position into the RPC's cursor semantics exactly as the
//! documentation prescribes: a fresh pass sends the configured
//! `startLedger`, a resumed pass sends only the cursor (never the
//! ledger bounds).

use safeguard_audit_core::{SourceError, SourceResult};
use safeguard_audit_soroban::{SorobanEvent, SorobanEventFeed, SorobanEventsResult};

use crate::errors::RpcError;
use crate::events::{GetEventsParams, MAX_LIMIT};
use crate::EventsRpc;

/// A mock `getEvents` client over a recorded event list.
///
/// Test-only. Paging is real (cursor resumes, limits are honored) so
/// ingestion behavior is exercised faithfully; the transport-failure
/// counter lets retry tests inject transient errors on demand.
pub struct MockEventsClient {
    events: Vec<SorobanEvent>,
    /// Page size when the request carries no explicit limit.
    default_limit: usize,
    /// How many further calls fail with a transport error.
    transport_failures_remaining: u32,
}

impl MockEventsClient {
    /// A mock over `events` with the node's default page size of 100.
    pub fn new(events: Vec<SorobanEvent>) -> Self {
        Self {
            events,
            default_limit: 100,
            transport_failures_remaining: 0,
        }
    }

    /// Makes the next `count` calls fail as transport errors (to
    /// exercise retry policies).
    pub fn fail_next(&mut self, count: u32) -> &mut Self {
        self.transport_failures_remaining = count;
        self
    }
}

impl EventsRpc for MockEventsClient {
    fn get_events(&mut self, params: &GetEventsParams) -> crate::RpcResult<SorobanEventsResult> {
        if self.transport_failures_remaining > 0 {
            self.transport_failures_remaining -= 1;
            return Err(RpcError::Transport("mock node unreachable".into()));
        }
        params.validate()?;

        // Resume after the cursor (the id of the last event served on
        // the previous page), or start at the beginning.
        let start = match params.cursor_value() {
            Some(cursor) => {
                let at = self
                    .events
                    .iter()
                    .position(|e| e.id == cursor)
                    .ok_or_else(|| RpcError::InvalidRequest(format!("unknown cursor {cursor}")))?;
                at + 1
            }
            None => 0,
        };
        let limit = params
            .limit_value()
            .map(|l| l as usize)
            .unwrap_or(self.default_limit);
        let end = (start + limit).min(self.events.len());
        let served = self.events[start..end].to_vec();
        let cursor = if end < self.events.len() {
            served.last().map(|e| e.id.clone())
        } else {
            None
        };
        Ok(SorobanEventsResult {
            events: served,
            cursor,
            latest_ledger: None,
            oldest_ledger: None,
            latest_ledger_close_time: None,
            oldest_ledger_close_time: None,
        })
    }
}

/// Adapts any [`EventsRpc`] client to the [`SorobanEventFeed`] door the
/// ingestion source consumes.
///
/// `start_ledger` is where a fresh pass begins (sent only when no
/// cursor is being resumed from, exactly as the RPC documentation
/// prescribes). The adapter holds a `&mut` borrow of the client, so an
/// ingestion loop owns the client and passes it through.
pub struct EventsRpcFeed<'a, C> {
    client: &'a mut C,
    start_ledger: Option<u32>,
}

impl<'a, C: EventsRpc> EventsRpcFeed<'a, C> {
    /// Builds the feed over `client`, beginning fresh passes at
    /// `start_ledger` (or at the node's earliest retained ledger when
    /// `None`).
    pub fn new(client: &'a mut C, start_ledger: Option<u32>) -> Self {
        Self {
            client,
            start_ledger,
        }
    }
}

impl<C: EventsRpc> SorobanEventFeed for EventsRpcFeed<'_, C> {
    fn fetch_page(
        &mut self,
        after: Option<&str>,
        limit: usize,
    ) -> SourceResult<SorobanEventsResult> {
        // The source's page limit is already within the RPC range, but
        // the trait is public: reject anything out of range before it
        // can be truncated by the cast below.
        if !(1..=MAX_LIMIT as usize).contains(&limit) {
            return Err(SourceError::InvalidItem(format!(
                "page limit {limit} is outside the getEvents range"
            )));
        }
        let mut params = GetEventsParams::new();
        match after {
            Some(cursor) => params = params.cursor(cursor),
            None => {
                if let Some(ledger) = self.start_ledger {
                    params = params.start_ledger(ledger);
                }
            }
        }
        params = params.limit(limit as u32);
        if let Err(error) = params.validate() {
            return Err(SourceError::InvalidItem(error.to_string()));
        }
        self.client
            .get_events(&params)
            .map_err(|error| SourceError::FetchFailed(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_soroban::SorobanEventType;

    const CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

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

    fn events(count: u32) -> Vec<SorobanEvent> {
        (1..=count).map(event).collect()
    }

    #[test]
    fn the_mock_pages_with_cursor_semantics() {
        let mut client = MockEventsClient::new(events(5));
        let params = GetEventsParams::new().start_ledger(100).limit(2);
        let page1 = client.get_events(&params).unwrap();
        assert_eq!(page1.events.len(), 2);
        assert_eq!(page1.events[0].id, toid(1));
        let cursor = page1.cursor.unwrap();
        assert_eq!(cursor, toid(2));

        let resumed = GetEventsParams::new().cursor(&cursor).limit(10);
        let page2 = client.get_events(&resumed).unwrap();
        assert_eq!(page2.events.len(), 3);
        assert_eq!(page2.events[0].id, toid(3));
        assert!(page2.cursor.is_none());
    }

    #[test]
    fn the_mock_can_inject_transient_failures() {
        let mut client = MockEventsClient::new(events(1));
        client.fail_next(2);
        let params = GetEventsParams::new().start_ledger(100).limit(10);
        assert!(matches!(
            client.get_events(&params),
            Err(RpcError::Transport(_))
        ));
        assert!(matches!(
            client.get_events(&params),
            Err(RpcError::Transport(_))
        ));
        assert!(client.get_events(&params).is_ok());
    }

    #[test]
    fn the_feed_bridge_resumes_and_starts_fresh() {
        let mut client = MockEventsClient::new(events(3));
        let mut feed = EventsRpcFeed::new(&mut client, Some(100));

        // A fresh pass asks for the configured start ledger.
        let page1 = feed.fetch_page(None, 2).unwrap();
        assert_eq!(page1.events.len(), 2);
        assert_eq!(page1.events[0].id, toid(1));

        // A resumed pass sends only the cursor.
        let page2 = feed.fetch_page(page1.cursor.as_deref(), 10).unwrap();
        assert_eq!(page2.events.len(), 1);
        assert_eq!(page2.events[0].id, toid(3));
    }

    #[test]
    fn feed_transport_failures_surface_as_fetch_failures() {
        let mut client = MockEventsClient::new(events(1));
        client.fail_next(1);
        let mut feed = EventsRpcFeed::new(&mut client, Some(100));
        assert!(matches!(
            feed.fetch_page(None, 10),
            Err(SourceError::FetchFailed(_))
        ));
    }
}
