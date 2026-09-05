//! # safeguard-audit-rpc
//!
//! The Stellar Soroban RPC protocol boundary: request and response
//! envelopes for the JSON-RPC `getEvents` method, verified against the
//! current Stellar API reference — plus the retry/timeout policy an
//! ingestion loop runs under, and a clearly-labeled mock for tests.
//!
//! ## What is modeled here
//!
//! [`events`] holds the request side (named `params` with `startLedger`,
//! `endLedger`, up to five `filters` each naming a type and up to five
//! contract ids or topic matchers, and `pagination` carrying the opaque
//! cursor and the 1-10,000 `limit`) and the response side (the
//! JSON-RPC 2.0 envelope whose `result` is the verified
//! [`SorobanEventsResult`] shape from `safeguard-audit-soroban`, with
//! the `error` member surfaced as a typed [`RpcError`]). Parsing is
//! pinned against the Stellar documentation's own example request and
//! response.
//!
//! ## What is deliberately *not* modeled
//!
//! * **No HTTP transport.** This crate defines the [`EventsRpc`]
//!   contract — one typed `get_events` call — and the envelope
//!   machinery, but performs no network I/O. A transport (outside this
//!   crate) serializes the request body, POSTs it to an RPC node, and
//!   hands the response body back to the parser.
//! * **No retry magic.** [`RetryPolicy`] and [`fetch_with_retry`] are
//!   the policy and executor shape an ingestion loop runs under:
//!   bounded attempts with capped exponential backoff, retrying only
//!   the failure classes that can plausibly clear (transport hiccups
//!   and generic JSON-RPC server errors), never protocol or request
//!   errors.
//! * **No invented semantics.** The mock client serves recorded events
//!   and is labeled for testing/development only — it is not an RPC
//!   node and must never be treated as a security boundary.
//!
//! Anything below is synthetic test data — this repository never
//! hard-codes credentials or real network endpoints.

pub mod errors;
pub mod events;
pub mod mock;
pub mod retry;

pub use errors::{RpcError, RpcResult};
pub use events::{
    parse_get_events_response, EventFilter, EventTypeFilter, GetEventsParams, GetEventsRequest,
    JsonRpcEnvelope, RpcErrorBody,
};
pub use mock::{EventsRpcFeed, MockEventsClient};
pub use retry::{fetch_with_retry, RetryPolicy, RpcPolicy};

/// The typed client contract an RPC transport implements.
pub trait EventsRpc {
    /// Executes one `getEvents` call for `params`, returning the page.
    ///
    /// Implementations serialize [`GetEventsRequest`], POST it to the
    /// node, parse the response body with [`parse_get_events_response`],
    /// and surface transport failures as [`RpcError::Transport`] so the
    /// retry policy can treat them correctly.
    fn get_events(
        &mut self,
        params: &GetEventsParams,
    ) -> RpcResult<safeguard_audit_soroban::SorobanEventsResult>;
}
