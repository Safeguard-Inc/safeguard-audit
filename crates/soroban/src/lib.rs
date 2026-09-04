//! # safeguard-audit-soroban
//!
//! The Soroban adapter: the door real on-chain data enters through.
//!
//! `safeguard-hooks` enforcement produces the *compliance meaning* of an
//! operation; this crate only carries the *on-chain facts* — which
//! contract emitted which event, in which ledger and transaction, with
//! which topics — from a Soroban node into the ingestion pipeline. It
//! speaks the audit layer's normalized vocabulary on one side and a
//! verified Soroban wire shape on the other, and it must never leak
//! Soroban-specific types into anything downstream.
//!
//! ## What is modeled here
//!
//! [`wire`] models the Stellar RPC `getEvents` response envelope exactly
//! as the Stellar documentation defines it (verified against the
//! current API reference): `type` (`contract`/`system`), `ledger`,
//! `ledgerClosedAt`, `contractId`, the TOID-based `id` dedup key,
//! transaction/operation indices, the 1-4 `topic` segments, the `value`,
//! and the transaction hash.
//!
//! ## What is deliberately *not* modeled
//!
//! * **ScVal decoding.** Topics and values are opaque base64 ScVals
//!   here. Decoding them into typed values requires the XDR/soroban
//!   environment types and — more importantly — the *meaning* of a
//!   topic belongs to the contract that emitted it. That meaning is
//!   verified against the actual hooks/contract surface before anything
//!   is mapped, never invented in this crate.
//! * **No RPC client.** [`source`] implements the audit-core
//!   [`EventSource`] door over a narrow [`SorobanEventFeed`] trait — the
//!   fetch operation an RPC client supplies outside this crate. This
//!   crate depends on no network stack and no node.
//! * **No audit semantics.** A generic Soroban event does not become an
//!   `AuditEvent` by magic: mapping requires an operator-provided
//!   contract registry and the verified payload schemas of the events
//!   this deployment cares about.
//!
//! Anything below is synthetic test data — this repository never
//! hard-codes credentials or real network endpoints.

pub mod mapping;
pub mod source;
pub mod wire;

pub use mapping::{parse_ledger_close_time, to_normalized, NormalizedParts};
pub use source::{SorobanEventFeed, SorobanEventSource};
pub use wire::{SorobanEvent, SorobanEventType, SorobanEventsResult};
