//! # safeguard-audit-events
//!
//! Semantic event types for the audit layer.
//!
//! This crate sits between raw sources and the normalized [`AuditEvent`]
//! envelope. It defines:
//!
//! * **source-shaped events** that mirror what `safeguard-hooks` actually
//!   emits on-chain (freeze/unfreeze, bind/unbind, configuration changes)
//!   and what an indexer can observe about transactions and operations, and
//! * **derived events** that the audit layer itself produces for things no
//!   contract can emit — a denied transfer (reverts discard events), a
//!   policy version change observed by an indexer, an auditor access, an
//!   investigation lifecycle step.
//!
//! Every type here projects onto the provider-neutral core envelope via
//! `into_audit_event`, which stamps provenance (observed vs derived) and
//! derives the deterministic [`EventId`] from stable source identity parts.
//!
//! ## Honest event surface
//!
//! Per-operation *approvals* are never emitted on-chain by the enforcement
//! layer (any contract could spoof the hook surface), and *denials* cannot
//! be emitted (a revert discards its events). Transfer outcomes are
//! therefore always derived events carrying derivation info, reconstructed
//! by an authorized process from authoritative transaction metadata. The
//! audit trail records the distinction instead of blurring it.

pub mod compliance;
pub mod errors;
pub mod event_id;
pub mod freeze;
pub mod sanctions;
pub mod transaction;
pub mod transfer;

pub use errors::{EventError, EventResult};
pub use event_id::{derive_event_id, derived_event_id, onchain_event_id, EventSlot};
