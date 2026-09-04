//! # safeguard-audit-core
//!
//! Provider-neutral domain model for the Safeguard audit layer (VERIFY).
//!
//! This crate is the vocabulary the rest of the repository speaks. It defines
//! the normalized event and record shapes that survive ingestion, the
//! references used to correlate history back to `safeguard-policy` decisions
//! and `safeguard-hooks` enforcement, the integrity primitives that make
//! records tamper-evident, and the models behind investigations, evidence,
//! reports, authorization, retention, and privacy classification.
//!
//! ## Dependency rule
//!
//! Nothing in this crate may depend on a concrete event source, database,
//! RPC provider, or protocol adapter. Soroban-specific types live in the
//! adapter crates; protocol behavior is isolated behind interfaces. This
//! crate only ever references what is already normalized.
//!
//! ## What this crate is *not*
//!
//! It is not a policy engine, an enforcement layer, a wallet, a generic
//! blockchain explorer, or a database. Policy *definition* belongs to
//! `safeguard-policy`; policy *enforcement* belongs to `safeguard-hooks`;
//! this repository *records and verifies what happened*.

pub mod correlation;
pub mod errors;
pub mod event;
pub mod identifiers;
pub mod pagination;
pub mod privacy;
pub mod serialization;
pub mod timestamps;

pub use correlation::{
    AccountReference, ContractReference, DecisionResult, EnforcementResultReference,
    LedgerReference, OperationReference, PolicyDecisionReference, PolicyReference, TokenReference,
    TransactionReference, VersionLabel,
};
pub use errors::AuditError;
pub use event::{AuditEvent, DerivationInfo, EventKind, EventOrder, EventProvenance, OriginKind};
pub use identifiers::EventId;
pub use pagination::{Cursor, Page, PageRequest};
pub use privacy::DataClassification;
pub use timestamps::{Clock, FixedClock, SystemClock, TimeRange, Timestamp};
