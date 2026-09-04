//! # safeguard-audit-normalizer
//!
//! Deterministic normalization for the audit layer: raw, provider-shaped
//! events become provider-neutral [`AuditEvent`] envelopes that the indexer
//! can deduplicate, order, and persist.
//!
//! The pipeline is explicit and each stage owns one concern:
//!
//! ```text
//! raw item (scheme + JSON payload)
//!   → parse      (decode the payload by scheme into a typed raw form)
//!   → validate   (semantic rules: types, identifiers, placement)
//!   → classify   (project the raw form onto the normalized envelope)
//! ```
//!
//! ## Determinism
//!
//! Normalization is a pure function of (raw payload, scheme, normalizer
//! configuration). Given the same inputs it yields byte-identical
//! envelopes: same event id (derived from stable source identifiers, never
//! arrival time), same ordering metadata, same provenance labels. The
//! configuration pins the network, the emitting-source label, and the
//! parser version, so a recorded envelope can always name exactly which
//! parser configuration produced it.
//!
//! ## What the normalizer is *not*
//!
//! It does not fetch anything (that is an [`EventSource`]), it does not
//! decide what to record or skip (that is the indexer), it does not judge
//! payloads against policy, and it never invents semantic values: an
//! unsupported type, version, or identifier shape is an error, never a
//! silent reinterpretation.
//!
//! [`AuditEvent`]: safeguard_audit_core::AuditEvent
//! [`EventSource`]: safeguard_audit_core::EventSource

pub mod errors;
pub mod parser;
pub mod scheme;

pub use errors::{NormalizerError, NormalizerResult};
pub use parser::{parse, HooksType, ParsedEvent, RawEnvelope, RawHooksEvent};
pub use scheme::Scheme;
