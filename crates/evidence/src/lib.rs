//! # safeguard-audit-evidence
//!
//! Evidence services for the Safeguard audit layer.
//!
//! `audit-core` defines the artifact *models*: [`EvidenceArtifact`] with
//! provenance (which records and events support it, which parser and
//! generator versions produced it) and integrity slots. This crate
//! implements the *machinery* that turns verified audit records into
//! evidence that can be exported and independently checked.
//!
//! ## What lives here
//!
//! * **model** — the evidence *package*: an artifact paired with the
//!   artifact-linked integrity manifest certifying its source records.
//! * **events** — projection of each generation onto a derived
//!   `evidence-generated` event in the audit store.

pub mod errors;
pub mod events;
pub mod model;

pub use errors::{EvidenceError, EvidenceResult};
pub use events::record_generation;
pub use model::{EvidenceManifest, EvidencePackage};

/// The crate's stable source label for the events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-evidence";