//! # safeguard-audit-evidence
//!
//! Evidence services for the Safeguard audit layer.
//!
//! `audit-core` defines the artifact *models*: [`EvidenceArtifact`] with
//! provenance (which records and events support it, which parser and
//! generator versions produced it) and integrity slots. This crate
//! implements the *machinery* that turns verified audit records into
//! evidence that can be exported and independently checked.

pub mod errors;

pub use errors::{EvidenceError, EvidenceResult};

/// The crate's stable source label for the events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-evidence";