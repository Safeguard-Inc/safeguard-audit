//! # safeguard-audit-evidence
//!
//! Evidence services for the Safeguard audit layer.
//!
//! `audit-core` defines the artifact *models*: [`EvidenceArtifact`] with
//! provenance (which records and events support it, which parser and
//! generator versions produced it) and integrity slots. This crate
//! implements the *machinery* that turns verified audit records into
//! evidence that can be exported and independently checked:
//!
//! ```text
//! source records ──► fetch ──► integrity gate ──► sort ──► seal
//!      (audit store)   │           │                        │
//!                       │           └─ altered? refuse      ├─► artifact + content digest
//!                       └─ missing? refuse                 └─► integrity manifest
//!                                                                  (per-record + aggregate)
//!                                             │
//!                                             ▼
//!                                   evidence-generated event
//!                                   recorded into the audit store
//! ```
//!
//! ## What lives here
//!
//! * **builder** — [`EvidenceBuilder`]: authorizes the acting auditor,
//!   fetches each named source record, refuses records whose stored
//!   digest no longer matches their body (an altered source must not
//!   become evidence), orders the set deterministically, and seals an
//!   [`EvidencePackage`]: an artifact with a content digest plus an
//!   artifact-linked integrity manifest over its source records.
//! * **verify** — recomputing the artifact digest, the manifest
//!   aggregate, and every per-record digest, with and without store
//!   access (an exported package can be checked standalone).
//! * **model** — the evidence *package*: an artifact paired with the
//!   artifact-linked integrity manifest certifying its source records.
//! * **events** — projection of each generation onto a derived
//!   `evidence-generated` event in the audit store.
//!
//! ## Honest limits
//!
//! The artifact digest and manifest make alteration *detectable*; they do
//! not make the artifact immutable. The builder refuses altered sources
//! up front, but neither replaces on-chain anchoring, which is the
//! Soroban ledger's job.
//!
//! ## Boundaries
//!
//! * This crate generates and verifies evidence; it does not decide
//!   policy, enforce transfers, or grant access (authorization decisions
//!   come from the authorization crate).
//! * Artifacts reference records by id; protected record content is never
//!   copied into the artifact. Privacy remains the store's concern.

pub mod builder;
pub mod errors;
pub mod events;
pub mod model;
pub mod verify;

pub use builder::{EvidenceBuilder, EvidenceBuildOptions};
pub use errors::{EvidenceError, EvidenceResult};
pub use events::record_generation;
pub use model::{EvidenceManifest, EvidencePackage};
pub use verify::{
    verify_package, verify_package_structure, EvidenceVerification, EvidenceVerificationSummary,
};

/// The crate's stable source label for the events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-evidence";