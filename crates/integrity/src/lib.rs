//! # safeguard-audit-integrity
//!
//! Tamper-evident hashing and verification for audit records.
//!
//! The persisted integrity *vocabulary* (digests, schemes, outcomes,
//! manifests) lives in `safeguard-audit-core`; this crate implements the
//! computation against it:
//!
//! * **hashing** — canonical record input and the SHA-256 primitive every
//!   digest builds on;
//! * **digest** — the `standalone` scheme: one digest per record;
//! * **chain** — the `chained` scheme: digest(N) covers digest(N-1) plus
//!   record(N), so reordering, deletion, or replacement breaks the chain;
//! * **manifest** — digest inventories over record ranges, evidence
//!   packages, or exports;
//! * **verification** — recomputing digests and comparing them to what
//!   was stored, reporting machine-readable outcomes;
//! * **tamper** — scanning for alteration and locating the first failure.
//!
//! ## Honest limits
//!
//! Chained digests over locally stored records make tampering
//! *detectable*; they do not create blockchain-level immutability. The
//! crate distinguishes local record integrity (verified here) from
//! on-chain source integrity (anchored by the ledger) and export
//! integrity (manifests shipped with packages), and never claims
//! otherwise.

pub mod chain;
pub mod digest;
pub mod errors;
pub mod hashing;
pub mod manifest;
pub mod tamper;
pub mod verification;

pub use chain::{chain_step, seal_chain, verify_chain};
pub use digest::{record_digest, seal_standalone};
pub use errors::{IntegrityError, IntegrityResult};
pub use hashing::{canonical_record_input, hash_bytes};
pub use manifest::{build_manifest, ManifestOptions};
pub use tamper::{detect, intact, locate_tampering};
pub use verification::{
    all_verified, verify_all, verify_manifest_aggregate, verify_manifest_records, verify_record,
};
