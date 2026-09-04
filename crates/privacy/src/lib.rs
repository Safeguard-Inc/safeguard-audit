//! # safeguard-audit-privacy
//!
//! The enforcement boundary of the audit layer's classification policy.
//!
//! `audit-core` owns the *vocabulary*: `DataClassification` names how
//! sensitive a piece of audit data is, and the `AuditRecord` carries both
//! an overall classification and a per-field `redactions` table. This
//! crate applies that policy wherever protected values would otherwise
//! reach a reader — a report, an export, a display — by turning detail
//! values into a deterministic, marker-based redacted view *before* the
//! data leaves the record.
//!
//! ## The rule
//!
//! A detail value is disclosed only when its classification is strictly
//! below the disclosure ceiling, mirroring the record-level ceiling the
//! reporting service already enforces (`is_at_least(ceiling)` excludes).
//! Fields the record's `redactions` table does not name inherit the
//! record's own classification, so an empty table protects at the record
//! level instead of silently disclosing. Redaction is deterministic:
//! the same record and ceiling always produce the same output.
//!
//! ## What this crate is *not*
//!
//! It does not invent cryptography. Private balances, transfer amounts,
//! and ciphertexts are never recorded by this repository in the first
//! place; when an upstream Confidential Token architecture exposes them
//! through a legitimate view-key mechanism, that integration arrives
//! later through the `DecryptionProvider` boundary and only after the
//! upstream protocol has been verified. Nothing here decrypts, guesses,
//! or un-redacts.
//!
//! It is also not a policy engine: it never decides what *should* be
//! secret. Classification is decided upstream (`audit-core` vocabulary,
//! semantic event types); this crate only stops protected values from
//! being repeated.

pub mod ceiling;
pub mod disclosure;
pub mod redaction;

pub use ceiling::disclosure_ceiling;
pub use disclosure::{disclose_details, redacted_keys, RecordDisclosure};
pub use redaction::{is_redacted, redact_details, REDACTED_MARKER};
