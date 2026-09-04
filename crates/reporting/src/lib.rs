//! # safeguard-audit-reporting
//!
//! Reporting services for the Safeguard audit layer.
//!
//! `audit-core` defines the report *models*: [`Report`] with its captured
//! [`ReportQuery`] (the reproducibility record), version labels, summary
//! counts, and public-reference rows. This crate implements the
//! *machinery* that turns an authorized request into a report:
//!
//! ```text
//! request ──► authorize ──► map to query ──► scan the store ──► filter
//!  (kind + query)   │            │              (paged)         │
//!                    │            └ incoherent? refuse          ├─► classification ceiling
//!                    └ denied? refuse                          └─► multi-token membership
//!                                             │
//!                                             ▼
//!                              summary counts + public-reference rows
//!                                             │
//!                                             ▼
//!                          deterministic report id + content digest
//!                                             │
//!                                             ▼
//!                          report-generated event recorded on the trail
//! ```
//!
//! ## What lives here
//!
//! * **query** — the deterministic mapping from a [`ReportQuery`] to the
//!   store's [`AuditQuery`] (network, token, account, outcome, event
//!   kinds, time range).
//! * **service** — [`ReportService`]: authorizes the requester, validates
//!   the request, scans the matching range in deterministic order,
//!   applies the privacy ceiling (rows at or above the query's
//!   classification ceiling are excluded) and multi-token membership,
//!   assembles count-only summaries and public transaction-reference
//!   rows, and seals the report with a deterministic id and a content
//!   digest.
//! * **events** — projection of each generation onto a derived
//!   `report-generated` event in the audit store.
//!
//! ## Reproducibility
//!
//! A report captures its own query, so the same store and the same
//! request reproduce the same report — including the same report id
//! (derived from network + kind + canonical query) and the same digest.
//!
//! ## Boundaries
//!
//! * Reports are *bounded summaries*: count tables plus public
//!   transaction references, never dumps of protected data. The
//!   classification ceiling is enforced at generation time.
//! * The reporting crate generates reports; it does not decide policy,
//!   enforce transfers, or grant access (authorization decisions come
//!   from the authorization crate).

pub mod errors;
pub mod events;
pub mod query;
pub mod service;

pub use errors::{ReportingError, ReportingResult};
pub use events::record_report;
pub use query::to_audit_query;
pub use service::ReportService;

/// The crate's stable source label for the events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-reporting";