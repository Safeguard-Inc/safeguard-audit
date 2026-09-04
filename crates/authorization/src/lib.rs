//! # safeguard-audit-authorization
//!
//! Authorization services for the Safeguard audit layer.
//!
//! `audit-core` defines the authorization *models*: [`AuditorRole`],
//! [`AccessAction`], [`AccessScope`], [`AuthorizationDecision`], and
//! [`AuditAccessEntry`]. This crate implements the *decisions* on top of
//! them — the machinery that answers "may this identity perform this
//! action within this scope right now?" and records the answer.
//!
//! ## The evaluation chain
//!
//! ```text
//! identity (role)  ──► role permission matrix ──► action allowed?
//! granted scopes   ──► scope containment        ──► scope in bounds?
//! credential       ──► expiry / validity check  ──► still authorized?
//!                                    │
//!                                    ▼
//!                     AuthorizationDecision (granted / denied / out-of-scope)
//!                                    │
//!                                    ▼
//!                     AuditAccessEntry ──► audit-access event ──► store
//! ```
//!
//! * **Roles** (`roles`) — the default least-privilege matrix mapping each
//!   [`AuditorRole`] to the [`AccessAction`]s it may perform.
//! * **Permissions** (`permissions`) — per-identity permission sets with
//!   action checks, seeded from the role matrix and overridable.
//! * **Scopes** (`scopes`) — containment: does a requested scope fall
//!   inside a granted scope? Scoped auditors never leak into unrelated
//!   scopes by construction.
//! * **Credentials** (`credentials`) — identity proof with an expiry;
//!   verification is time-aware so an expired credential is a clean denial,
//!   never a panic.
//! * **Registry** (`registry`) — the auditor grant table: who holds which
//!   role and which scopes, with grant/revoke for auditability.
//! * **Authorizer** (`authorizer`) — the service that composes the above
//!   into an [`AuthorizationDecision`] attributed to a known actor.
//! * **Access log** (`access_log`) — turns every decision into an
//!   [`AuditAccessEntry`] and persists it as a derived `audit-access`
//!   event through the store. The audit trail auditing itself stops there:
//!   access events are recorded once and there is deliberately no
//!   meta-audit of the audit.
//!
//! ## Privacy boundary
//!
//! Authorization is the gate in front of protected data. Classification
//! lives in `audit-core` (`DataClassification`); the authorizer treats a
//! requested scope touching `restricted` or `highly-restricted` data as a
//! separate, explicit decision so protected access is always attributable.
//!
//! ## No fake guarantees
//!
//! This crate verifies *credentials the registry knows about*; it does not
//! implement cryptography. Real credential material (signatures, keys,
//! tokens) must be validated by an upstream identity provider behind the
//! credential abstraction — this crate treats a registered credential that
//! has not expired as valid and says so plainly.

pub mod authorizer;
pub mod credentials;
pub mod errors;
pub mod permissions;
pub mod registry;
pub mod roles;
pub mod scopes;

pub use errors::{AuthorizationError, AuthorizationResult};

/// The crate's stable parser/version label for events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-authorization";