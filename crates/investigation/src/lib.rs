//! # safeguard-audit-investigation
//!
//! Investigation services for the Safeguard audit layer.
//!
//! `audit-core` defines the case *models*: [`InvestigationCase`] with
//! validated [`CaseStatus`] transitions, a deterministic [`TimelineEntry`]
//! timeline, [`Finding`]s, [`Note`]s, and [`RelatedReferences`]. This
//! crate implements the *services* on top of them — the machinery that
//! turns "investigate this denied operation" into a live case whose every
//! step is recorded.
//!
//! ## The case lifecycle
//!
//! ```text
//! open(case) ──► assign(investigator) ──► investigating
//!   │                 │                       │
//!   │                 ├─► link records        ├─► escalated (needs review)
//!   │                 ├─► add finding         │
//!   │                 └─► add note            ▼
//!   │                                   resolved
//!   │                                       │
//!   └────────── admin reopen ◄──────────────▼
//!                           closed (reason recorded)
//! ```
//!
//! Every step that changes a case is projected onto the audit store as a
//! derived `investigation-opened` / `investigation-updated` /
//! `investigation-closed` event (via `audit-events::InvestigationLifecycle`),
//! so the audit trail can answer "which cases exist, who touched them, and
//! when" independently of the case store's current state.
//!
//! ## What lives here
//!
//! * **store** — the [`CaseStore`] contract for persisting case state, and
//!   the in-memory implementation for tests and single-node development.
//!   The case store holds *current state*; history lives in the audit
//!   store as lifecycle events.
//! * **service** — [`CaseService`], the workflow facade: opening a case
//!   derives a deterministic [`CaseId`], assigning and transitions are
//!   validated against the model, records are linked only when they exist
//!   in the audit store, and closure is recorded with its reason.
//! * **events** — projection helpers that turn each lifecycle step into
//!   the derived audit event recorded through the [`EventStore`].
//!
//! ## Boundaries
//!
//! * This crate never *enforces* policy — it investigates what happened.
//! * Cases are mutable state; the audit trail they generate is
//!   append-only. The two are deliberately separate stores.
//! * Case access is gated by the authorization crate's roles and scopes;
//!   the service accepts an authorization decision rather than re-deriving
//!   policy.

pub mod errors;

pub use errors::{InvestigationError, InvestigationResult};

/// The crate's stable source label for lifecycle events it derives.
pub const SOURCE_LABEL: &str = "safeguard-audit-investigation";