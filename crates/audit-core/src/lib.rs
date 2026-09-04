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

pub mod audit;
pub mod authorization;
pub mod correlation;
pub mod errors;
pub mod event;
pub mod evidence;
pub mod identifiers;
pub mod integrity;
pub mod investigation;
pub mod pagination;
pub mod privacy;
pub mod record;
pub mod report;
pub mod retention;
pub mod serialization;
pub mod timestamps;

pub use audit::RECORD_SCHEMA_VERSION;
pub use authorization::{
    AccessAction, AccessResult, AccessScope, AuditAccessEntry, AuditorIdentity, AuditorRole,
    AuthorizationDecision,
};
pub use correlation::{
    AccountReference, ContractReference, DecisionResult, EnforcementResultReference,
    LedgerReference, OperationReference, PolicyDecisionReference, PolicyReference, TokenReference,
    TransactionReference, VersionLabel,
};
pub use errors::{AuditError, AuditResult};
pub use event::{AuditEvent, DerivationInfo, EventKind, EventOrder, EventProvenance, OriginKind};
pub use evidence::{EvidenceArtifact, EvidenceKind, EvidenceProvenance};
pub use identifiers::{
    AccessEntryId, AccountId, AuditorId, CaseId, ContractId, EventId, EvidenceId, FindingId,
    ManifestId, NetworkId, NoteId, ReasonCode, RecordId, ReportId, RequestId, TransactionHash,
};
pub use integrity::{
    IntegrityDigest, IntegrityManifest, IntegrityScheme, IntegrityStatus, ManifestEntry,
    VerificationFailure, VerificationOutcome,
};
pub use investigation::{
    CaseStatus, Finding, FindingKind, InvestigationCase, Note, Priority, RelatedReferences,
    Severity, TimelineEntry, TimelineEntryKind,
};
pub use pagination::{Cursor, Page, PageRequest};
pub use privacy::DataClassification;
pub use record::{AuditRecord, RecordIntegrity};
pub use report::{
    GeneratorVersions, Report, ReportKind, ReportQuery, ReportRequest, ReportSummary,
};
pub use retention::{RetentionPeriod, RetentionPolicy, RetentionStatus};
pub use timestamps::{Clock, FixedClock, SystemClock, TimeRange, Timestamp};
