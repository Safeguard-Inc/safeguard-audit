//! The normalized audit event envelope.
//!
//! Raw events from any source — a Soroban ledger, an RPC feed, the
//! simulator, a fixture — arrive in provider-specific shapes. Before
//! anything downstream touches them, a normalizer converts them into this
//! provider-neutral [`AuditEvent`]: one envelope with a typed [`EventKind`],
//! source provenance, ordering metadata, and optional references to the
//! transaction, operation, token, accounts, policy decision, and
//! enforcement result the event is about.
//!
//! ## What survives normalization
//!
//! The envelope holds only *public metadata and references*: addresses,
//! hashes, codes, timestamps, and provenance labels. No amounts, balances,
//! ciphertexts, or other protected values exist on this shape. Events that
//! need extra context carry it as short, validated `details` strings whose
//! allowed keys are the normalizer's concern.
//!
//! ## Derived events
//!
//! Some things worth recording never appear as an on-chain event (a denied
//! transfer, for instance: the hooks layer reverts before any event can be
//! emitted). Such events are *derived* — reconstructed by an authorized
//! process from authoritative on-chain metadata — and their provenance
//! carries a [`DerivationInfo`] explaining exactly what they were derived
//! from and how, so a reader can always tell an observed event from an
//! interpretation of one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::correlation::{
    AccountReference, DecisionResult, EnforcementResultReference, LedgerReference,
    OperationReference, PolicyDecisionReference, TokenReference, TransactionReference,
    VersionLabel,
};
use crate::errors::{AuditError, AuditResult};
use crate::identifiers::{EventId, NetworkId, ReasonCode};
use crate::serialization::canonical_json;
use crate::timestamps::Timestamp;

/// The current schema version of the normalized event envelope.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// The supported normalized event kinds.
///
/// The list is the union of:
///
/// * the event classes the audit spec defines (transfer outcomes, freeze
///   state, compliance decisions, investigation/evidence/report lifecycle),
/// * the state transitions `safeguard-hooks` actually emits on-chain
///   (token bind/unbind, configuration changes), and
/// * `record-corrected`, the append-only correction event.
///
/// Kinds serialize to stable kebab-case strings. Adding a kind is a
/// deliberate schema change; normalizers reject anything outside this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    /// A transfer was permitted (derived where not emitted on-chain).
    TransferAuthorized,
    /// A transfer was refused by policy or authorization.
    TransferDenied,
    /// A transfer was permitted but flagged for review.
    TransferFlagged,
    /// An account was frozen on a token (on-chain hooks event).
    AccountFrozen,
    /// An account was unfrozen on a token (on-chain hooks event).
    AccountUnfrozen,
    /// A token was bound to enforcement (on-chain hooks event).
    TokenBound,
    /// A token was unbound from enforcement (on-chain hooks event).
    TokenUnbound,
    /// Enforcement configuration changed (on-chain hooks event).
    ConfigurationChanged,
    /// A compliance decision was produced and recorded.
    ComplianceDecision,
    /// A policy version change was observed.
    PolicyVersionChanged,
    /// An authorization grant or revocation was recorded.
    AuthorizationChanged,
    /// An auditor accessed audit data (the audit trail auditing itself).
    AuditAccess,
    /// An investigation case was opened.
    InvestigationOpened,
    /// An investigation case was updated.
    InvestigationUpdated,
    /// An investigation case was closed.
    InvestigationClosed,
    /// An evidence artifact was generated.
    EvidenceGenerated,
    /// A report was generated.
    ReportGenerated,
    /// A record was corrected (the correction is itself a new record).
    RecordCorrected,
}

impl EventKind {
    /// The stable wire string for this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TransferAuthorized => "transfer-authorized",
            Self::TransferDenied => "transfer-denied",
            Self::TransferFlagged => "transfer-flagged",
            Self::AccountFrozen => "account-frozen",
            Self::AccountUnfrozen => "account-unfrozen",
            Self::TokenBound => "token-bound",
            Self::TokenUnbound => "token-unbound",
            Self::ConfigurationChanged => "configuration-changed",
            Self::ComplianceDecision => "compliance-decision",
            Self::PolicyVersionChanged => "policy-version-changed",
            Self::AuthorizationChanged => "authorization-changed",
            Self::AuditAccess => "audit-access",
            Self::InvestigationOpened => "investigation-opened",
            Self::InvestigationUpdated => "investigation-updated",
            Self::InvestigationClosed => "investigation-closed",
            Self::EvidenceGenerated => "evidence-generated",
            Self::ReportGenerated => "report-generated",
            Self::RecordCorrected => "record-corrected",
        }
    }

    /// Parses a wire string back into a kind, or `None` if unsupported.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "transfer-authorized" => Self::TransferAuthorized,
            "transfer-denied" => Self::TransferDenied,
            "transfer-flagged" => Self::TransferFlagged,
            "account-frozen" => Self::AccountFrozen,
            "account-unfrozen" => Self::AccountUnfrozen,
            "token-bound" => Self::TokenBound,
            "token-unbound" => Self::TokenUnbound,
            "configuration-changed" => Self::ConfigurationChanged,
            "compliance-decision" => Self::ComplianceDecision,
            "policy-version-changed" => Self::PolicyVersionChanged,
            "authorization-changed" => Self::AuthorizationChanged,
            "audit-access" => Self::AuditAccess,
            "investigation-opened" => Self::InvestigationOpened,
            "investigation-updated" => Self::InvestigationUpdated,
            "investigation-closed" => Self::InvestigationClosed,
            "evidence-generated" => Self::EvidenceGenerated,
            "report-generated" => Self::ReportGenerated,
            "record-corrected" => Self::RecordCorrected,
            _ => return None,
        })
    }

    /// The complete supported kind set (registry used by normalizers and
    /// validation tests).
    pub const ALL: &'static [EventKind] = &[
        Self::TransferAuthorized,
        Self::TransferDenied,
        Self::TransferFlagged,
        Self::AccountFrozen,
        Self::AccountUnfrozen,
        Self::TokenBound,
        Self::TokenUnbound,
        Self::ConfigurationChanged,
        Self::ComplianceDecision,
        Self::PolicyVersionChanged,
        Self::AuthorizationChanged,
        Self::AuditAccess,
        Self::InvestigationOpened,
        Self::InvestigationUpdated,
        Self::InvestigationClosed,
        Self::EvidenceGenerated,
        Self::ReportGenerated,
        Self::RecordCorrected,
    ];
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where an event came from.
///
/// This is the first thing a reader checks: an *observed* on-chain event
/// and a *derived* reconstruction of one are different kinds of evidence
/// with different trust profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginKind {
    /// Emitted by a contract and observed on a ledger.
    OnChain,
    /// Reconstructed by an authorized process from authoritative metadata.
    Derived,
    /// Imported from another system (e.g. an external compliance feed).
    Imported,
    /// Produced by the simulator for tests, fixtures, or development.
    Simulated,
}

/// Why and from what a derived event was produced.
///
/// Derivation must be transparent: an investigator must be able to trace a
/// derived record back to the observed data that supports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationInfo {
    /// Short method label, e.g. `failed-tx-analysis`.
    method: String,
    /// The observed events (if any) this event was derived from.
    source_events: Vec<EventId>,
    /// Free-form (but short) explanation; never contains protected values.
    note: String,
}

impl DerivationInfo {
    /// Builds derivation info. `method` and `note` are bounded printable
    /// strings.
    pub fn new(method: &str, source_events: Vec<EventId>, note: &str) -> AuditResult<Self> {
        if method.is_empty() || method.len() > 64 || !method.chars().all(|c| c.is_ascii_graphic()) {
            return Err(AuditError::invalid_identifier(
                "derivation method",
                "must be 1-64 printable ASCII chars",
            ));
        }
        if note.len() > 512 {
            return Err(AuditError::invalid_identifier(
                "derivation note",
                "must be at most 512 chars",
            ));
        }
        Ok(Self {
            method: method.to_owned(),
            source_events,
            note: note.to_owned(),
        })
    }

    /// The derivation method label.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The observed events this was derived from.
    pub fn source_events(&self) -> &[EventId] {
        &self.source_events
    }

    /// The human explanation.
    pub fn note(&self) -> &str {
        &self.note
    }
}

/// Provenance of a normalized event: origin, emitting source, parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProvenance {
    /// On-chain, derived, imported, or simulated.
    origin: OriginKind,
    /// Stable label of the emitting source, e.g. `soroban`,
    /// `safeguard-hooks`, or `simulator`.
    source: String,
    /// Version of the parser/normalizer that produced this envelope.
    parser_version: VersionLabel,
    /// Present exactly when `origin == Derived`; explains the derivation.
    derivation: Option<DerivationInfo>,
}

impl EventProvenance {
    /// Builds provenance for an observed/imported/simulated event.
    pub fn new(
        origin: OriginKind,
        source: &str,
        parser_version: VersionLabel,
    ) -> AuditResult<Self> {
        let valid = (1..=64).contains(&source.len())
            && source.chars().all(|c| c.is_ascii_graphic() && c != ' ');
        if !valid {
            return Err(AuditError::invalid_identifier(
                "provenance source",
                "must be 1-64 printable ASCII chars without spaces",
            ));
        }
        Ok(Self {
            origin,
            source: source.to_owned(),
            parser_version,
            derivation: None,
        })
    }

    /// Attaches derivation info (required for derived events).
    pub fn with_derivation(mut self, info: DerivationInfo) -> Self {
        self.derivation = Some(info);
        self
    }

    /// The origin kind.
    pub fn origin(&self) -> OriginKind {
        self.origin
    }

    /// The emitting source label.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The parser version.
    pub fn parser_version(&self) -> &VersionLabel {
        &self.parser_version
    }

    /// The derivation info, if derived.
    pub fn derivation(&self) -> Option<&DerivationInfo> {
        self.derivation.as_ref()
    }
}

/// Deterministic ordering metadata for an event.
///
/// Ordering follows the on-chain hierarchy — ledger, then transaction
/// position within the ledger, then operation index, then event index —
/// never local arrival time. Fields are optional because not every source
/// provides every level; the indexer's ordering module resolves the total
/// order and makes any residual uncertainty explicit.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct EventOrder {
    /// Ledger sequence (Stellar). Events from different ledgers order by
    /// this first.
    pub ledger_sequence: Option<i64>,
    /// Position of the transaction among the ledger's transactions.
    pub transaction_position: Option<u32>,
    /// Zero-based operation index within the transaction.
    pub operation_index: Option<u32>,
    /// Zero-based index of the event within the operation's diagnostics.
    pub event_index: Option<u32>,
}

/// A normalized audit event: the provider-neutral envelope everything
/// downstream consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Deterministic identity derived from stable source identifiers —
    /// never from arrival time. The deduplication key.
    pub event_id: EventId,
    /// What kind of event this is.
    pub kind: EventKind,
    /// Schema version of the envelope itself.
    pub schema_version: u32,
    /// The network the event belongs to.
    pub network: NetworkId,
    /// Where the event came from.
    pub provenance: EventProvenance,
    /// When the underlying activity was observed (ledger close time where
    /// known), if at all.
    pub observed_at: Option<Timestamp>,
    /// Ordering metadata for deterministic sequencing.
    pub order: EventOrder,
    /// The ledger, when the event has on-chain placement.
    pub ledger: Option<LedgerReference>,
    /// The transaction, when known.
    pub transaction: Option<TransactionReference>,
    /// The operation inside the transaction, when known.
    pub operation: Option<OperationReference>,
    /// The token the event concerns, when applicable.
    pub token: Option<TokenReference>,
    /// The initiating actor account, when applicable.
    pub actor: Option<AccountReference>,
    /// The subject account (e.g. the frozen account, or the counterparty),
    /// when applicable.
    pub subject: Option<AccountReference>,
    /// The recorded policy decision, when the event is decision-bearing.
    pub decision: Option<PolicyDecisionReference>,
    /// The recorded enforcement result, when the event passed through hooks.
    pub enforcement: Option<EnforcementResultReference>,
    /// The operation outcome, when the event describes one.
    pub outcome: Option<DecisionResult>,
    /// A machine-readable reason code, when recorded.
    pub reason: Option<ReasonCode>,
    /// Short validated extension details; allowed keys are constrained by
    /// the normalizer so this cannot smuggle arbitrary or protected data.
    pub details: BTreeMap<String, String>,
}

impl AuditEvent {
    /// Builds an envelope with empty optional context. Populate the public
    /// fields, then call [`AuditEvent::finish`] to validate.
    pub fn new(
        event_id: EventId,
        kind: EventKind,
        network: NetworkId,
        provenance: EventProvenance,
    ) -> Self {
        Self {
            event_id,
            kind,
            schema_version: EVENT_SCHEMA_VERSION,
            network,
            provenance,
            observed_at: None,
            order: EventOrder::default(),
            ledger: None,
            transaction: None,
            operation: None,
            token: None,
            actor: None,
            subject: None,
            decision: None,
            enforcement: None,
            outcome: None,
            reason: None,
            details: BTreeMap::new(),
        }
    }

    /// Validates envelope-wide invariants:
    ///
    /// * schema version is supported,
    /// * provenance and kind agree (a `Derived` origin must carry
    ///   derivation info),
    /// * the network is consistent across every reference that names one,
    /// * event ordering components, when present, are coherent
    ///   (operation index implies a transaction).
    pub fn validate(&self) -> AuditResult<()> {
        if self.schema_version != EVENT_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedSchema(format!(
                "event schema version {} is not supported (expected {EVENT_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if self.provenance.origin == OriginKind::Derived && self.provenance.derivation.is_none() {
            return Err(AuditError::InvalidEvent(
                "derived events must carry derivation info".into(),
            ));
        }
        for (label, net) in [
            ("ledger", self.ledger.as_ref().map(|l| l.network())),
            (
                "transaction",
                self.transaction.as_ref().map(|t| t.network()),
            ),
            ("token", self.token.as_ref().map(|t| t.network())),
            ("actor", self.actor.as_ref().map(|a| a.network())),
            ("subject", self.subject.as_ref().map(|s| s.network())),
        ] {
            if let Some(net) = net {
                if net != &self.network {
                    return Err(AuditError::InvalidEvent(format!(
                        "{label} reference is on network `{net}` but the event is on `{}`",
                        self.network
                    )));
                }
            }
        }
        if let Some(op) = &self.operation {
            let tx = self.transaction.as_ref().ok_or_else(|| {
                AuditError::InvalidEvent(
                    "operation reference requires a transaction reference".into(),
                )
            })?;
            if op.transaction() != tx {
                return Err(AuditError::InvalidEvent(
                    "operation reference must match its transaction reference".into(),
                ));
            }
        }
        Ok(())
    }

    /// Canonical JSON bytes for this event — the deterministic input to
    /// record identity and digests.
    pub fn canonical_bytes(&self) -> AuditResult<Vec<u8>> {
        canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{ContractId, NetworkId, TransactionHash};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn parser() -> VersionLabel {
        VersionLabel::new("1.0.0").unwrap()
    }

    fn observed_provenance() -> EventProvenance {
        EventProvenance::new(OriginKind::OnChain, "soroban", parser()).unwrap()
    }

    #[test]
    fn every_kind_round_trips_through_its_wire_string() {
        for kind in EventKind::ALL {
            assert_eq!(EventKind::from_wire(kind.as_str()), Some(*kind));
            let json = serde_json::to_string(kind).unwrap();
            let back: EventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *kind);
        }
        assert_eq!(EventKind::from_wire("not-a-kind"), None);
    }

    #[test]
    fn derived_events_must_carry_derivation_info() {
        let provenance = EventProvenance::new(OriginKind::Derived, "safeguard-audit", parser())
            .unwrap()
            .with_derivation(
                DerivationInfo::new(
                    "failed-tx-analysis",
                    vec![EventId::derive(&["testnet", "tx", "0"])],
                    "reconstructed from the failed transaction",
                )
                .unwrap(),
            );
        let event = AuditEvent::new(
            EventId::derive(&["testnet", "tx", "0", "denied"]),
            EventKind::TransferDenied,
            network(),
            provenance,
        );
        assert!(event.validate().is_ok());
    }

    #[test]
    fn derived_origin_without_info_is_rejected() {
        let event = AuditEvent::new(
            EventId::derive(&["x"]),
            EventKind::TransferDenied,
            network(),
            EventProvenance::new(OriginKind::Derived, "safeguard-audit", parser()).unwrap(),
        );
        assert!(matches!(event.validate(), Err(AuditError::InvalidEvent(_))));
    }

    #[test]
    fn cross_network_references_are_rejected() {
        let other = NetworkId::new(NetworkId::MAINNET).unwrap();
        let tx = TransactionReference::new(other, TransactionHash::new(&"ab".repeat(32)).unwrap());
        let mut event = AuditEvent::new(
            EventId::derive(&["x"]),
            EventKind::TransferAuthorized,
            network(),
            observed_provenance(),
        );
        event.transaction = Some(tx);
        assert!(matches!(event.validate(), Err(AuditError::InvalidEvent(_))));
    }

    #[test]
    fn operation_requires_its_transaction() {
        let tx =
            TransactionReference::new(network(), TransactionHash::new(&"ab".repeat(32)).unwrap());
        let op = OperationReference::new(tx.clone(), 0, Some("invoke_contract")).unwrap();
        let mut event = AuditEvent::new(
            EventId::derive(&["x"]),
            EventKind::TransferAuthorized,
            network(),
            observed_provenance(),
        );
        event.transaction = Some(tx);
        event.operation = Some(op);
        assert!(event.validate().is_ok());

        let mut broken = AuditEvent::new(
            EventId::derive(&["y"]),
            EventKind::TransferAuthorized,
            network(),
            observed_provenance(),
        );
        let orphan = OperationReference::new(
            TransactionReference::new(network(), TransactionHash::new(&"cd".repeat(32)).unwrap()),
            0,
            None,
        )
        .unwrap();
        broken.operation = Some(orphan);
        assert!(broken.validate().is_err());
    }

    #[test]
    fn unsupported_schema_versions_are_rejected() {
        let mut event = AuditEvent::new(
            EventId::derive(&["x"]),
            EventKind::AccountFrozen,
            network(),
            observed_provenance(),
        );
        event.schema_version = 99;
        assert!(matches!(
            event.validate(),
            Err(AuditError::UnsupportedSchema(_))
        ));
    }

    #[test]
    fn canonical_bytes_are_stable_across_detail_insertion_order() {
        let mut a = AuditEvent::new(
            EventId::derive(&["e"]),
            EventKind::TokenBound,
            network(),
            observed_provenance(),
        );
        let token = ContractId::new(&format!("C{}", "A".repeat(55))).unwrap();
        a.token = Some(TokenReference::for_contract(network(), token));

        let mut b = a.clone();
        // Same content, different map insertion order.
        a.details.insert("first".into(), "1".into());
        a.details.insert("second".into(), "2".into());
        b.details.insert("second".into(), "2".into());
        b.details.insert("first".into(), "1".into());
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
        assert_eq!(a, b);
    }
}
