//! Provider-neutral references used to correlate audit history.
//!
//! An audit record answers "what happened" — but only *in relation to what
//! the system knows*: which token, which accounts, which transaction and
//! operation, which `safeguard-policy` decision, which `safeguard-hooks`
//! enforcement. All of that lives here as typed, validated reference
//! values.
//!
//! ## Boundaries
//!
//! * These are **references**, not state. We never duplicate balances,
//!   policy bodies, or hook logic — only enough identity to point at the
//!   authoritative source.
//! * References are public metadata: network labels, addresses, hashes, and
//!   codes. Protected values (amounts, ciphertexts) never appear here.
//! * No Soroban-specific types leak in: adapters convert protocol data into
//!   these shapes and nothing downstream depends on the adapter.

use serde::{Deserialize, Serialize};

use crate::errors::{AuditError, AuditResult};
use crate::identifiers::{AccountId, ContractId, NetworkId, ReasonCode, TransactionHash};
use crate::timestamps::Timestamp;

/// The outcome a compliance decision reached about an operation.
///
/// `Allowed` and `Denied` are the enforcement-relevant outcomes; `Flagged`
/// marks operations that passed policy but warrant review (e.g. a sanctions
/// rule or an investigation trigger).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionResult {
    /// The operation was permitted.
    Allowed,
    /// The operation was refused.
    Denied,
    /// The operation was permitted but flagged for review.
    Flagged,
}

impl DecisionResult {
    /// The machine-readable code used in reason strings and CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Flagged => "flagged",
        }
    }
}

/// A version label attached to a policy, hook, parser, or software build.
///
/// Versions are short dot-separated labels (`1.2.0`, `v3`, `2026.1`),
/// validated so they can appear in manifests and URLs unescaped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionLabel(String);

impl VersionLabel {
    /// Validates and wraps a version label: 1-32 chars of `[0-9A-Za-z._-]`,
    /// not starting with `-`.
    pub fn new(value: &str) -> AuditResult<Self> {
        let valid = (1..=32).contains(&value.len())
            && !value.starts_with('-')
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(AuditError::invalid_identifier(
                "version label",
                "must be 1-32 chars of [0-9A-Za-z._-], not starting with '-'",
            ))
        }
    }

    /// The label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VersionLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A ledger on a network: sequence plus the network's close time.
///
/// `sequence` follows Stellar's ledger sequence semantics (positive
/// integers starting at 1 on genesis).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReference {
    network: NetworkId,
    sequence: i64,
    close_time: Option<Timestamp>,
}

impl LedgerReference {
    /// Builds a ledger reference. `sequence` must be positive.
    pub fn new(
        network: NetworkId,
        sequence: i64,
        close_time: Option<Timestamp>,
    ) -> AuditResult<Self> {
        if sequence < 1 {
            return Err(AuditError::invalid_identifier(
                "ledger sequence",
                format!("sequence {sequence} must be >= 1"),
            ));
        }
        Ok(Self {
            network,
            sequence,
            close_time,
        })
    }

    /// The network this ledger belongs to.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The ledger sequence number.
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The ledger close time, when the source provided it.
    pub fn close_time(&self) -> Option<Timestamp> {
        self.close_time
    }
}

/// A transaction on a network, identified by its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReference {
    network: NetworkId,
    hash: TransactionHash,
}

impl TransactionReference {
    /// Builds a transaction reference.
    pub fn new(network: NetworkId, hash: TransactionHash) -> Self {
        Self { network, hash }
    }

    /// The network the transaction was submitted to.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The transaction hash.
    pub fn hash(&self) -> &TransactionHash {
        &self.hash
    }
}

/// A single operation inside a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReference {
    transaction: TransactionReference,
    index: u32,
    op_type: Option<String>,
}

impl OperationReference {
    /// Builds an operation reference with an optional operation type label
    /// (e.g. `"invoke_contract"`). The label is descriptive metadata only;
    /// adapters own the authoritative mapping.
    pub fn new(
        transaction: TransactionReference,
        index: u32,
        op_type: Option<&str>,
    ) -> AuditResult<Self> {
        let op_type = op_type.map(str::to_owned);
        if let Some(t) = &op_type {
            let valid = (1..=64).contains(&t.len()) && t.chars().all(|c| c.is_ascii_graphic());
            if !valid {
                return Err(AuditError::invalid_identifier(
                    "operation type",
                    "must be 1-64 printable ASCII chars",
                ));
            }
        }
        Ok(Self {
            transaction,
            index,
            op_type,
        })
    }

    /// The containing transaction.
    pub fn transaction(&self) -> &TransactionReference {
        &self.transaction
    }

    /// The zero-based operation index within the transaction.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The operation type label, if known.
    pub fn op_type(&self) -> Option<&str> {
        self.op_type.as_deref()
    }
}

/// An account on a network (a party to an audited operation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReference {
    network: NetworkId,
    account: AccountId,
}

impl AccountReference {
    /// Builds an account reference.
    pub fn new(network: NetworkId, account: AccountId) -> Self {
        Self { network, account }
    }

    /// The network the account lives on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The account address.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
}

/// A contract on a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractReference {
    network: NetworkId,
    contract: ContractId,
}

impl ContractReference {
    /// Builds a contract reference.
    pub fn new(network: NetworkId, contract: ContractId) -> Self {
        Self { network, contract }
    }

    /// The network the contract is deployed on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The contract address.
    pub fn contract(&self) -> &ContractId {
        &self.contract
    }
}

/// A token: a Soroban confidential-token contract, or (for classic assets)
/// an asset code plus issuer.
///
/// A token is identified either by its contract address (the Soroban case)
/// or by the classic `asset_code`/`issuer` pair. The `TokenReference`
/// carries whichever shape the source provided; nothing downstream assumes
/// one over the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenReference {
    network: NetworkId,
    contract: Option<ContractId>,
    asset_code: Option<String>,
    issuer: Option<AccountId>,
}

impl TokenReference {
    /// References a Soroban token by its contract.
    pub fn for_contract(network: NetworkId, contract: ContractId) -> Self {
        Self {
            network,
            contract: Some(contract),
            asset_code: None,
            issuer: None,
        }
    }

    /// References a classic asset by code and issuer.
    pub fn for_classic_asset(
        network: NetworkId,
        asset_code: &str,
        issuer: AccountId,
    ) -> AuditResult<Self> {
        let valid = (1..=12).contains(&asset_code.len())
            && asset_code.chars().all(|c| c.is_ascii_alphanumeric());
        if !valid {
            return Err(AuditError::invalid_identifier(
                "asset code",
                "must be 1-12 alphanumeric chars",
            ));
        }
        Ok(Self {
            network,
            contract: None,
            asset_code: Some(asset_code.to_owned()),
            issuer: Some(issuer),
        })
    }

    /// The network the token lives on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The Soroban contract address, when this is a contract token.
    pub fn contract(&self) -> Option<&ContractId> {
        self.contract.as_ref()
    }

    /// The classic asset code, when this is a classic asset.
    pub fn asset_code(&self) -> Option<&str> {
        self.asset_code.as_deref()
    }

    /// The classic asset issuer, when this is a classic asset.
    pub fn issuer(&self) -> Option<&AccountId> {
        self.issuer.as_ref()
    }

    /// A stable reference string for display and correlation.
    pub fn display(&self) -> String {
        match (&self.contract, &self.asset_code) {
            (Some(c), _) => format!("{}:contract:{}", self.network, c),
            (None, Some(code)) => {
                let issuer = self
                    .issuer
                    .as_ref()
                    .map(|i| i.as_str())
                    .unwrap_or("unknown");
                format!("{}:asset:{}:{}", self.network, code, issuer)
            }
            (None, None) => format!("{}:asset:unknown", self.network),
        }
    }
}

/// Which version of a policy produced a decision.
///
/// A policy reference is **historical**: it names the policy and version
/// that actually produced a recorded decision. Nothing here re-evaluates
/// policy — audit history represents what was decided, and replay
/// verification is an explicit, separate operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReference {
    /// The policy contract/address that owns the policy.
    policy: ContractId,
    /// The policy version that was in force.
    version: VersionLabel,
    /// Optional SHA-256 digest of the policy body at that version.
    digest: Option<String>,
}

impl PolicyReference {
    /// Builds a policy reference.
    pub fn new(policy: ContractId, version: VersionLabel) -> Self {
        Self {
            policy,
            version,
            digest: None,
        }
    }

    /// Attaches an optional policy-body digest (64 lowercase hex chars).
    pub fn with_digest(mut self, digest: impl Into<Option<String>>) -> AuditResult<Self> {
        if let Some(d) = digest.into() {
            if !is_sha256_hex(&d) {
                return Err(AuditError::invalid_identifier(
                    "policy digest",
                    "must be 64 lowercase hex chars",
                ));
            }
            self.digest = Some(d);
        }
        Ok(self)
    }

    /// The policy address.
    pub fn policy(&self) -> &ContractId {
        &self.policy
    }

    /// The policy version.
    pub fn version(&self) -> &VersionLabel {
        &self.version
    }

    /// The optional policy-body digest.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// A recorded compliance decision: the policy reference plus its result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionReference {
    /// The policy reference that produced the decision.
    policy: PolicyReference,
    /// The decision itself.
    result: DecisionResult,
    /// Machine-readable reason code (e.g. `POLICY_DENIED`, `FROZEN_ACCOUNT`).
    reason: Option<ReasonCode>,
    /// When the decision was made (ledger time where known).
    decided_at: Option<Timestamp>,
}

impl PolicyDecisionReference {
    /// Builds a policy decision reference.
    pub fn new(policy: PolicyReference, result: DecisionResult) -> Self {
        Self {
            policy,
            result,
            reason: None,
            decided_at: None,
        }
    }

    /// Attaches a machine-readable reason code.
    pub fn with_reason(mut self, reason: ReasonCode) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Attaches the decision time.
    pub fn with_decided_at(mut self, at: Timestamp) -> Self {
        self.decided_at = Some(at);
        self
    }

    /// The policy reference.
    pub fn policy(&self) -> &PolicyReference {
        &self.policy
    }

    /// The decision result.
    pub fn result(&self) -> DecisionResult {
        self.result
    }

    /// The reason code, when the source recorded one.
    pub fn reason(&self) -> Option<&ReasonCode> {
        self.reason.as_ref()
    }

    /// When the decision was made.
    pub fn decided_at(&self) -> Option<Timestamp> {
        self.decided_at
    }
}

/// A reference to the `safeguard-hooks` enforcement that processed an
/// operation: which hook version ran and what it decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementResultReference {
    /// Stable identifier of the enforcement hook (e.g. a contract address
    /// or a configured hook name).
    hook: String,
    /// The hook software version that produced the result.
    hook_version: VersionLabel,
    /// What the enforcement layer decided.
    result: DecisionResult,
    /// Optional reason code surfaced by the hook.
    reason: Option<ReasonCode>,
}

impl EnforcementResultReference {
    /// Builds an enforcement result reference.
    pub fn new(
        hook: &str,
        hook_version: VersionLabel,
        result: DecisionResult,
    ) -> AuditResult<Self> {
        let valid = (1..=128).contains(&hook.len()) && hook.chars().all(|c| c.is_ascii_graphic());
        if !valid {
            return Err(AuditError::invalid_identifier(
                "hook identifier",
                "must be 1-128 printable ASCII chars",
            ));
        }
        Ok(Self {
            hook: hook.to_owned(),
            hook_version,
            result,
            reason: None,
        })
    }

    /// Attaches a machine-readable reason code.
    pub fn with_reason(mut self, reason: ReasonCode) -> Self {
        self.reason = Some(reason);
        self
    }

    /// The hook identifier.
    pub fn hook(&self) -> &str {
        &self.hook
    }

    /// The hook version.
    pub fn hook_version(&self) -> &VersionLabel {
        &self.hook_version
    }

    /// The enforcement result.
    pub fn result(&self) -> DecisionResult {
        self.result
    }

    /// The reason code, when recorded.
    pub fn reason(&self) -> Option<&ReasonCode> {
        self.reason.as_ref()
    }
}

/// Whether a string is 64 lowercase hex chars (a SHA-256 digest shape).
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{AccountId, ContractId, NetworkId, ReasonCode, TransactionHash};

    fn testnet() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn version_labels_validate() {
        assert!(VersionLabel::new("1.2.0").is_ok());
        assert!(VersionLabel::new("v3").is_ok());
        assert!(VersionLabel::new("-bad").is_err());
        assert!(VersionLabel::new("has space").is_err());
        assert!(VersionLabel::new(&"x".repeat(33)).is_err());
    }

    #[test]
    fn ledger_sequences_must_be_positive() {
        let t = Timestamp::from_unix_seconds(1000);
        assert!(LedgerReference::new(testnet(), 1, Some(t)).is_ok());
        assert!(LedgerReference::new(testnet(), 0, None).is_err());
    }

    #[test]
    fn operation_references_validate() {
        let tx =
            TransactionReference::new(testnet(), TransactionHash::new(&"ab".repeat(32)).unwrap());
        let op = OperationReference::new(tx.clone(), 2, Some("invoke_contract")).unwrap();
        assert_eq!(op.index(), 2);
        assert_eq!(op.transaction(), &tx);
        assert!(OperationReference::new(tx, 0, Some("bad label!")).is_err());
    }

    #[test]
    fn token_references_carry_either_shape() {
        let contract = ContractId::new(&format!("C{}", "A".repeat(55))).unwrap();
        let token = TokenReference::for_contract(testnet(), contract.clone());
        assert_eq!(token.contract(), Some(&contract));
        assert_eq!(token.asset_code(), None);
        let issuer = AccountId::new(&format!("G{}", "A".repeat(55))).unwrap();
        let classic = TokenReference::for_classic_asset(testnet(), "USD", issuer.clone()).unwrap();
        assert_eq!(classic.asset_code(), Some("USD"));
        assert!(
            TokenReference::for_classic_asset(testnet(), "TOO LONG CODE", issuer.clone()).is_err()
        );
        assert!(TokenReference::for_classic_asset(testnet(), "US$", issuer.clone()).is_err());
        assert!(token.display().contains("contract:"));
        assert!(classic.display().contains("asset:USD:"));
    }

    #[test]
    fn policy_references_are_historical() {
        let policy = ContractId::new(&format!("C{}", "B".repeat(55))).unwrap();
        let v = PolicyReference::new(policy.clone(), VersionLabel::new("2.1").unwrap());
        let with_hash = v.clone().with_digest(Some("a".repeat(64))).unwrap();
        assert_eq!(with_hash.policy(), &policy);
        assert!(v.clone().with_digest(Some("zz".repeat(32))).is_err());

        let decision = PolicyDecisionReference::new(v.clone(), DecisionResult::Denied)
            .with_reason(ReasonCode::new("POLICY_DENIED").unwrap());
        assert_eq!(decision.result(), DecisionResult::Denied);
        assert_eq!(decision.reason().unwrap().as_str(), "POLICY_DENIED");
        assert_eq!(decision.policy().version().as_str(), "2.1");
    }

    #[test]
    fn enforcement_references_name_hook_and_version() {
        let result = EnforcementResultReference::new(
            "safeguard-hooks",
            VersionLabel::new("0.4.0").unwrap(),
            DecisionResult::Allowed,
        )
        .unwrap()
        .with_reason(ReasonCode::new("OK").unwrap());
        assert_eq!(result.hook(), "safeguard-hooks");
        assert_eq!(result.hook_version().as_str(), "0.4.0");
        assert!(EnforcementResultReference::new(
            "",
            VersionLabel::new("1").unwrap(),
            DecisionResult::Allowed
        )
        .is_err());
    }

    #[test]
    fn decision_result_labels_are_stable() {
        assert_eq!(DecisionResult::Allowed.as_str(), "allowed");
        assert_eq!(DecisionResult::Denied.as_str(), "denied");
        assert_eq!(DecisionResult::Flagged.as_str(), "flagged");
        // kebab-case serde keeps wire names stable.
        assert_eq!(
            serde_json::to_string(&DecisionResult::Denied).unwrap(),
            "\"denied\""
        );
    }
}
