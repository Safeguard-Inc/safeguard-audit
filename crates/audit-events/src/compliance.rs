//! Compliance events: configuration changes observed from the enforcement
//! hook, and standalone compliance decisions recorded by the audit layer.
//!
//! * `ComplianceConfigChanged` mirrors the hooks event of the same name
//!   (`configuration-changed` normalized kind): the enforcement hook
//!   publishes it whenever its compliance configuration (policy address,
//!   SAC passthrough) is written or rotated.
//! * `ComplianceDecision` is a derived event recording a policy decision
//!   that was *observed*, not emitted — policy decisions are made by
//!   `safeguard-policy` and applied by `safeguard-hooks`; the audit layer
//!   only records the decision it can attribute. Transfer-level outcomes
//!   belong to `transfer.rs`; this type covers decisions about an account,
//!   token, or configuration that are not a single transfer.

use safeguard_audit_core::{
    AccountId, AccountReference, AuditEvent, ContractId, DecisionResult, EventKind, NetworkId,
    ReasonCode, TokenReference, VersionLabel,
};

use crate::event_id::{
    derived_audit_event_base, observed_audit_event_base, DerivationSource, EventSlot,
};
use crate::transaction::TransactionContext;
use crate::{EventError, EventResult};

/// An observed `compliance_config_changed` event from the enforcement hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceConfigChanged {
    /// The configured policy address after the change (`None` = disabled).
    pub policy: Option<String>,
    /// The SAC-passthrough flag after the change.
    pub sac_passthrough: bool,
}

impl ComplianceConfigChanged {
    /// Projects the observed config change onto the normalized envelope.
    pub fn into_audit_event(
        &self,
        network: NetworkId,
        source: &str,
        parser: VersionLabel,
        tx: &TransactionContext,
        slot: EventSlot,
    ) -> EventResult<AuditEvent> {
        let mut event = observed_audit_event_base(
            EventKind::ConfigurationChanged,
            network,
            source,
            parser,
            tx,
            slot,
        )?;
        event
            .details
            .insert("sac_passthrough".into(), self.sac_passthrough.to_string());
        if let Some(policy) = &self.policy {
            let policy = ContractId::new(policy).map_err(|e| EventError::InvalidFieldValue {
                field: "policy".into(),
                detail: e.to_string(),
            })?;
            event
                .details
                .insert("policy_contract".into(), policy.as_str().to_owned());
        }
        Ok(event)
    }
}

/// A standalone compliance decision observed off-chain and recorded as a
/// derived `compliance-decision` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceDecision {
    /// The token the decision concerns, when applicable.
    pub token: Option<String>,
    /// The account the decision concerns, when applicable.
    pub account: Option<String>,
    /// The decision itself.
    pub decision: DecisionResult,
    /// Optional machine-readable reason code.
    pub reason: Option<ReasonCode>,
}

impl ComplianceDecision {
    /// Derives the normalized event for this decision.
    ///
    /// Decisions are derived (never emitted by the hook surface), so the
    /// projection carries derivation info naming the method and the source
    /// material. The transaction context is optional: not every decision is
    /// tied to a transaction.
    pub fn into_audit_event(
        &self,
        network: NetworkId,
        source: &str,
        parser: VersionLabel,
        tx: Option<&TransactionContext>,
        slot: EventSlot,
    ) -> EventResult<AuditEvent> {
        let mut refs: Vec<String> = Vec::new();
        if let Some(token) = &self.token {
            refs.push(format!("token:{token}"));
        }
        if let Some(account) = &self.account {
            refs.push(format!("account:{account}"));
        }
        refs.push(format!("decision:{}", self.decision.as_str()));
        if let Some(r) = &self.reason {
            refs.push(format!("reason:{r}"));
        }
        let source_refs: Vec<&str> = refs.iter().map(String::as_str).collect();

        let mut event = derived_audit_event_base(
            EventKind::ComplianceDecision,
            network,
            source,
            parser,
            DerivationSource {
                method: "observed-decision",
                note: "compliance decision recorded from an authorized observer",
                source_refs: &source_refs,
                tx,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event.outcome = Some(self.decision);
        event.reason = self.reason.clone();
        if let Some(token) = &self.token {
            event.token = Some(TokenReference::for_contract(
                event.network.clone(),
                ContractId::new(token).map_err(|e| EventError::InvalidFieldValue {
                    field: "token".into(),
                    detail: e.to_string(),
                })?,
            ));
        }
        if let Some(account) = &self.account {
            event.subject = Some(AccountReference::new(
                event.network.clone(),
                AccountId::new(account).map_err(|e| EventError::InvalidFieldValue {
                    field: "account".into(),
                    detail: e.to_string(),
                })?,
            ));
        }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{NetworkId, OriginKind, Timestamp};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn tx() -> TransactionContext {
        TransactionContext::new(
            network(),
            "ab".repeat(32),
            Some(10),
            Some(Timestamp::from_unix_seconds(1_700_000_000)),
            crate::transaction::TxStatus::Succeeded,
        )
    }

    #[test]
    fn config_changes_project_with_details() {
        let change = ComplianceConfigChanged {
            policy: Some(format!("C{}", "A".repeat(55))),
            sac_passthrough: true,
        };
        let event = change
            .into_audit_event(
                network(),
                "safeguard-hooks",
                VersionLabel::new("0.4.0").unwrap(),
                &tx(),
                EventSlot::default(),
            )
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::ConfigurationChanged);
        assert_eq!(event.provenance.origin(), OriginKind::OnChain);
        assert_eq!(event.details.get("sac_passthrough").unwrap(), "true");
        assert!(event.details.contains_key("policy_contract"));
    }

    #[test]
    fn decisions_derive_with_provenance() {
        let decision = ComplianceDecision {
            token: Some(format!("C{}", "A".repeat(55))),
            account: Some(format!("G{}", "B".repeat(55))),
            decision: DecisionResult::Denied,
            reason: Some(ReasonCode::new("POLICY_DENIED").unwrap()),
        };
        let event = decision
            .into_audit_event(
                network(),
                "safeguard-audit",
                VersionLabel::new("1.0.0").unwrap(),
                Some(&tx()),
                EventSlot::default(),
            )
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::ComplianceDecision);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(event.outcome, Some(DecisionResult::Denied));
        assert!(event.provenance.derivation().is_some());
    }
}
