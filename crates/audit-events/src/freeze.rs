//! Freeze-state events: `account_frozen` and `account_unfrozen`.
//!
//! These are the events `safeguard-hooks` actually emits when an account is
//! frozen or unfrozen on a bound token — observed on-chain, never derived.
//! They carry only public addresses; no balances or other protected values
//! exist in the hooks event surface.

use safeguard_audit_core::ContractId;
use safeguard_audit_core::{
    AccountId, AccountReference, AuditEvent, EventKind, NetworkId, TokenReference, VersionLabel,
};

use crate::event_id::{observed_audit_event_base, EventSlot};
use crate::transaction::TransactionContext;
use crate::{EventError, EventResult};

/// An observed freeze-state transition (`account_frozen` or
/// `account_unfrozen`) as emitted by the enforcement hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreezeTransition {
    /// `AccountFrozen` or `AccountUnfrozen`.
    kind: EventKind,
    /// The token contract address (the hook topic's `token`).
    token: String,
    /// The frozen/unfrozen account address (the hook topic's `account`).
    account: String,
}

impl FreezeTransition {
    /// Builds a freeze transition; `kind` must be a freeze kind.
    pub fn new(
        kind: EventKind,
        token: impl Into<String>,
        account: impl Into<String>,
    ) -> EventResult<Self> {
        if !matches!(kind, EventKind::AccountFrozen | EventKind::AccountUnfrozen) {
            return Err(EventError::InvalidFieldValue {
                field: "kind".into(),
                detail: format!("`{kind}` is not a freeze-transition kind"),
            });
        }
        Ok(Self {
            kind,
            token: token.into(),
            account: account.into(),
        })
    }

    /// The freeze kind.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// Projects this observed transition onto the normalized envelope.
    ///
    /// `source` labels the emitting system (e.g. `safeguard-hooks`); the
    /// transaction is required because an observed on-chain event always
    /// has one.
    pub fn into_audit_event(
        &self,
        network: NetworkId,
        source: &str,
        parser: VersionLabel,
        tx: &TransactionContext,
        slot: EventSlot,
    ) -> EventResult<AuditEvent> {
        let token = TokenReference::for_contract(
            network.clone(),
            ContractId::new(&self.token).map_err(|e| EventError::InvalidFieldValue {
                field: "token".into(),
                detail: e.to_string(),
            })?,
        );
        let account = AccountReference::new(
            network.clone(),
            AccountId::new(&self.account).map_err(|e| EventError::InvalidFieldValue {
                field: "account".into(),
                detail: e.to_string(),
            })?,
        );

        let mut event = observed_audit_event_base(self.kind, network, source, parser, tx, slot)?;
        event.token = Some(token);
        event.subject = Some(account);
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{EventKind, NetworkId, OriginKind, Timestamp};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn tx() -> TransactionContext {
        TransactionContext::new(
            network(),
            "ab".repeat(32),
            Some(100),
            Some(Timestamp::from_unix_seconds(1_700_000_000)),
            crate::transaction::TxStatus::Succeeded,
        )
    }

    #[test]
    fn freeze_transitions_project_as_observed_onchain_events() {
        let t = FreezeTransition::new(
            EventKind::AccountFrozen,
            format!("C{}", "A".repeat(55)),
            format!("G{}", "B".repeat(55)),
        )
        .unwrap();
        let event = t
            .into_audit_event(
                network(),
                "safeguard-hooks",
                VersionLabel::new("0.4.0").unwrap(),
                &tx(),
                EventSlot::default(),
            )
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::AccountFrozen);
        assert_eq!(event.provenance.origin(), OriginKind::OnChain);
        assert_eq!(
            event.token.as_ref().unwrap().contract().unwrap().as_str(),
            &format!("C{}", "A".repeat(55))
        );
        assert!(event.subject.is_some());
        assert!(event.transaction.is_some());
    }

    #[test]
    fn only_freeze_kinds_are_accepted() {
        assert!(FreezeTransition::new(EventKind::TokenBound, "t", "a").is_err());
        assert!(FreezeTransition::new(EventKind::AccountFrozen, "t", "a").is_ok());
        assert!(FreezeTransition::new(EventKind::AccountUnfrozen, "t", "a").is_ok());
    }

    #[test]
    fn same_source_transition_derives_same_id() {
        let t = FreezeTransition::new(
            EventKind::AccountFrozen,
            format!("C{}", "A".repeat(55)),
            format!("G{}", "B".repeat(55)),
        )
        .unwrap();
        let a = t
            .into_audit_event(
                network(),
                "safeguard-hooks",
                VersionLabel::new("0.4.0").unwrap(),
                &tx(),
                EventSlot::default(),
            )
            .unwrap();
        let b = t
            .into_audit_event(
                network(),
                "safeguard-hooks",
                VersionLabel::new("0.4.0").unwrap(),
                &tx(),
                EventSlot::default(),
            )
            .unwrap();
        assert_eq!(a.event_id, b.event_id);
    }
}
