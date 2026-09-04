//! Transfer outcome events.
//!
//! Transfer *authorizations, denials, and flags* are always **derived**
//! events. The enforcement layer deliberately never emits them:
//!
//! * an approval event would be spoofable (any contract can invoke the hook
//!   surface, and Soroban contracts cannot introspect their caller), and
//! * a denial reverts the transaction, and reverts discard events.
//!
//! The audit layer therefore reconstructs outcomes from authoritative
//! transaction metadata (did the operation succeed? which decision does the
//! correlated policy/hook record attribute?) and marks every such event
//! derived, with the reconstruction method named in its provenance.

use safeguard_audit_core::{
    AccountId, AccountReference, AuditEvent, ContractId, DecisionResult,
    EnforcementResultReference, EventKind, NetworkId, ReasonCode, TokenReference, VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::transaction::{OperationPosition, TransactionContext};
use crate::{EventError, EventResult};

/// The reconstructed outcome of one token transfer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    /// The token contract address.
    pub token: String,
    /// The sending account address, when known.
    pub from: Option<String>,
    /// The receiving account address, when known.
    pub to: Option<String>,
    /// The outcome: authorized, denied, or flagged.
    pub outcome: DecisionResult,
    /// Optional machine-readable reason code.
    pub reason: Option<ReasonCode>,
    /// The enforcement hook that processed the operation, when known.
    pub hook: Option<EnforcementResultReference>,
}

impl TransferOutcome {
    /// Maps an outcome onto its normalized event kind.
    pub fn kind(&self) -> EventKind {
        match self.outcome {
            DecisionResult::Allowed => EventKind::TransferAuthorized,
            DecisionResult::Denied => EventKind::TransferDenied,
            DecisionResult::Flagged => EventKind::TransferFlagged,
        }
    }

    /// Derives the normalized audit event for this transfer outcome.
    ///
    /// The transaction is required — an outcome is meaningless without the
    /// transaction it happened in — and the operation position is recorded
    /// so multi-operation transactions stay unambiguous.
    pub fn into_audit_event(
        &self,
        network: NetworkId,
        source: &str,
        parser: VersionLabel,
        tx: &TransactionContext,
        operation: OperationPosition,
        slot: EventSlot,
    ) -> EventResult<AuditEvent> {
        if self.token.is_empty() {
            return Err(EventError::MissingField("token".into()));
        }
        let mut refs: Vec<String> = vec![
            format!("tx:{}", tx.hash),
            format!("op:{}", operation.index),
            format!("token:{}", self.token),
        ];
        if let Some(from) = &self.from {
            refs.push(format!("from:{from}"));
        }
        if let Some(to) = &self.to {
            refs.push(format!("to:{to}"));
        }
        refs.push(format!("outcome:{}", self.outcome.as_str()));
        let source_refs: Vec<&str> = refs.iter().map(String::as_str).collect();

        let mut event = derived_audit_event_base(
            self.kind(),
            network,
            source,
            parser,
            DerivationSource {
                method: "transaction-outcome-analysis",
                note: "transfer outcome reconstructed from the recorded transaction and enforcement decision",
                source_refs: &source_refs,
                tx: Some(tx),
                source_events: Vec::new(),
            },
            slot,
        )?;
        event.outcome = Some(self.outcome);
        event.reason = self.reason.clone();
        event.enforcement = self.hook.clone();
        // Attach the validated operation reference for this transfer.
        let tx_ref = event
            .transaction
            .clone()
            .ok_or_else(|| EventError::MissingField("transaction".into()))?;
        event.operation = Some(
            crate::transaction::operation_reference(&tx_ref, operation, Some("transfer")).map_err(
                |e| EventError::InvalidFieldValue {
                    field: "operation".into(),
                    detail: e.to_string(),
                },
            )?,
        );
        event.token = Some(TokenReference::for_contract(
            event.network.clone(),
            ContractId::new(&self.token).map_err(|e| EventError::InvalidFieldValue {
                field: "token".into(),
                detail: e.to_string(),
            })?,
        ));
        if let Some(from) = &self.from {
            event.actor = Some(AccountReference::new(
                event.network.clone(),
                AccountId::new(from).map_err(|e| EventError::InvalidFieldValue {
                    field: "from".into(),
                    detail: e.to_string(),
                })?,
            ));
        }
        if let Some(to) = &self.to {
            event.subject = Some(AccountReference::new(
                event.network.clone(),
                AccountId::new(to).map_err(|e| EventError::InvalidFieldValue {
                    field: "to".into(),
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
    use safeguard_audit_core::{DecisionResult, NetworkId, OriginKind, Timestamp};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn token() -> String {
        format!("C{}", "A".repeat(55))
    }

    fn tx() -> TransactionContext {
        TransactionContext::new(
            network(),
            "cd".repeat(32),
            Some(77),
            Some(Timestamp::from_unix_seconds(1_700_000_100)),
            crate::transaction::TxStatus::Failed,
        )
    }

    fn denied_outcome() -> TransferOutcome {
        TransferOutcome {
            token: token(),
            from: Some(format!("G{}", "B".repeat(55))),
            to: Some(format!("G{}", "C".repeat(55))),
            outcome: DecisionResult::Denied,
            reason: Some(ReasonCode::new("POLICY_DENIED").unwrap()),
            hook: None,
        }
    }

    #[test]
    fn outcomes_map_onto_kinds() {
        let authorized = TransferOutcome {
            outcome: DecisionResult::Allowed,
            ..denied_outcome()
        };
        let flagged = TransferOutcome {
            outcome: DecisionResult::Flagged,
            ..denied_outcome()
        };
        assert_eq!(authorized.kind(), EventKind::TransferAuthorized);
        assert_eq!(denied_outcome().kind(), EventKind::TransferDenied);
        assert_eq!(flagged.kind(), EventKind::TransferFlagged);
    }

    #[test]
    fn denied_transfers_derive_events_with_derivation_info() {
        let event = denied_outcome()
            .into_audit_event(
                network(),
                "safeguard-audit",
                VersionLabel::new("1.0.0").unwrap(),
                &tx(),
                OperationPosition { index: 0 },
                EventSlot::default(),
            )
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::TransferDenied);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(event.outcome, Some(DecisionResult::Denied));
        assert_eq!(event.reason.as_ref().unwrap().as_str(), "POLICY_DENIED");
        assert!(event.actor.is_some());
        assert!(event.subject.is_some());
        assert_eq!(event.operation.as_ref().unwrap().index(), 0);
        // The transaction status (failed) is framing, not recorded as outcome.
        assert_eq!(event.outcome, Some(DecisionResult::Denied));
    }

    #[test]
    fn duplicate_derivations_are_idempotent() {
        let a = denied_outcome()
            .into_audit_event(
                network(),
                "safeguard-audit",
                VersionLabel::new("1.0.0").unwrap(),
                &tx(),
                OperationPosition { index: 0 },
                EventSlot::default(),
            )
            .unwrap();
        let b = denied_outcome()
            .into_audit_event(
                network(),
                "safeguard-audit",
                VersionLabel::new("1.0.0").unwrap(),
                &tx(),
                OperationPosition { index: 0 },
                EventSlot::default(),
            )
            .unwrap();
        assert_eq!(a.event_id, b.event_id);
    }

    #[test]
    fn empty_tokens_are_rejected() {
        let outcome = TransferOutcome {
            token: String::new(),
            ..denied_outcome()
        };
        assert!(outcome
            .into_audit_event(
                network(),
                "safeguard-audit",
                VersionLabel::new("1").unwrap(),
                &tx(),
                OperationPosition { index: 0 },
                EventSlot::default()
            )
            .is_err());
    }
}
