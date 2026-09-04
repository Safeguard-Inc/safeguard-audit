//! Sanctions screening events.
//!
//! A sanctions screening result is an *input* to compliance decisions made
//! by `safeguard-policy`, not a decision itself. When the audit layer
//! records that a screening flagged an account or operation, the record is
//! a derived `transfer-flagged`-class event whose derivation names the
//! screening rule — so an investigator can tell *why* something was
//! flagged without the audit layer becoming a screening engine.

use safeguard_audit_core::{
    AccountId, AccountReference, AuditEvent, ContractId, EventKind, NetworkId, TokenReference,
    VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::transaction::TransactionContext;
use crate::{EventError, EventResult};

/// A recorded sanctions-screening flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanctionsFlag {
    /// The token the flag concerns, when applicable.
    pub token: Option<String>,
    /// The flagged account.
    pub account: String,
    /// The rule/feed that produced the flag (e.g. `ofac-list`).
    pub rule: String,
}

impl SanctionsFlag {
    /// Derives the normalized flagged event for this screening result.
    ///
    /// The flag is derived from the screening provider's output and is
    /// recorded as a `transfer-flagged` event scoped to the account, with
    /// the screening rule named in the details so the flag is explainable.
    pub fn into_audit_event(
        &self,
        network: NetworkId,
        source: &str,
        parser: VersionLabel,
        tx: Option<&TransactionContext>,
        slot: EventSlot,
    ) -> EventResult<AuditEvent> {
        let mut refs: Vec<String> = vec![
            format!("account:{}", self.account),
            format!("rule:{}", self.rule),
        ];
        if let Some(token) = &self.token {
            refs.push(format!("token:{token}"));
        }
        let source_refs: Vec<&str> = refs.iter().map(String::as_str).collect();

        let mut event = derived_audit_event_base(
            EventKind::TransferFlagged,
            network,
            source,
            parser,
            DerivationSource {
                method: "sanctions-screening-result",
                note: "sanctions screening flagged the account; recorded for investigation",
                source_refs: &source_refs,
                tx,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event.subject = Some(AccountReference::new(
            event.network.clone(),
            AccountId::new(&self.account).map_err(|e| EventError::InvalidFieldValue {
                field: "account".into(),
                detail: e.to_string(),
            })?,
        ));
        event.details.insert("flag".into(), "sanctions".into());
        event.details.insert("rule".into(), self.rule.clone());
        if let Some(token) = &self.token {
            event.token = Some(TokenReference::for_contract(
                event.network.clone(),
                ContractId::new(token).map_err(|e| EventError::InvalidFieldValue {
                    field: "token".into(),
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
    use safeguard_audit_core::{NetworkId, OriginKind};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn screening_flags_project_as_derived_flagged_events() {
        let flag = SanctionsFlag {
            token: Some(format!("C{}", "A".repeat(55))),
            account: format!("G{}", "B".repeat(55)),
            rule: "ofac-list".into(),
        };
        let event = flag
            .into_audit_event(
                network(),
                "safeguard-policy",
                VersionLabel::new("1.2.0").unwrap(),
                None,
                EventSlot::default(),
            )
            .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::TransferFlagged);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(event.details.get("rule").unwrap(), "ofac-list");
        assert!(event.subject.is_some());
    }
}
