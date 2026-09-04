//! Policy version change events.
//!
//! The audit layer must correlate recorded decisions with the policy
//! *version* that produced them. When an indexer or operator observes that
//! `safeguard-policy` rotated a version, the change is recorded as a
//! derived `policy-version-changed` event. The event is purely historical
//! bookkeeping: it names the policy contract and the versions observed; it
//! never re-evaluates policy.

use safeguard_audit_core::{AuditEvent, EventKind, NetworkId, VersionLabel};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// An observed policy version rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersionChange {
    /// The network the policy lives on.
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-policy`).
    pub source: String,
    /// Parser/normalizer version producing this event.
    pub parser: VersionLabel,
    /// The policy contract address.
    pub policy: String,
    /// The version observed before the change, when known.
    pub from_version: Option<String>,
    /// The version observed after the change.
    pub to_version: String,
    /// Optional digest of the new policy body (64 lowercase hex chars).
    pub digest: Option<String>,
}

impl PolicyVersionChange {
    /// Derives the normalized `policy-version-changed` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let source_refs = [
            self.policy.as_str(),
            self.from_version.as_deref().unwrap_or("?"),
            self.to_version.as_str(),
        ];
        let mut event = derived_audit_event_base(
            EventKind::PolicyVersionChanged,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "policy-version-observed",
                note: "policy version rotation observed and recorded for historical correlation",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event.details.insert("policy".into(), self.policy.clone());
        if let Some(from) = &self.from_version {
            event.details.insert("from_version".into(), from.clone());
        }
        event
            .details
            .insert("to_version".into(), self.to_version.clone());
        if let Some(digest) = &self.digest {
            if validate_digest(digest) {
                event.details.insert("digest".into(), digest.clone());
            }
        }
        Ok(event)
    }
}

fn validate_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{EventKind, NetworkId, OriginKind};

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn version_changes_project_as_derived_events() {
        let change = PolicyVersionChange {
            network: network(),
            source: "safeguard-policy".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            policy: format!("C{}", "A".repeat(55)),
            from_version: Some("1.1.0".into()),
            to_version: "1.2.0".into(),
            digest: Some("a".repeat(64)),
        };
        let event = change.into_audit_event(EventSlot::default()).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::PolicyVersionChanged);
        assert_eq!(event.provenance.origin(), OriginKind::Derived);
        assert_eq!(event.details.get("to_version").unwrap(), "1.2.0");
        assert_eq!(event.details.get("from_version").unwrap(), "1.1.0");
        assert!(event.details.contains_key("digest"));
    }

    #[test]
    fn malformed_digests_are_dropped_not_stored() {
        let change = PolicyVersionChange {
            network: network(),
            source: "safeguard-policy".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            policy: format!("C{}", "A".repeat(55)),
            from_version: None,
            to_version: "2.0.0".into(),
            digest: Some("not-a-digest".into()),
        };
        let event = change.into_audit_event(EventSlot::default()).unwrap();
        assert!(!event.details.contains_key("digest"));
        assert!(!event.details.contains_key("from_version"));
    }
}
