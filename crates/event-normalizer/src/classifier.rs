//! The classify stage: validated raw forms become normalized envelopes.
//!
//! A [`RawHooksEvent`] is projected onto the provider-neutral
//! [`AuditEvent`]: the kind maps from the hooks type, provenance is
//! stamped as observed-on-chain from the configured emitting source and
//! parser version, placement metadata comes from [`crate::metadata`], and
//! the deterministic event id is derived from the *source identity parts*
//! (network, transaction hash, operation index, event index, kind) — never
//! from arrival time.
//!
//! An already-normalized `audit-envelope` passes through unchanged: its
//! event id is authoritative (re-deriving would break replay), so the
//! classifier only hands it back after validation.
//!
//! Classification adds nothing the raw form did not carry: no invented
//! actor, no invented reason, no reinterpreted values.

use safeguard_audit_core::{
    AccountId, AccountReference, AuditEvent, ContractId, EventProvenance, NetworkId, OriginKind,
    TokenReference, VersionLabel,
};
use safeguard_audit_events::onchain_event_id;

use crate::errors::{NormalizerError, NormalizerResult};
use crate::metadata;
use crate::parser::{ParsedEvent, RawHooksEvent};

/// The pinned configuration classification stamps into every envelope.
///
/// Determinism requires that the *same* raw payload always classifies to
/// the *same* envelope, so the network, the emitting-source label, and
/// the parser version are part of the normalizer's configuration rather
/// than inputs that vary per call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizeConfig {
    /// The network the raw events belong to.
    network: NetworkId,
    /// The emitting source label stamped into provenance (e.g.
    /// `safeguard-hooks`). Validated by [`EventProvenance::new`] on
    /// classify.
    source: String,
    /// The parser version stamped into provenance.
    parser_version: VersionLabel,
}

impl NormalizeConfig {
    /// Builds a normalize configuration.
    pub fn new(
        network: NetworkId,
        source: impl Into<String>,
        parser_version: VersionLabel,
    ) -> Self {
        Self {
            network,
            source: source.into(),
            parser_version,
        }
    }

    /// The configured network.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The configured source label.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The configured parser version.
    pub fn parser_version(&self) -> &VersionLabel {
        &self.parser_version
    }
}

/// Projects a validated raw form onto the normalized envelope.
pub fn classify(config: &NormalizeConfig, parsed: &ParsedEvent) -> NormalizerResult<AuditEvent> {
    match parsed {
        ParsedEvent::HooksState(raw) => classify_hooks(config, raw),
        ParsedEvent::Envelope(raw) => Ok((*raw.event).clone()),
    }
}

fn classify_error(detail: impl Into<String>) -> NormalizerError {
    NormalizerError::ClassificationFailed {
        scheme: "hooks-state-event",
        detail: detail.into(),
    }
}

fn classify_hooks(config: &NormalizeConfig, raw: &RawHooksEvent) -> NormalizerResult<AuditEvent> {
    let kind = raw.hooks_type.to_event_kind();
    let network = config.network().clone();

    // Deterministic identity from stable source parts.
    let event_id = onchain_event_id(
        network.as_str(),
        Some(&raw.transaction_hash),
        Some(raw.operation_index),
        Some(raw.event_index),
        kind,
    )
    .map_err(|e| classify_error(format!("cannot derive event id: {e}")))?;

    let provenance = EventProvenance::new(
        OriginKind::OnChain,
        config.source(),
        config.parser_version().clone(),
    )
    .map_err(|e| classify_error(format!("provenance: {e}")))?;

    let placement = metadata::hooks_placement(raw, network.clone())?;

    let mut event = AuditEvent::new(event_id, kind, network, provenance);
    event.observed_at = Some(placement.observed_at);
    event.order = placement.order;
    event.ledger = Some(placement.ledger);
    event.transaction = Some(placement.transaction);
    event.operation = placement.operation;

    // The token contract the event concerns is always carried.
    let token = ContractId::new(&raw.token).map_err(|e| classify_error(format!("token: {e}")))?;
    event.token = Some(TokenReference::for_contract(event.network.clone(), token));

    match raw.hooks_type {
        t if t.has_account() => {
            // Freeze/unfreeze name their subject account; the actor is not
            // part of the hooks surface and is never invented here.
            let account = raw
                .account
                .as_ref()
                .ok_or_else(|| classify_error("subject account missing after validation"))?;
            let account = AccountId::new(account)
                .map_err(|e| classify_error(format!("subject account: {e}")))?;
            event.subject = Some(AccountReference::new(event.network.clone(), account));
        }
        t if t.has_policy_config() => {
            // Config changes carry the SAC passthrough flag and the newly
            // configured policy address as short detail values, matching
            // the audit-events projection for the same surface.
            if let Some(flag) = raw.sac_passthrough {
                event
                    .details
                    .insert("sac_passthrough".into(), flag.to_string());
            }
            if let Some(policy) = &raw.policy {
                let policy =
                    ContractId::new(policy).map_err(|e| classify_error(format!("policy: {e}")))?;
                event
                    .details
                    .insert("policy_contract".into(), policy.as_str().to_owned());
            }
        }
        _ => {}
    }

    event
        .validate()
        .map_err(|e| classify_error(format!("classified event failed validation: {e}")))?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::scheme::Scheme;
    use crate::validator;
    use safeguard_audit_core::{EventKind, Timestamp};

    const FROZEN_FIXTURE: &str =
        include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");
    const BOUND_FIXTURE: &str =
        include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
    const CONFIG_FIXTURE: &str =
        include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");
    const ENVELOPE_FIXTURE: &str =
        include_str!("../../../fixtures/events/denied-transfer/event.json");

    fn config() -> NormalizeConfig {
        NormalizeConfig::new(
            NetworkId::new(NetworkId::TESTNET).unwrap(),
            "safeguard-hooks",
            VersionLabel::new("1.0.0").unwrap(),
        )
    }

    fn classify_fixture(scheme: Scheme, payload: &str) -> AuditEvent {
        let parsed = parse(scheme, payload).unwrap();
        validator::validate(&parsed).unwrap();
        classify(&config(), &parsed).unwrap()
    }

    #[test]
    fn frozen_event_classifies_as_an_observed_onchain_event() {
        let event = classify_fixture(Scheme::HooksStateEvent, FROZEN_FIXTURE);
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::AccountFrozen);
        assert_eq!(event.provenance.origin(), OriginKind::OnChain);
        assert_eq!(event.provenance.source(), "safeguard-hooks");
        assert_eq!(
            event.observed_at,
            Some(Timestamp::from_unix_seconds(1_700_000_400))
        );
        assert_eq!(event.order.ledger_sequence, Some(423));
        assert_eq!(event.order.operation_index, Some(2));
        assert_eq!(event.order.event_index, Some(0));
        assert!(event.ledger.is_some());
        assert!(event.transaction.is_some());
        assert!(event.operation.is_some());
        assert!(event.token.is_some());
        let subject = event.subject.as_ref().expect("freeze names a subject");
        assert!(subject.account().as_str().starts_with('G'));
        // The event id is the canonical on-chain derivation for these parts.
        let expected = onchain_event_id(
            "testnet",
            Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"),
            Some(2),
            Some(0),
            EventKind::AccountFrozen,
        )
        .unwrap();
        assert_eq!(event.event_id, expected);
    }

    #[test]
    fn bound_event_carries_token_but_no_subject() {
        let event = classify_fixture(Scheme::HooksStateEvent, BOUND_FIXTURE);
        assert_eq!(event.kind, EventKind::TokenBound);
        assert!(event.token.is_some());
        assert!(event.subject.is_none());
        assert!(event.actor.is_none());
    }

    #[test]
    fn config_change_event_carries_details_and_token() {
        let event = classify_fixture(Scheme::HooksStateEvent, CONFIG_FIXTURE);
        assert_eq!(event.kind, EventKind::ConfigurationChanged);
        assert!(event.token.is_some());
        assert_eq!(
            event.details.get("sac_passthrough").map(String::as_str),
            Some("true")
        );
        assert!(event.details.contains_key("policy_contract"));
    }

    #[test]
    fn envelope_scheme_passes_through_unchanged() {
        let parsed = parse(Scheme::AuditEnvelope, ENVELOPE_FIXTURE).unwrap();
        validator::validate(&parsed).unwrap();
        let event = classify(&config(), &parsed).unwrap();
        // The re-ingested envelope keeps its authoritative id and fields.
        let ParsedEvent::Envelope(original) = &parsed else {
            unreachable!()
        };
        assert_eq!(event, *original.event);
    }

    #[test]
    fn classification_is_deterministic_and_idempotent() {
        let a = classify_fixture(Scheme::HooksStateEvent, FROZEN_FIXTURE);
        let b = classify_fixture(Scheme::HooksStateEvent, FROZEN_FIXTURE);
        assert_eq!(a, b);
        assert_eq!(a.event_id, b.event_id);
        // Canonical bytes are identical too — downstream digest stability.
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    }

    #[test]
    fn config_change_never_invents_actor_or_subject() {
        let event = classify_fixture(Scheme::HooksStateEvent, CONFIG_FIXTURE);
        assert!(event.actor.is_none());
        assert!(event.subject.is_none());
        assert!(event.decision.is_none());
        assert!(event.enforcement.is_none());
    }
}
