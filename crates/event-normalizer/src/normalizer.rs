//! The `Normalizer` service: one deterministic function per raw item.
//!
//! The indexer feeds [`RawEventItem`]s in; the normalizer runs the whole
//! pipeline on each — resolve the scheme, parse, validate, classify — and
//! returns a [`NormalizedEvent`]: the normalized envelope plus the item's
//! stable source position (so the indexer can checkpoint) and the scheme
//! that produced it (so provenance stays transparent).
//!
//! The service is stateless and deterministic by construction: it holds
//! only the pinned [`NormalizeConfig`] (network, emitting source, parser
//! version) and every stage is a pure function of (config, item). The same
//! item always normalizes to the same envelope with the same event id —
//! which is what makes the downstream deduplication and replay rules
//! sound.
//!
//! [`RawEventItem`]: safeguard_audit_core::RawEventItem

use std::str::FromStr;

use safeguard_audit_core::{AuditEvent, RawEventItem};

use crate::classifier::{classify, NormalizeConfig};
use crate::errors::{NormalizerError, NormalizerResult};
use crate::parser::parse;
use crate::scheme::Scheme;
use crate::validator;

/// One normalized item: the envelope plus the source position and scheme
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    /// The normalized envelope, ready for deduplication and storage.
    pub event: AuditEvent,
    /// The scheme that produced it.
    pub scheme: Scheme,
    /// The raw item's stable source position (the indexer's checkpoint
    /// key), carried through untouched.
    pub position: String,
}

/// The normalization service.
///
/// Cheap to construct and clone; one instance per (network, source,
/// parser version) combination is the expected usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalizer {
    config: NormalizeConfig,
}

impl Normalizer {
    /// Builds a normalizer pinned to `config`.
    pub fn new(config: NormalizeConfig) -> Self {
        Self { config }
    }

    /// The pinned configuration.
    pub fn config(&self) -> &NormalizeConfig {
        &self.config
    }

    /// Normalizes one raw item.
    ///
    /// The returned envelope is fully validated; `Err` names the stage
    /// that rejected the item (unsupported scheme, unsupported version,
    /// malformed or invalid payload, classification failure) so the
    /// caller can react to the kind of failure.
    pub fn normalize(&self, item: &RawEventItem) -> NormalizerResult<NormalizedEvent> {
        let scheme = Scheme::from_str(item.scheme())
            .map_err(|()| NormalizerError::UnsupportedScheme(item.scheme().to_owned()))?;

        let parsed = parse(scheme, item.payload())?;
        validator::validate(&parsed)?;
        let event = classify(&self.config, &parsed)?;

        // The classified envelope must land on the configured network. An
        // envelope scheme carrying a different network is a cross-network
        // import, which belongs to a different ingestion path — never a
        // silent mix inside one normalizer instance.
        if event.network != *self.config.network() {
            return Err(NormalizerError::ValidationFailed {
                scheme: scheme.as_label(),
                detail: format!(
                    "payload is on network `{}` but the normalizer is pinned to `{}`",
                    event.network,
                    self.config.network()
                ),
            });
        }

        Ok(NormalizedEvent {
            event,
            scheme,
            position: item.position().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        EventKind, EventSource, NetworkId, OriginKind, SourcePage, SourceResult, VersionLabel,
    };

    const FROZEN_FIXTURE: &str =
        include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");
    const ENVELOPE_FIXTURE: &str =
        include_str!("../../../fixtures/events/denied-transfer/event.json");

    fn normalizer() -> Normalizer {
        Normalizer::new(NormalizeConfig::new(
            NetworkId::new(NetworkId::TESTNET).unwrap(),
            "safeguard-hooks",
            VersionLabel::new("1.0.0").unwrap(),
        ))
    }

    fn item(scheme: &str, payload: &str, position: &str) -> RawEventItem {
        RawEventItem::new(scheme, payload, position).unwrap()
    }

    #[test]
    fn hooks_fixture_normalizes_to_a_valid_envelope() {
        let out = normalizer()
            .normalize(&item(
                "hooks-state-event",
                FROZEN_FIXTURE,
                "ledger:423:tx:0",
            ))
            .unwrap();
        assert!(out.event.validate().is_ok());
        assert_eq!(out.event.kind, EventKind::AccountFrozen);
        assert_eq!(out.event.provenance.origin(), OriginKind::OnChain);
        assert_eq!(out.position, "ledger:423:tx:0");
        assert_eq!(out.scheme, Scheme::HooksStateEvent);
    }

    #[test]
    fn normalization_is_deterministic_for_the_same_item() {
        let n = normalizer();
        let raw = item("hooks-state-event", FROZEN_FIXTURE, "ledger:423");
        let a = n.normalize(&raw).unwrap();
        let b = n.normalize(&raw).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn same_payload_different_positions_still_normalize_identically() {
        // The position is checkpoint metadata, not identity: an event
        // served at two source positions must normalize to the same
        // envelope and event id, or replay could never deduplicate.
        let n = normalizer();
        let a = n
            .normalize(&item("hooks-state-event", FROZEN_FIXTURE, "pos-1"))
            .unwrap();
        let b = n
            .normalize(&item("hooks-state-event", FROZEN_FIXTURE, "pos-2"))
            .unwrap();
        assert_eq!(a.event, b.event);
        assert_eq!(a.event.event_id, b.event.event_id);
        assert_ne!(a.position, b.position);
    }

    #[test]
    fn envelope_reingest_keeps_its_authoritative_identity() {
        let out = normalizer()
            .normalize(&item("audit-envelope", ENVELOPE_FIXTURE, "backfill:1"))
            .unwrap();
        assert_eq!(out.scheme, Scheme::AuditEnvelope);
        assert!(out.event.validate().is_ok());
        // The id inside the payload is authoritative and preserved.
        let expected = serde_json::from_str::<AuditEvent>(ENVELOPE_FIXTURE).unwrap();
        assert_eq!(out.event.event_id, expected.event_id);
    }

    #[test]
    fn unknown_schemes_fail_as_unsupported() {
        assert!(matches!(
            normalizer().normalize(&item("rpc-events", FROZEN_FIXTURE, "p")),
            Err(NormalizerError::UnsupportedScheme(s)) if s == "rpc-events"
        ));
    }

    #[test]
    fn malformed_payloads_fail_without_panicking() {
        let out = normalizer().normalize(&item("hooks-state-event", "{ nope", "p"));
        assert!(matches!(out, Err(NormalizerError::MalformedPayload { .. })));
    }

    #[test]
    fn cross_network_envelopes_are_rejected() {
        let event = serde_json::from_str::<AuditEvent>(ENVELOPE_FIXTURE).unwrap();
        let mainnet = serde_json::to_string(&event).unwrap().replacen(
            "\"network\":\"testnet\"",
            "\"network\":\"mainnet\"",
            1,
        );
        let cross = item("audit-envelope", &mainnet, "p");
        assert!(normalizer().normalize(&cross).is_err());
    }

    #[test]
    fn integration_with_an_event_source_end_to_end() {
        // A tiny source yielding the committed fixture, normalized through
        // the same door an indexer uses.
        struct OneShot {
            served: bool,
        }
        impl EventSource for OneShot {
            type Error = safeguard_audit_core::SourceError;
            fn source_name(&self) -> &str {
                "fixture:frozen"
            }
            fn fetch_after(
                &mut self,
                after: Option<&str>,
                _limit: usize,
            ) -> SourceResult<SourcePage> {
                if self.served {
                    return Ok(SourcePage::end());
                }
                if after.is_some() {
                    return Err(safeguard_audit_core::SourceError::InvalidPosition(
                        "already drained".into(),
                    ));
                }
                self.served = true;
                let raw =
                    RawEventItem::new("hooks-state-event", FROZEN_FIXTURE, "fixture:0").unwrap();
                Ok(SourcePage::new(vec![raw], None))
            }
        }

        let mut source = OneShot { served: false };
        let page = source.fetch_after(None, 10).unwrap();
        assert_eq!(page.items().len(), 1);
        let out = normalizer().normalize(&page.items()[0]).unwrap();
        assert_eq!(out.event.kind, EventKind::AccountFrozen);
    }

    #[test]
    fn scheme_labels_round_trip() {
        assert_eq!(
            Scheme::from_str("hooks-state-event").unwrap(),
            Scheme::HooksStateEvent
        );
        assert_eq!(
            Scheme::from_str("audit-envelope").unwrap(),
            Scheme::AuditEnvelope
        );
        assert!(Scheme::from_str("nope").is_err());
    }
}
