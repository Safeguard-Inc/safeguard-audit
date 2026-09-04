//! Per-scheme payload parsers: raw JSON becomes typed raw forms.
//!
//! The parser is the *decode* stage and nothing more. It turns the
//! payload text of a known scheme into a typed structural form, checking
//! that the payload is JSON and that it carries exactly the fields its
//! scheme defines (unknown fields are rejected rather than silently
//! dropped, so decoding can never change semantic values). Whether the
//! decoded values are *sensible* — a real identifier shape, a supported
//! hooks type, a coherent placement — is the validator's job, not this
//! module's.
//!
//! ## Determinism
//!
//! Parsing is a pure function of (scheme, payload text): the same payload
//! always decodes to the same typed form, with no clocks, randomness, or
//! environment input anywhere in this module.

use serde_json::Value;

use safeguard_audit_core::{AuditEvent, EventKind};

use crate::errors::{NormalizerError, NormalizerResult};
use crate::scheme::Scheme;

/// The on-chain state events `safeguard-hooks` can emit.
///
/// This mirrors the hook surface exactly; anything outside it is rejected
/// rather than guessed at. The variant name maps 1:1 onto the payload's
/// `type` string and onto a normalized [`EventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HooksType {
    /// `account_frozen`
    AccountFrozen,
    /// `account_unfrozen`
    AccountUnfrozen,
    /// `token_bound`
    TokenBound,
    /// `token_unbound`
    TokenUnbound,
    /// `compliance_config_changed`
    ComplianceConfigChanged,
}

impl HooksType {
    /// The payload's `type` string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountFrozen => "account_frozen",
            Self::AccountUnfrozen => "account_unfrozen",
            Self::TokenBound => "token_bound",
            Self::TokenUnbound => "token_unbound",
            Self::ComplianceConfigChanged => "compliance_config_changed",
        }
    }

    /// Parses a payload `type` string, if supported.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "account_frozen" => Self::AccountFrozen,
            "account_unfrozen" => Self::AccountUnfrozen,
            "token_bound" => Self::TokenBound,
            "token_unbound" => Self::TokenUnbound,
            "compliance_config_changed" => Self::ComplianceConfigChanged,
            _ => return None,
        })
    }

    /// The normalized kind this hooks event projects onto.
    pub fn to_event_kind(self) -> EventKind {
        match self {
            Self::AccountFrozen => EventKind::AccountFrozen,
            Self::AccountUnfrozen => EventKind::AccountUnfrozen,
            Self::TokenBound => EventKind::TokenBound,
            Self::TokenUnbound => EventKind::TokenUnbound,
            Self::ComplianceConfigChanged => EventKind::ConfigurationChanged,
        }
    }

    /// Whether this hooks event type names a subject account.
    pub fn has_account(self) -> bool {
        matches!(self, Self::AccountFrozen | Self::AccountUnfrozen)
    }

    /// Whether this hooks event type carries a policy configuration.
    pub fn has_policy_config(self) -> bool {
        matches!(self, Self::ComplianceConfigChanged)
    }

    /// All supported hooks event types.
    pub const ALL: &'static [HooksType] = &[
        Self::AccountFrozen,
        Self::AccountUnfrozen,
        Self::TokenBound,
        Self::TokenUnbound,
        Self::ComplianceConfigChanged,
    ];
}

impl std::fmt::Display for HooksType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The decoded form of a `hooks-state-event` v1 payload.
///
/// Values are still raw strings and numbers; identifier-format checks
/// belong to the validator. Type-dependent fields are optional here and
/// their presence is enforced per type by the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHooksEvent {
    /// Which hooks state event this is.
    pub hooks_type: HooksType,
    /// The token contract address the event concerns.
    pub token: String,
    /// The subject account (freeze/unfreeze events only).
    pub account: Option<String>,
    /// The configured policy contract (config-change events only).
    pub policy: Option<String>,
    /// The SAC-passthrough flag (config-change events only).
    pub sac_passthrough: Option<bool>,
    /// The ledger sequence the event was observed in.
    pub ledger: i64,
    /// The ledger close time in Unix seconds.
    pub close_time: i64,
    /// The 64-hex-char transaction hash.
    pub transaction_hash: String,
    /// The operation index within the transaction.
    pub operation_index: u32,
    /// The event index within the operation.
    pub event_index: u32,
}

/// The decoded form of an `audit-envelope` v1 payload: an already
/// normalized envelope, validated again on the way in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEnvelope {
    /// The re-ingested envelope.
    pub event: Box<AuditEvent>,
}

/// The result of the parse stage: a typed raw form per scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    /// A decoded `hooks-state-event` payload.
    HooksState(RawHooksEvent),
    /// A decoded `audit-envelope` payload.
    Envelope(RawEnvelope),
}

/// The exact top-level fields of the normalized envelope (in canonical
/// order). Used to reject unknown fields on re-ingestion so an envelope
/// cannot smuggle extra data that serde would silently drop.
const ENVELOPE_FIELDS: &[&str] = &[
    "event_id",
    "kind",
    "schema_version",
    "network",
    "provenance",
    "observed_at",
    "order",
    "ledger",
    "transaction",
    "operation",
    "token",
    "actor",
    "subject",
    "decision",
    "enforcement",
    "outcome",
    "reason",
    "details",
];

/// The exact top-level fields of a raw hooks state event.
const HOOKS_FIELDS: &[&str] = &[
    "type",
    "token",
    "account",
    "policy",
    "sac_passthrough",
    "ledger",
    "close_time",
    "transaction_hash",
    "operation_index",
    "event_index",
];

/// Decodes a payload by scheme into its typed raw form.
pub fn parse(scheme: Scheme, payload: &str) -> NormalizerResult<ParsedEvent> {
    match scheme {
        Scheme::HooksStateEvent => parse_hooks_state(payload).map(ParsedEvent::HooksState),
        Scheme::AuditEnvelope => parse_envelope(payload).map(ParsedEvent::Envelope),
    }
}

fn parse_hooks_state(payload: &str) -> NormalizerResult<RawHooksEvent> {
    let obj = as_object(payload, "hooks-state-event")?;
    reject_unknown_fields(&obj, HOOKS_FIELDS, "hooks-state-event")?;

    let hooks_type = match obj.get("type") {
        Some(Value::String(s)) => {
            HooksType::from_wire(s).ok_or_else(|| NormalizerError::ValidationFailed {
                scheme: "hooks-state-event",
                detail: format!("`{s}` is not a supported hooks event type"),
            })?
        }
        _ => return malformed("hooks-state-event", "`type` must be a string"),
    };
    let token = required_string(&obj, "token", "hooks-state-event")?;
    let account = optional_string(&obj, "account", "hooks-state-event")?;
    let policy = optional_string(&obj, "policy", "hooks-state-event")?;
    let sac_passthrough = match obj.get("sac_passthrough") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return malformed("hooks-state-event", "`sac_passthrough` must be a boolean"),
    };
    let ledger = match obj.get("ledger") {
        Some(Value::Number(n)) => {
            n.as_i64()
                .filter(|v| *v >= 0)
                .ok_or_else(|| NormalizerError::MalformedPayload {
                    scheme: "hooks-state-event",
                    detail: "`ledger` must be a non-negative integer".into(),
                })?
        }
        _ => {
            return malformed(
                "hooks-state-event",
                "`ledger` must be a non-negative integer",
            )
        }
    };
    let close_time = match obj.get("close_time") {
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| NormalizerError::MalformedPayload {
                scheme: "hooks-state-event",
                detail: "`close_time` must be an integer Unix timestamp".into(),
            })?,
        _ => {
            return malformed(
                "hooks-state-event",
                "`close_time` must be an integer Unix timestamp",
            )
        }
    };
    let transaction_hash = required_string(&obj, "transaction_hash", "hooks-state-event")?;
    let operation_index = match obj.get("operation_index") {
        Some(Value::Number(n)) => {
            n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| NormalizerError::MalformedPayload {
                    scheme: "hooks-state-event",
                    detail: "`operation_index` must be a non-negative integer".into(),
                })?
        }
        _ => {
            return malformed(
                "hooks-state-event",
                "`operation_index` must be a non-negative integer",
            )
        }
    };
    let event_index = match obj.get("event_index") {
        Some(Value::Number(n)) => {
            n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| NormalizerError::MalformedPayload {
                    scheme: "hooks-state-event",
                    detail: "`event_index` must be a non-negative integer".into(),
                })?
        }
        _ => {
            return malformed(
                "hooks-state-event",
                "`event_index` must be a non-negative integer",
            )
        }
    };

    Ok(RawHooksEvent {
        hooks_type,
        token,
        account,
        policy,
        sac_passthrough,
        ledger,
        close_time,
        transaction_hash,
        operation_index,
        event_index,
    })
}

fn parse_envelope(payload: &str) -> NormalizerResult<RawEnvelope> {
    let obj = as_object(payload, "audit-envelope")?;
    reject_unknown_fields(&obj, ENVELOPE_FIELDS, "audit-envelope")?;
    let value: Value =
        serde_json::from_str(payload).map_err(|e| NormalizerError::MalformedPayload {
            scheme: "audit-envelope",
            detail: format!("payload is not valid JSON: {e}"),
        })?;
    let event: AuditEvent =
        serde_json::from_value(value).map_err(|e| NormalizerError::MalformedPayload {
            scheme: "audit-envelope",
            detail: format!("payload does not decode as an audit event: {e}"),
        })?;
    Ok(RawEnvelope {
        event: Box::new(event),
    })
}

fn as_object(
    payload: &str,
    scheme: &'static str,
) -> NormalizerResult<serde_json::Map<String, Value>> {
    let value: Value =
        serde_json::from_str(payload).map_err(|e| NormalizerError::MalformedPayload {
            scheme,
            detail: format!("payload is not valid JSON: {e}"),
        })?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| NormalizerError::MalformedPayload {
            scheme,
            detail: "payload must be a JSON object".into(),
        })
}

fn reject_unknown_fields(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
    scheme: &'static str,
) -> NormalizerResult<()> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(NormalizerError::MalformedPayload {
                scheme,
                detail: format!("unknown field `{key}`"),
            });
        }
    }
    Ok(())
}

fn required_string(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    scheme: &'static str,
) -> NormalizerResult<String> {
    match obj.get(field) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(NormalizerError::MalformedPayload {
            scheme,
            detail: format!("`{field}` must be a string"),
        }),
    }
}

fn optional_string(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    scheme: &'static str,
) -> NormalizerResult<Option<String>> {
    match obj.get(field) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(NormalizerError::MalformedPayload {
            scheme,
            detail: format!("`{field}` must be a string"),
        }),
    }
}

fn malformed<T>(scheme: &'static str, detail: &str) -> NormalizerResult<T> {
    Err(NormalizerError::MalformedPayload {
        scheme,
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::OriginKind;

    /// The committed fixture for a frozen-account hooks event.
    const FROZEN_FIXTURE: &str =
        include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");
    /// The committed fixture for a token-bound hooks event.
    const BOUND_FIXTURE: &str =
        include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
    /// The committed fixture for a config-change hooks event.
    const CONFIG_FIXTURE: &str =
        include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");
    /// The committed fixture for an already-normalized envelope.
    const ENVELOPE_FIXTURE: &str =
        include_str!("../../../fixtures/events/denied-transfer/event.json");

    #[test]
    fn every_hooks_type_round_trips_its_wire_string() {
        for t in HooksType::ALL {
            assert_eq!(HooksType::from_wire(t.as_str()), Some(*t));
        }
        assert_eq!(HooksType::from_wire("transfer_approved"), None);
        assert_eq!(HooksType::from_wire(""), None);
    }

    #[test]
    fn hooks_types_map_onto_normalized_kinds() {
        assert_eq!(
            HooksType::AccountFrozen.to_event_kind(),
            EventKind::AccountFrozen
        );
        assert_eq!(
            HooksType::AccountUnfrozen.to_event_kind(),
            EventKind::AccountUnfrozen
        );
        assert_eq!(HooksType::TokenBound.to_event_kind(), EventKind::TokenBound);
        assert_eq!(
            HooksType::TokenUnbound.to_event_kind(),
            EventKind::TokenUnbound
        );
        assert_eq!(
            HooksType::ComplianceConfigChanged.to_event_kind(),
            EventKind::ConfigurationChanged
        );
    }
    #[test]
    fn frozen_fixture_decodes_to_a_typed_raw_form() {
        let parsed = parse(Scheme::HooksStateEvent, FROZEN_FIXTURE).unwrap();
        let ParsedEvent::HooksState(raw) = parsed else {
            panic!("expected a hooks-state decode");
        };
        assert_eq!(raw.hooks_type, HooksType::AccountFrozen);
        assert!(raw.token.starts_with('C'));
        assert!(raw.account.as_deref().unwrap().starts_with('G'));
        assert_eq!(raw.ledger, 423);
        assert_eq!(raw.close_time, 1_700_000_400);
        assert_eq!(raw.operation_index, 2);
        assert_eq!(raw.event_index, 0);
        assert_eq!(raw.policy, None);
        assert_eq!(raw.sac_passthrough, None);
    }

    #[test]
    fn bound_fixture_decodes_without_account_fields() {
        let parsed = parse(Scheme::HooksStateEvent, BOUND_FIXTURE).unwrap();
        let ParsedEvent::HooksState(raw) = parsed else {
            panic!("expected a hooks-state decode");
        };
        assert_eq!(raw.hooks_type, HooksType::TokenBound);
        assert_eq!(raw.ledger, 415);
        assert!(raw.account.is_none());
    }

    #[test]
    fn config_fixture_decodes_policy_fields() {
        let parsed = parse(Scheme::HooksStateEvent, CONFIG_FIXTURE).unwrap();
        let ParsedEvent::HooksState(raw) = parsed else {
            panic!("expected a hooks-state decode");
        };
        assert_eq!(raw.hooks_type, HooksType::ComplianceConfigChanged);
        assert!(raw.policy.as_deref().unwrap().starts_with('C'));
        assert_eq!(raw.sac_passthrough, Some(true));
    }

    #[test]
    fn envelope_fixture_decodes_to_the_canonical_envelope() {
        let parsed = parse(Scheme::AuditEnvelope, ENVELOPE_FIXTURE).unwrap();
        let ParsedEvent::Envelope(raw) = parsed else {
            panic!("expected an envelope decode");
        };
        assert_eq!(raw.event.kind, EventKind::TransferDenied);
        assert_eq!(raw.event.schema_version, 1);
        assert_eq!(raw.event.provenance.origin(), OriginKind::Derived);
        assert!(raw.event.provenance.derivation().is_some());
        // The committed fixture must be a fully valid envelope.
        assert!(raw.event.validate().is_ok());
    }

    #[test]
    fn invalid_json_is_a_malformed_payload() {
        assert!(matches!(
            parse(Scheme::HooksStateEvent, "{ not json"),
            Err(NormalizerError::MalformedPayload { .. })
        ));
        assert!(matches!(
            parse(Scheme::AuditEnvelope, ""),
            Err(NormalizerError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn non_object_payloads_are_rejected() {
        assert!(matches!(
            parse(Scheme::HooksStateEvent, "[1,2,3]"),
            Err(NormalizerError::MalformedPayload { .. })
        ));
        assert!(matches!(
            parse(Scheme::AuditEnvelope, "\"nope\""),
            Err(NormalizerError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn unknown_fields_are_rejected_not_dropped() {
        let with_extra = r#"{
            "type": "token_bound", "token": "C", "ledger": 1,
            "close_time": 2, "transaction_hash": "ab",
            "operation_index": 0, "event_index": 0,
            "amount": 100
        }"#;
        assert!(matches!(
            parse(Scheme::HooksStateEvent, with_extra),
            Err(NormalizerError::MalformedPayload { detail, .. })
                if detail.contains("unknown field `amount`")
        ));

        let envelope_with_extra = format!(
            "{{\"event_id\": \"evt_{}\", \"kind\": \"token-bound\", \"schema_version\": 1, \"network\": \"testnet\", \"provenance\": {{}}, \"details\": {{}}, \"smuggled\": true}}",
            "a".repeat(32)
        );
        assert!(matches!(
            parse(Scheme::AuditEnvelope, &envelope_with_extra),
            Err(NormalizerError::MalformedPayload { detail, .. })
                if detail.contains("unknown field `smuggled`")
        ));
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        let missing_token = r#"{
            "type": "account_frozen", "ledger": 1, "close_time": 2,
            "transaction_hash": "ab", "operation_index": 0, "event_index": 0
        }"#;
        assert!(matches!(
            parse(Scheme::HooksStateEvent, missing_token),
            Err(NormalizerError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn wrong_value_types_are_rejected() {
        let string_ledger = r#"{
            "type": "account_frozen", "token": "C", "account": "G",
            "ledger": "423", "close_time": 2, "transaction_hash": "ab",
            "operation_index": 0, "event_index": 0
        }"#;
        assert!(matches!(
            parse(Scheme::HooksStateEvent, string_ledger),
            Err(NormalizerError::MalformedPayload { .. })
        ));

        let float_index = r#"{
            "type": "account_frozen", "token": "C", "account": "G",
            "ledger": 1, "close_time": 2, "transaction_hash": "ab",
            "operation_index": 0.5, "event_index": 0
        }"#;
        assert!(matches!(
            parse(Scheme::HooksStateEvent, float_index),
            Err(NormalizerError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn unsupported_hooks_types_are_rejected() {
        let bogus_type = r#"{
            "type": "transfer_approved", "token": "C", "ledger": 1,
            "close_time": 2, "transaction_hash": "ab",
            "operation_index": 0, "event_index": 0
        }"#;
        assert!(matches!(
            parse(Scheme::HooksStateEvent, bogus_type),
            Err(NormalizerError::ValidationFailed { .. })
        ));
    }

    #[test]
    fn parsing_is_deterministic() {
        let a = parse(Scheme::HooksStateEvent, FROZEN_FIXTURE).unwrap();
        let b = parse(Scheme::HooksStateEvent, FROZEN_FIXTURE).unwrap();
        assert_eq!(a, b);
    }
}
