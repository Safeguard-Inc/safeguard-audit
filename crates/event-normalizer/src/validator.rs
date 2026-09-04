//! The validation stage: parsed forms must be *sensible*, not just
//! decodable.
//!
//! The parser guarantees structure (JSON, right fields, right types). This
//! module guarantees semantics:
//!
//! * **hooks-state-event** — type-dependent fields must be present exactly
//!   when the type requires them (a config change without `policy` is
//!   invalid; a freeze carrying a `policy` field is equally invalid), and
//!   every carried identifier must pass the same structural checks the
//!   builders enforce downstream.
//! * **audit-envelope** — the envelope must be on a supported schema
//!   version, must pass the envelope's own consistency rules, and every
//!   typed reference is *rebuilt through the public constructors* so
//!   validation cannot be bypassed by deserializing junk straight into an
//!   unvalidated newtype.
//!
//! Validation is deterministic and total: a payload either passes every
//! rule or fails with the rule it violated.
//!
//! ## Privacy rule
//!
//! Failures name the offending *field* and a structural description —
//! never the value itself, which could be protected data in a malformed
//! payload.

use safeguard_audit_core::{
    AccountId, AccountReference, AuditError, ContractId, DerivationInfo,
    EnforcementResultReference, EventProvenance, LedgerReference, NetworkId, OperationReference,
    PolicyDecisionReference, PolicyReference, ReasonCode, TokenReference, TransactionHash,
    TransactionReference, VersionLabel,
};

use crate::errors::{NormalizerError, NormalizerResult};
use crate::parser::ParsedEvent;
use crate::scheme::Scheme;

/// Validates a parsed raw form. `Ok(())` means the form is fit to
/// classify; anything else names the rule that failed.
pub fn validate(parsed: &ParsedEvent) -> NormalizerResult<()> {
    match parsed {
        ParsedEvent::HooksState(raw) => validate_hooks_state(raw),
        ParsedEvent::Envelope(raw) => validate_envelope(&raw.event),
    }
}

fn invalid_hooks(detail: impl Into<String>) -> NormalizerResult<()> {
    Err(NormalizerError::ValidationFailed {
        scheme: "hooks-state-event",
        detail: detail.into(),
    })
}

fn validate_hooks_state(raw: &crate::parser::RawHooksEvent) -> NormalizerResult<()> {
    // Type-dependent field presence must be exact: never silently ignore
    // an extra field, never tolerate a missing one.
    match raw.hooks_type {
        t if t.has_account() => {
            if raw.account.is_none() {
                return invalid_hooks("account: required for freeze-state events");
            }
            if raw.policy.is_some() || raw.sac_passthrough.is_some() {
                return invalid_hooks(
                    "policy: freeze-state events must not carry policy configuration",
                );
            }
        }
        t if t.has_policy_config() => {
            if raw.policy.is_none() {
                return invalid_hooks("policy: required for config-change events");
            }
            if raw.sac_passthrough.is_none() {
                return invalid_hooks("sac_passthrough: required for config-change events");
            }
            if raw.account.is_some() {
                return invalid_hooks(
                    "account: config-change events must not carry a subject account",
                );
            }
        }
        _ => {
            // bind/unbind: no account, no policy configuration.
            if raw.account.is_some() || raw.policy.is_some() || raw.sac_passthrough.is_some() {
                return invalid_hooks(
                    "account: bind/unbind events must not carry account or policy fields",
                );
            }
        }
    }

    // Identifier shapes must survive the same builders used downstream.
    check_hooks_value(|| ContractId::new(&raw.token).map(|_| ()), "token")?;
    if let Some(account) = &raw.account {
        check_hooks_value(|| AccountId::new(account).map(|_| ()), "account")?;
    }
    if let Some(policy) = &raw.policy {
        check_hooks_value(|| ContractId::new(policy).map(|_| ()), "policy")?;
    }
    check_tx_hash(&raw.transaction_hash)?;

    if raw.ledger < 1 {
        return invalid_hooks("ledger: sequence must be >= 1");
    }
    if raw.close_time < 0 {
        return invalid_hooks("close_time: must be a non-negative Unix timestamp");
    }
    Ok(())
}

/// The hooks surface carries real transaction hashes: 64 lowercase hex.
fn check_tx_hash(hash: &str) -> NormalizerResult<()> {
    let valid = hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        invalid_hooks("transaction_hash: must be 64 lowercase hex chars")
    }
}

/// Runs a builder that can only fail on the value it was given.
fn check_hooks_value<F>(f: F, field: &str) -> NormalizerResult<()>
where
    F: FnOnce() -> Result<(), AuditError>,
{
    f().map_err(|e| NormalizerError::ValidationFailed {
        scheme: "hooks-state-event",
        detail: format!("{field}: {e}"),
    })
}

fn invalid_envelope(detail: impl Into<String>) -> NormalizerResult<()> {
    Err(NormalizerError::ValidationFailed {
        scheme: "audit-envelope",
        detail: detail.into(),
    })
}

fn envelope_field(field: &str, err: AuditError) -> NormalizerError {
    NormalizerError::ValidationFailed {
        scheme: "audit-envelope",
        detail: format!("{field}: {err}"),
    }
}

fn validate_envelope(event: &safeguard_audit_core::AuditEvent) -> NormalizerResult<()> {
    // Schema gate first: an envelope from a future schema version must fail
    // as a *version* problem, not a generic validation problem.
    let declared = event.schema_version;
    let supported = Scheme::AuditEnvelope.supported_version();
    if declared != supported {
        return Err(NormalizerError::UnsupportedVersion {
            scheme: "audit-envelope",
            version: declared.to_string(),
            detail: format!("supported: {supported}"),
        });
    }

    // The envelope's own cross-field consistency rules.
    event.validate().map_err(|e| match e {
        AuditError::UnsupportedSchema(detail) => NormalizerError::UnsupportedVersion {
            scheme: "audit-envelope",
            version: declared.to_string(),
            detail,
        },
        other => NormalizerError::ValidationFailed {
            scheme: "audit-envelope",
            detail: other.to_string(),
        },
    })?;

    // Every typed reference is rebuilt through its public constructor so
    // deserialization cannot smuggle junk into an unvalidated newtype.
    NetworkId::new(event.network.as_str()).map_err(|e| envelope_field("network", e))?;
    validate_provenance(&event.provenance)?;
    if event.observed_at.is_some_and(|at| at.as_unix_seconds() < 0) {
        return invalid_envelope("observed_at must be a non-negative Unix timestamp");
    }
    if let Some(seq) = event.order.ledger_sequence {
        if seq < 1 {
            return invalid_envelope("order.ledger_sequence must be >= 1");
        }
    }
    if let Some(ledger) = &event.ledger {
        LedgerReference::new(
            NetworkId::new(ledger.network().as_str())
                .map_err(|e| envelope_field("ledger.network", e))?,
            ledger.sequence(),
            ledger.close_time(),
        )
        .map_err(|e| envelope_field("ledger.sequence", e))?;
        if ledger.close_time().is_some_and(|t| t.as_unix_seconds() < 0) {
            return invalid_envelope("ledger.close_time must be non-negative");
        }
    }
    if let Some(tx) = &event.transaction {
        TransactionReference::new(
            NetworkId::new(tx.network().as_str())
                .map_err(|e| envelope_field("transaction.network", e))?,
            TransactionHash::new(tx.hash().as_str())
                .map_err(|e| envelope_field("transaction.hash", e))?,
        );
    }
    if let Some(op) = &event.operation {
        let tx = op.transaction();
        OperationReference::new(
            TransactionReference::new(
                NetworkId::new(tx.network().as_str())
                    .map_err(|e| envelope_field("operation.transaction.network", e))?,
                TransactionHash::new(tx.hash().as_str())
                    .map_err(|e| envelope_field("operation.transaction.hash", e))?,
            ),
            op.index(),
            op.op_type(),
        )
        .map_err(|e| envelope_field("operation", e))?;
    }
    if let Some(token) = &event.token {
        validate_token(token)?;
    }
    if let Some(actor) = &event.actor {
        validate_account("actor", actor)?;
    }
    if let Some(subject) = &event.subject {
        validate_account("subject", subject)?;
    }
    if let Some(decision) = &event.decision {
        validate_decision(decision)?;
    }
    if let Some(enforcement) = &event.enforcement {
        validate_enforcement(enforcement)?;
    }
    if let Some(reason) = &event.reason {
        ReasonCode::new(reason.as_str()).map_err(|e| envelope_field("reason", e))?;
    }
    for (key, value) in &event.details {
        let ok_key = (1..=64).contains(&key.len()) && key.chars().all(|c| c.is_ascii_graphic());
        let ok_value = value.len() <= 1024;
        if !ok_key || !ok_value {
            return invalid_envelope(
                "details: keys must be 1-64 printable ASCII chars, values at most 1024 chars",
            );
        }
    }
    Ok(())
}

fn validate_provenance(provenance: &EventProvenance) -> NormalizerResult<()> {
    VersionLabel::new(provenance.parser_version().as_str())
        .map_err(|e| envelope_field("provenance.parser_version", e))?;
    if let Some(derivation) = provenance.derivation() {
        DerivationInfo::new(
            derivation.method(),
            derivation.source_events().to_vec(),
            derivation.note(),
        )
        .map_err(|e| envelope_field("provenance.derivation", e))?;
    }
    Ok(())
}

fn validate_account(field: &str, reference: &AccountReference) -> NormalizerResult<()> {
    AccountReference::new(
        NetworkId::new(reference.network().as_str())
            .map_err(|e| envelope_field(&format!("{field}.network"), e))?,
        AccountId::new(reference.account().as_str())
            .map_err(|e| envelope_field(&format!("{field}.account"), e))?,
    );
    Ok(())
}

fn validate_token(token: &TokenReference) -> NormalizerResult<()> {
    let network =
        NetworkId::new(token.network().as_str()).map_err(|e| envelope_field("token.network", e))?;
    if let Some(contract) = token.contract() {
        TokenReference::for_contract(
            network,
            ContractId::new(contract.as_str()).map_err(|e| envelope_field("token.contract", e))?,
        );
        return Ok(());
    }
    match (token.asset_code(), token.issuer()) {
        (Some(code), Some(issuer)) => {
            TokenReference::for_classic_asset(
                network,
                code,
                AccountId::new(issuer.as_str()).map_err(|e| envelope_field("token.issuer", e))?,
            )
            .map_err(|e| envelope_field("token.asset_code", e))?;
            Ok(())
        }
        _ => invalid_envelope("token must identify a contract or a classic asset"),
    }
}

fn validate_decision(decision: &PolicyDecisionReference) -> NormalizerResult<()> {
    let policy_ref = decision.policy();
    let mut policy = PolicyReference::new(
        ContractId::new(policy_ref.policy().as_str())
            .map_err(|e| envelope_field("decision.policy.policy", e))?,
        VersionLabel::new(policy_ref.version().as_str())
            .map_err(|e| envelope_field("decision.policy.version", e))?,
    );
    if let Some(digest) = policy_ref.digest() {
        policy = policy
            .with_digest(digest.to_owned())
            .map_err(|e| envelope_field("decision.policy.digest", e))?;
    }
    let mut rebuilt = PolicyDecisionReference::new(policy, decision.result());
    if let Some(reason) = decision.reason() {
        rebuilt = rebuilt.with_reason(
            ReasonCode::new(reason.as_str()).map_err(|e| envelope_field("decision.reason", e))?,
        );
    }
    if let Some(at) = decision.decided_at() {
        if at.as_unix_seconds() < 0 {
            return invalid_envelope("decision.decided_at must be non-negative");
        }
        rebuilt = rebuilt.with_decided_at(at);
    }
    let _ = rebuilt;
    Ok(())
}

fn validate_enforcement(enforcement: &EnforcementResultReference) -> NormalizerResult<()> {
    let mut rebuilt = EnforcementResultReference::new(
        enforcement.hook(),
        VersionLabel::new(enforcement.hook_version().as_str())
            .map_err(|e| envelope_field("enforcement.hook_version", e))?,
        enforcement.result(),
    )
    .map_err(|e| envelope_field("enforcement.hook", e))?;
    if let Some(reason) = enforcement.reason() {
        rebuilt = rebuilt.with_reason(
            ReasonCode::new(reason.as_str())
                .map_err(|e| envelope_field("enforcement.reason", e))?,
        );
    }
    let _ = rebuilt;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse, RawEnvelope};
    use crate::scheme::Scheme;
    use safeguard_audit_core::{AuditEvent, EventProvenance, OriginKind};

    const FROZEN_FIXTURE: &str =
        include_str!("../../../fixtures/events/frozen-account/observed-hooks-event.json");
    const BOUND_FIXTURE: &str =
        include_str!("../../../fixtures/events/bound-token/observed-hooks-event.json");
    const CONFIG_FIXTURE: &str =
        include_str!("../../../fixtures/events/config-change/observed-hooks-event.json");
    const ENVELOPE_FIXTURE: &str =
        include_str!("../../../fixtures/events/denied-transfer/event.json");

    fn validate_str(scheme: Scheme, payload: &str) -> NormalizerResult<()> {
        let parsed = parse(scheme, payload)?;
        validate(&parsed)
    }

    fn envelope_from_fixture() -> AuditEvent {
        serde_json::from_str(ENVELOPE_FIXTURE).expect("fixture must stay decodable")
    }

    fn wrap(event: AuditEvent) -> crate::parser::ParsedEvent {
        crate::parser::ParsedEvent::Envelope(RawEnvelope {
            event: Box::new(event),
        })
    }

    #[test]
    fn committed_hooks_fixtures_validate() {
        assert!(validate_str(Scheme::HooksStateEvent, FROZEN_FIXTURE).is_ok());
        assert!(validate_str(Scheme::HooksStateEvent, BOUND_FIXTURE).is_ok());
        assert!(validate_str(Scheme::HooksStateEvent, CONFIG_FIXTURE).is_ok());
    }

    #[test]
    fn committed_envelope_fixture_validates() {
        assert!(validate_str(Scheme::AuditEnvelope, ENVELOPE_FIXTURE).is_ok());
    }

    #[test]
    fn freeze_without_account_is_invalid() {
        let payload = r#"{
            "type": "account_frozen",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "ledger": 423, "close_time": 1700000400,
            "transaction_hash": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            "operation_index": 2, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(matches!(
            validate(&parsed),
            Err(NormalizerError::ValidationFailed { detail, .. })
                if detail.contains("account")
        ));
    }

    #[test]
    fn freeze_with_policy_fields_is_invalid() {
        let payload = r#"{
            "type": "account_frozen",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "account": "GAFROZENACCOUNTDEMO00000000000000000000000000000000000",
            "policy": "CPOLICYCONTRACTDEMO0000000000000000000000000000000000",
            "ledger": 423, "close_time": 1700000400,
            "transaction_hash": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            "operation_index": 2, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(validate(&parsed).is_err());
    }

    #[test]
    fn bind_with_account_field_is_invalid() {
        let payload = r#"{
            "type": "token_bound",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "account": "GAFROZENACCOUNTDEMO00000000000000000000000000000000000",
            "ledger": 415, "close_time": 1700000100,
            "transaction_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "operation_index": 0, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(validate(&parsed).is_err());
    }

    #[test]
    fn config_change_without_sac_flag_is_invalid() {
        let payload = r#"{
            "type": "compliance_config_changed",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "policy": "CPOLICYCONTRACTDEMO0000000000000000000000000000000000",
            "ledger": 419, "close_time": 1700000050,
            "transaction_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "operation_index": 1, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(validate(&parsed).is_err());
    }

    #[test]
    fn zero_ledger_and_uppercase_hash_are_invalid() {
        let payload = r#"{
            "type": "token_bound",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "ledger": 0, "close_time": 1700000100,
            "transaction_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "operation_index": 0, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(validate(&parsed).is_err());
    }

    #[test]
    fn negative_close_times_are_invalid() {
        let payload = r#"{
            "type": "token_bound",
            "token": "CCONFIDENTIALTOKENDEMO000000000000000000000000000000",
            "ledger": 415, "close_time": -1,
            "transaction_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "operation_index": 0, "event_index": 0
        }"#;
        let parsed = parse(Scheme::HooksStateEvent, payload).unwrap();
        assert!(validate(&parsed).is_err());
    }

    #[test]
    fn unsupported_envelope_versions_are_version_problems() {
        let mut event = envelope_from_fixture();
        event.schema_version = 99;
        assert!(matches!(
            validate(&wrap(event)),
            Err(NormalizerError::UnsupportedVersion {
                scheme: "audit-envelope",
                ..
            })
        ));
    }

    #[test]
    fn cross_network_envelopes_are_rejected() {
        let mut event = envelope_from_fixture();
        let tx = TransactionReference::new(
            NetworkId::new("mainnet").unwrap(),
            TransactionHash::new(&"ab".repeat(32)).unwrap(),
        );
        event.transaction = Some(tx);
        assert!(validate(&wrap(event)).is_err());
    }

    #[test]
    fn junk_reason_codes_are_rejected() {
        // ReasonCode::new rejects mixed case; smuggle it through the JSON
        // layer since in-memory ReasonCodes can only hold valid values.
        let json = ENVELOPE_FIXTURE.replace("POLICY_DENIED", "policy_denied");
        let tampered: AuditEvent = serde_json::from_str(&json).unwrap();
        assert!(validate(&wrap(tampered)).is_err());
    }

    #[test]
    fn overlong_detail_values_are_rejected() {
        let mut event = envelope_from_fixture();
        event.details.insert("key".into(), "x".repeat(2048));
        assert!(validate(&wrap(event)).is_err());
    }

    #[test]
    fn derived_origin_without_derivation_is_rejected() {
        let mut event = envelope_from_fixture();
        event.provenance = EventProvenance::new(
            OriginKind::Derived,
            "safeguard-audit",
            VersionLabel::new("1.0.0").unwrap(),
        )
        .unwrap();
        assert!(validate(&wrap(event)).is_err());
    }

    #[test]
    fn validation_is_deterministic() {
        // Determinism here means: identical payloads always produce the
        // same verdict, never a clock- or state-dependent one.
        assert!(validate_str(Scheme::HooksStateEvent, FROZEN_FIXTURE).is_ok());
        assert!(validate_str(Scheme::HooksStateEvent, FROZEN_FIXTURE).is_ok());
        assert!(validate_str(Scheme::AuditEnvelope, ENVELOPE_FIXTURE).is_ok());
        assert!(validate_str(Scheme::AuditEnvelope, ENVELOPE_FIXTURE).is_ok());
    }
}
