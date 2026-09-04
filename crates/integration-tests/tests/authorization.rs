//! Authorization services through the real pipeline.
//!
//! These tests exercise the authorizer as an operator would: register
//! auditors with scopes and credentials, ask for decisions across the full
//! outcome space (granted, denied, out-of-scope, expired, escalation), and
//! confirm that every decision lands in the store as an `audit-access`
//! record — the audit trail auditing itself, at exactly one hop.

use safeguard_audit_authorization::{
    reason, AccessLog, AccessLogWithStore, Authorizer, Credential, Grant, Registry,
    StoreAccessLog,
};
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditorId, AuditorRole, EventKind, FixedClock, NetworkId,
    PageRequest, Timestamp, VersionLabel,
};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_storage::{AuditQuery, EventStore};

fn net() -> NetworkId {
    NetworkId::new(NetworkId::TESTNET).unwrap()
}

fn scope_net() -> AccessScope {
    AccessScope::Network(net())
}

fn aud(n: &str) -> AuditorId {
    AuditorId::derive(&[n])
}

fn clock_at(secs: i64) -> FixedClock {
    FixedClock::at(Timestamp::from_unix_seconds(secs))
}

/// Registers an auditor with a role, a network scope, and a credential
/// expiring at `expiry` (in seconds).
fn registered(
    registry: &mut Registry,
    name: &str,
    role: AuditorRole,
    expiry: i64,
) {
    registry
        .register(
            Grant::new(aud(name), role)
                .with_scope(scope_net())
                .with_credential(Credential::new(
                    aud(name),
                    format!("material-{name}"),
                    Timestamp::from_unix_seconds(expiry),
                )),
        )
        .unwrap();
}

/// Runs one decision and records it through the store-backed access log.
/// Returns the decision alongside the store so callers can assert on the
/// recorded history.
fn decide_and_record(
    authorizer: &Authorizer,
    store: &mut MemoryEventStore,
    auditor: &AuditorId,
    action: AccessAction,
    scope: &AccessScope,
) -> safeguard_audit_core::AuthorizationDecision {
    let decision = authorizer.authorize(auditor, action, scope).unwrap();
    let entry = authorizer.entry_for_decision(&decision, Some("rec_1234")).unwrap();
    let log = StoreAccessLog::new(
        net(),
        safeguard_audit_authorization::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        clock_at(1_700_000_000),
    );
    log.record_into(&entry, store).unwrap();
    decision
}

fn audit_access_records(store: &MemoryEventStore) -> Vec<safeguard_audit_core::AuditRecord> {
    store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(1000).unwrap(),
        )
        .unwrap()
        .items()
        .to_vec()
}

#[test]
fn authorized_auditor_reads_within_scope_and_the_access_is_recorded() {
    let mut registry = Registry::new();
    registered(&mut registry, "alice", AuditorRole::SeniorAuditor, 9_999_999_999);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));
    let mut store = MemoryEventStore::new();

    let decision = decide_and_record(
        &authorizer,
        &mut store,
        &aud("alice"),
        AccessAction::GenerateReport,
        &scope_net(),
    );

    assert!(decision.allowed());
    assert_eq!(decision.reason(), Some(reason::GRANTED));

    // One audit-access record, carrying the attribution and outcome.
    let records = audit_access_records(&store);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event.kind, EventKind::AuditAccess);
    assert_eq!(records[0].event.details.get("result").unwrap(), "granted");
    assert_eq!(records[0].event.details.get("action").unwrap(), "generate-report");
    assert_eq!(
        records[0].event.details.get("auditor").unwrap(),
        aud("alice").as_str()
    );
    assert_eq!(
        records[0].event.details.get("accessed_at").unwrap(),
        "1700000000"
    );
    // The record is self-attributing: it answers who/when without any
    // external lookup.
    assert!(records[0].event.details.contains_key("entry"));
}

#[test]
fn unauthorized_action_is_denied_and_recorded_as_denied() {
    let mut registry = Registry::new();
    // Read-only reviewer cannot request protected data.
    registered(&mut registry, "bob", AuditorRole::ReadOnlyReviewer, 9_999_999_999);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));
    let mut store = MemoryEventStore::new();

    let decision = decide_and_record(
        &authorizer,
        &mut store,
        &aud("bob"),
        AccessAction::RequestProtectedData,
        &scope_net(),
    );

    assert!(!decision.allowed());
    assert_eq!(decision.reason(), Some(reason::ACTION_DENIED));
    let records = audit_access_records(&store);
    assert_eq!(records[0].event.details.get("result").unwrap(), "denied");
}

#[test]
fn out_of_scope_access_is_recorded_as_out_of_scope() {
    let mut registry = Registry::new();
    registered(&mut registry, "carol", AuditorRole::SeniorAuditor, 9_999_999_999);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));
    let mut store = MemoryEventStore::new();

    let mainnet = AccessScope::Network(NetworkId::new(NetworkId::MAINNET).unwrap());
    let decision = decide_and_record(
        &authorizer,
        &mut store,
        &aud("carol"),
        AccessAction::ReadRecord,
        &mainnet,
    );

    assert!(!decision.allowed());
    assert_eq!(decision.reason(), Some(reason::SCOPE_OUT_OF_BOUNDS));
    let records = audit_access_records(&store);
    assert_eq!(
        records[0].event.details.get("result").unwrap(),
        "out-of-scope"
    );
}

#[test]
fn expired_credential_denies_even_a_full_administrator() {
    // Administrator grant, but the credential expired at 1_700_000_000.
    let mut registry = Registry::new();
    registered(&mut registry, "dave", AuditorRole::Administrator, 1_700_000_000);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_001));
    let mut store = MemoryEventStore::new();

    let decision = decide_and_record(
        &authorizer,
        &mut store,
        &aud("dave"),
        AccessAction::ReadRecord,
        &scope_net(),
    );

    assert!(!decision.allowed());
    assert_eq!(decision.reason(), Some(reason::CREDENTIAL_EXPIRED));
}

#[test]
fn privilege_escalation_is_blocked_at_every_hop() {
    // A plain auditor attempts administrator-only actions and out-of-scope
    // targets; each attempt is denied or out-of-scope, never granted.
    let mut registry = Registry::new();
    registered(&mut registry, "mallory", AuditorRole::Auditor, 9_999_999_999);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));
    let mut store = MemoryEventStore::new();

    // Hop 1: an action no role grants (auditor cannot export).
    let export = decide_and_record(
        &authorizer,
        &mut store,
        &aud("mallory"),
        AccessAction::ExportRecords,
        &scope_net(),
    );
    assert!(!export.allowed());
    assert_eq!(export.reason(), Some(reason::ACTION_DENIED));

    // Hop 2: a mainnet scope when only testnet is granted.
    let mainnet = AccessScope::Network(NetworkId::new(NetworkId::MAINNET).unwrap());
    let foreign = decide_and_record(
        &authorizer,
        &mut store,
        &aud("mallory"),
        AccessAction::ReadRecord,
        &mainnet,
    );
    assert!(!foreign.allowed());
    assert_eq!(foreign.reason(), Some(reason::SCOPE_OUT_OF_BOUNDS));

    // Hop 3: a grant for the same action but a wholly different network —
    // still out of scope, not silently upgraded.
    let standalone = AccessScope::Network(NetworkId::new(NetworkId::STANDALONE).unwrap());
    let dec = decide_and_record(
        &authorizer,
        &mut store,
        &aud("mallory"),
        AccessAction::ReadRecord,
        &standalone,
    );
    assert!(!dec.allowed());
    assert_eq!(dec.reason(), Some(reason::SCOPE_OUT_OF_BOUNDS));

    // Hop 4: an unknown auditor is denied, not an error.
    let ghost = decide_and_record(
        &authorizer,
        &mut store,
        &aud("ghost"),
        AccessAction::ReadRecord,
        &scope_net(),
    );
    assert!(!ghost.allowed());
    assert_eq!(ghost.reason(), Some(reason::UNKNOWN_AUDITOR));

    // Every attempt was recorded as denied or out-of-scope; nothing was
    // granted, so no record may carry a granted result.
    let records = audit_access_records(&store);
    assert_eq!(records.len(), 4);
    for record in records {
        let result = record.event.details.get("result").unwrap();
        assert!(
            result == "denied" || result == "out-of-scope",
            "no escalation may be granted, got {result}"
        );
    }
}

#[test]
fn scoped_auditor_never_reaches_unrelated_scopes() {
    // One auditor holds only a *token* scope on testnet; reading on a
    // different token or a different network must both fail.
    let token = AccessScope::Token(safeguard_audit_core::TokenReference::for_contract(
        net(),
        safeguard_audit_core::ContractId::new("CCONT").unwrap(),
    ));
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(aud("erin"), AuditorRole::Auditor)
                .with_scope(token.clone())
                .with_credential(Credential::new(
                    aud("erin"),
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));

    let other_token = AccessScope::Token(safeguard_audit_core::TokenReference::for_contract(
        net(),
        safeguard_audit_core::ContractId::new("COTHER").unwrap(),
    ));
    assert!(!authorizer
        .authorize(&aud("erin"), AccessAction::ReadRecord, &other_token)
        .unwrap()
        .allowed());
    // The network-level request is not covered by a token grant either.
    assert!(!authorizer
        .authorize(&aud("erin"), AccessAction::ReadRecord, &scope_net())
        .unwrap()
        .allowed());
    // Within the token itself, reading works.
    assert!(authorizer
        .authorize(&aud("erin"), AccessAction::ReadRecord, &token)
        .unwrap()
        .allowed());
}

#[test]
fn store_bound_log_records_through_the_trait() {
    let mut registry = Registry::new();
    // Frank holds a restricted-data classification scope (protected data).
    registry
        .register(
            Grant::new(aud("frank"), AuditorRole::ComplianceOfficer)
                .with_scope(scope_net())
                .with_scope(AccessScope::Classification(
                    safeguard_audit_core::DataClassification::Restricted,
                ))
                .with_credential(Credential::new(
                    aud("frank"),
                    "material-frank",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));
    let mut store = MemoryEventStore::new();
    let mut bound = AccessLogWithStore::new(
        StoreAccessLog::new(
            net(),
            safeguard_audit_authorization::SOURCE_LABEL,
            VersionLabel::new("1.0.0").unwrap(),
            clock_at(1_700_000_000),
        ),
        &mut store,
    );

    let decision = authorizer
        .authorize(
            &aud("frank"),
            AccessAction::VerifyIntegrity,
            &AccessScope::Classification(safeguard_audit_core::DataClassification::Restricted),
        )
        .unwrap();
    let entry = authorizer
        .entry_for_decision(&decision, None)
        .unwrap()
        .with_classification(safeguard_audit_core::DataClassification::Restricted);
    bound.record(&entry).unwrap();

    let records = audit_access_records(&store);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].event.details.get("auditor").unwrap(),
        aud("frank").as_str()
    );
    assert_eq!(records[0].event.details.get("result").unwrap(), "granted");
    assert_eq!(
        records[0].event.details.get("classification").unwrap(),
        "restricted"
    );
}

#[test]
fn replaying_the_same_decision_is_idempotent_in_the_store() {
    let mut registry = Registry::new();
    registered(&mut registry, "grace", AuditorRole::Auditor, 9_999_999_999);
    let authorizer = Authorizer::new(registry, clock_at(1_700_000_000));

    let decision = authorizer
        .authorize(&aud("grace"), AccessAction::ReadRecord, &scope_net())
        .unwrap();
    let entry = authorizer.entry_for_decision(&decision, Some("rec_x")).unwrap();

    let mut store = MemoryEventStore::new();
    let log = StoreAccessLog::new(
        net(),
        safeguard_audit_authorization::SOURCE_LABEL,
        VersionLabel::new("1.0.0").unwrap(),
        clock_at(1_700_000_000),
    );
    log.record_into(&entry, &mut store).unwrap();
    log.record_into(&entry, &mut store).unwrap();

    let records = audit_access_records(&store);
    assert_eq!(records.len(), 1, "access logging must be idempotent");
}
