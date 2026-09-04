//! Privacy enforcement across the real boundaries.
//!
//! The privacy crate derives a disclosure ceiling from an auditor's
//! scopes; the authorization crate decides what those scopes cover. These
//! tests pin the two to each other *as implemented*: for every grant and
//! every field classification, a field is disclosed at the derived
//! ceiling exactly when the authorizer would answer yes, and a record
//! fetched from the store discloses precisely its covered fields —
//! nothing more, even when serialized.

use safeguard_audit_authorization::scopes::covers_classification;
use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessScope, AuditEvent, AuditRecord, AuditorId, AuditorRole, DataClassification,
    DerivationInfo, EventId, EventKind, EventProvenance, FixedClock, NetworkId, OriginKind,
    PageRequest, ReportKind, ReportQuery, ReportRequest, Timestamp, VersionLabel,
};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_privacy::redaction::is_disclosable;
use safeguard_audit_privacy::{disclosure_ceiling, RecordDisclosure};
use safeguard_audit_reporting::ReportService;
use safeguard_audit_storage::{AuditQuery, EventStore, InsertOutcome};

/// Every classification level, most public to most protected.
const LEVELS: [DataClassification; 5] = [
    DataClassification::Public,
    DataClassification::Operational,
    DataClassification::Confidential,
    DataClassification::Restricted,
    DataClassification::HighlyRestricted,
];

fn net() -> NetworkId {
    NetworkId::new(NetworkId::TESTNET).unwrap()
}

fn parser() -> VersionLabel {
    VersionLabel::new("1.0.0").unwrap()
}

fn clock() -> FixedClock {
    FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000))
}

#[test]
fn the_derived_ceiling_discloses_exactly_what_the_authorizer_covers() {
    // For a single classification grant at every level, a field is
    // disclosed at the derived ceiling exactly when covers_classification
    // would grant it — the privacy crate and the authorizer must agree as
    // implemented, not just by design.
    for granted in LEVELS {
        let scopes = [AccessScope::Classification(granted)];
        let ceiling = disclosure_ceiling(&scopes);
        for field in LEVELS {
            let covered = covers_classification(&scopes, field);
            let disclosed = match ceiling {
                Some(ceiling) => is_disclosable(field, ceiling),
                None => true,
            };
            assert_eq!(
                disclosed, covered,
                "grant {granted:?} must disclose {field:?} exactly when the authorizer covers it"
            );
        }
    }

    // `All` covers every classification and yields no ceiling.
    let all = [AccessScope::All];
    assert_eq!(disclosure_ceiling(&all), None);
    assert!(covers_classification(
        &all,
        DataClassification::HighlyRestricted
    ));

    // No grants cover anything, and the derived public ceiling discloses
    // nothing either.
    let none: [AccessScope; 0] = [];
    let ceiling = disclosure_ceiling(&none).unwrap();
    assert_eq!(ceiling, DataClassification::Public);
    for field in LEVELS {
        assert!(!covers_classification(&none, field));
        assert!(!is_disclosable(field, ceiling));
    }

    // Mixed classification grants behave as their most sensitive member,
    // on both sides of the boundary.
    let mixed = [
        AccessScope::Classification(DataClassification::Confidential),
        AccessScope::Classification(DataClassification::Restricted),
    ];
    assert_eq!(
        disclosure_ceiling(&mixed),
        Some(DataClassification::HighlyRestricted)
    );
    assert!(covers_classification(
        &mixed,
        DataClassification::Restricted
    ));
    assert!(!covers_classification(
        &mixed,
        DataClassification::HighlyRestricted
    ));
}

#[test]
fn a_stored_record_discloses_exactly_its_covered_fields() {
    const TX_HASH: &str = "abababababababababababababababababababababababababababababababab";
    let secret = "enc:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f";

    // A restricted record carrying a public transaction hash, a
    // highly-restricted ciphertext, and an undeclared note.
    let mut event = AuditEvent::new(
        EventId::derive(&["privacy-seed"]),
        EventKind::TransferDenied,
        net(),
        EventProvenance::new(OriginKind::Derived, "safeguard-audit", parser())
            .unwrap()
            .with_derivation(
                DerivationInfo::new(
                    "failed-tx-analysis",
                    vec![],
                    "reconstructed from the failed transaction",
                )
                .unwrap(),
            ),
    );
    event
        .details
        .insert("transaction_hash".into(), TX_HASH.into());
    event
        .details
        .insert("amount_ciphertext".into(), secret.into());
    event
        .details
        .insert("note".into(), "matched class B".into());

    let mut record =
        AuditRecord::from_event_classified(event, DataClassification::Restricted, &clock())
            .unwrap();
    record
        .redactions
        .insert("transaction_hash".into(), DataClassification::Public);
    record.redactions.insert(
        "amount_ciphertext".into(),
        DataClassification::HighlyRestricted,
    );

    let mut store = MemoryEventStore::new();
    store.insert(record).expect("seeded record inserts");

    // The auditor with a restricted grant reads the record back through
    // the store: the authorizer covers it, and the record is exactly as
    // seeded.
    let scopes = vec![AccessScope::Classification(DataClassification::Restricted)];
    let page = store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(10).unwrap(),
        )
        .unwrap();
    let fetched = &page.items()[0];
    assert!(covers_classification(&scopes, fetched.classification));

    // Disclosure at the derived ceiling shows the public hash and the
    // covered note, redacts the ciphertext, and proves what was withheld.
    let view = RecordDisclosure::disclose(fetched, disclosure_ceiling(&scopes));
    assert_eq!(view.details.get("transaction_hash").unwrap(), TX_HASH);
    assert_eq!(view.details.get("amount_ciphertext").unwrap(), "[redacted]");
    assert_eq!(view.details.get("note").unwrap(), "matched class B");
    assert_eq!(view.redacted_keys, vec!["amount_ciphertext"]);
    let json = serde_json::to_string(&view).unwrap();
    assert!(
        !json.contains(secret),
        "protected value leaked into disclosure"
    );

    // An `All` reader covers everything: no ceiling, every value shown.
    let all_view = RecordDisclosure::disclose(fetched, disclosure_ceiling(&[AccessScope::All]));
    assert_eq!(all_view.details.get("amount_ciphertext").unwrap(), secret);
    assert!(all_view.redacted_keys.is_empty());
}

#[test]
fn a_service_generated_record_discloses_its_operational_attribution() {
    // Drive the real stack: a denied transfer is recorded, the reporting
    // service generates a report over it, and the report-generated record
    // that lands on the trail carries the declared field policy — so a
    // reader at a confidential ceiling sees the operational attribution
    // facts instead of a wall of redaction markers.
    let actor = AuditorId::derive(&["senior-1"]);
    let clock = FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000));
    let mut registry = Registry::new();
    registry
        .register(
            Grant::new(actor.clone(), AuditorRole::SeniorAuditor)
                .with_scope(AccessScope::Network(net()))
                .with_credential(Credential::new(
                    actor.clone(),
                    "material",
                    Timestamp::from_unix_seconds(9_999_999_999),
                )),
        )
        .unwrap();
    let authorizer = Authorizer::new(registry, clock);
    let service = ReportService::new(
        net(),
        "safeguard-audit-reporting",
        VersionLabel::new("1.0.0").unwrap(),
        VersionLabel::new("0.6.0").unwrap(),
        clock,
        authorizer,
    );

    let mut audit = MemoryEventStore::new();
    let mut denied = AuditEvent::new(
        EventId::derive(&["denied-1"]),
        EventKind::TransferDenied,
        net(),
        EventProvenance::new(
            OriginKind::Derived,
            "safeguard-audit",
            VersionLabel::new("1.0.0").unwrap(),
        )
        .unwrap()
        .with_derivation(
            DerivationInfo::new(
                "failed-tx-analysis",
                vec![],
                "reconstructed from the failed transaction",
            )
            .unwrap(),
        ),
    );
    denied.outcome = Some(safeguard_audit_core::DecisionResult::Denied);
    denied.observed_at = Some(Timestamp::from_unix_seconds(100));
    let record = AuditRecord::from_event_classified(
        denied,
        DataClassification::Confidential,
        &FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000)),
    )
    .unwrap();
    assert_eq!(audit.insert(record), Ok(InsertOutcome::Inserted));

    let request = ReportRequest::new(
        ReportKind::DeniedTransactions,
        ReportQuery::with_outcome(safeguard_audit_core::DecisionResult::Denied),
        actor,
        Timestamp::from_unix_seconds(1_699_999_999),
    );
    service.generate(&mut audit, &request).unwrap();

    // Find the report-generated record the service recorded on the trail.
    let page = audit
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(10).unwrap(),
        )
        .unwrap();
    let generated = page
        .items()
        .iter()
        .find(|r| r.event.kind == EventKind::ReportGenerated)
        .expect("generation is recorded on the trail");
    assert!(!generated.redactions.is_empty());

    // At a confidential ceiling the declared operational fields disclose;
    // nothing protected is ever in the serialized projection.
    let view = RecordDisclosure::disclose(generated, Some(DataClassification::Confidential));
    assert_eq!(view.details.get("kind").unwrap(), "denied-transactions");
    assert_eq!(view.details.get("records").unwrap(), "1");
    assert!(!view.details.values().any(|v| v == "[redacted]"));
    assert!(view.redacted_keys.is_empty());
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("denied-transactions"));
}
