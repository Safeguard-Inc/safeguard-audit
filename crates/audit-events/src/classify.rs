//! Declared sensitivity of derived-event detail keys.
//!
//! Every `details` value a semantic event writes is classified here, so
//! the record's `redactions` table — the field-level vocabulary
//! `audit-core` has carried since the domain foundation — gets populated
//! when a derived event becomes a record, and disclosure at a ceiling
//! shows operational metadata instead of over-redacting it.
//!
//! The declarations are deliberately conservative:
//!
//! * **`public`** — event class names and digest hashes, which are
//!   ledger-visible vocabulary, not private information;
//! * **`operational`** — internal correlation labels and counts (report,
//!   evidence, case, actor, manifest, status, record counts);
//! * **`confidential`** — short prose that can carry context (an
//!   investigation summary or closure reason).
//!
//! Nothing is ever declared `restricted` or `highly-restricted` here.
//! Truly protected values (amounts, ciphertexts, decrypted data) are not
//! recorded on these events at all; if one ever appears it stays
//! *undeclared*, inherits the record's own classification at disclosure,
//! and belongs to the `DecryptionProvider` boundary — never to a
//! registry that would normalize it into routine metadata.

use safeguard_audit_core::privacy::FieldClassifications;
use safeguard_audit_core::{AuditEvent, DataClassification, EventKind};

/// The field-level classification table for `event`: the declared
/// sensitivity of every detail key the event actually carries.
///
/// Keys the event does not carry are never listed, so a stamped record
/// names exactly its own fields and no dangling policy rides along in its
/// canonical bytes.
pub fn detail_policy(event: &AuditEvent) -> FieldClassifications {
    let mut policy = FieldClassifications::new();
    for (key, classification) in declared(event.kind) {
        if event.details.contains_key(*key) {
            policy.insert((*key).to_owned(), *classification);
        }
    }
    policy
}

/// The declared key -> classification table for a kind's detail fields.
fn declared(kind: EventKind) -> &'static [(&'static str, DataClassification)] {
    match kind {
        EventKind::ReportGenerated => &[
            ("report", DataClassification::Operational),
            ("kind", DataClassification::Public),
            ("records", DataClassification::Operational),
            ("digest", DataClassification::Public),
        ],
        EventKind::EvidenceGenerated => &[
            ("evidence", DataClassification::Operational),
            ("kind", DataClassification::Public),
            ("records", DataClassification::Operational),
            ("manifest", DataClassification::Operational),
            ("digest", DataClassification::Public),
        ],
        EventKind::InvestigationOpened
        | EventKind::InvestigationUpdated
        | EventKind::InvestigationClosed => &[
            ("case", DataClassification::Operational),
            ("actor", DataClassification::Operational),
            ("status", DataClassification::Operational),
            ("summary", DataClassification::Confidential),
        ],
        // Kinds without declared detail keys (observed on-chain events,
        // transfer outcomes, access records, ...) keep an empty policy:
        // their undeclared values inherit the record's own classification
        // at disclosure, which is the conservative default.
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditorId, CaseId, CaseStatus, EvidenceId, EvidenceKind, IntegrityDigest, ManifestId,
        NetworkId, ReportId, ReportKind, Timestamp, VersionLabel,
    };

    use crate::event_id::EventSlot;
    use crate::evidence::EvidenceLifecycle;
    use crate::investigation::{InvestigationLifecycle, LifecycleKind};
    use crate::report::ReportLifecycle;

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn parser() -> VersionLabel {
        VersionLabel::new("1.0.0").unwrap()
    }

    #[test]
    fn report_policy_classifies_every_declared_field_and_only_present_ones() {
        let with_digest = ReportLifecycle {
            network: network(),
            source: "safeguard-audit-reporting".into(),
            parser: parser(),
            report: ReportId::derive(&["r1"]),
            kind: ReportKind::DeniedTransactions,
            record_count: 3,
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        };
        let event = with_digest.into_audit_event(EventSlot::default()).unwrap();
        let policy = detail_policy(&event);
        assert_eq!(policy.get("report"), Some(&DataClassification::Operational));
        assert_eq!(policy.get("kind"), Some(&DataClassification::Public));
        assert_eq!(
            policy.get("records"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(policy.get("digest"), Some(&DataClassification::Public));
        // Every declared key is actually present on the event.
        assert_eq!(policy.len(), event.details.len());

        // Without a digest the policy drops the digest entry entirely —
        // a stamped record never names a field the event does not carry.
        let bare = ReportLifecycle {
            digest: None,
            ..with_digest
        };
        let event = bare.into_audit_event(EventSlot::default()).unwrap();
        let policy = detail_policy(&event);
        assert_eq!(policy.len(), event.details.len());
        assert!(!policy.contains_key("digest"));
    }

    #[test]
    fn evidence_policy_covers_artifact_references_and_hashes() {
        let lifecycle = EvidenceLifecycle {
            network: network(),
            source: "safeguard-audit-evidence".into(),
            parser: parser(),
            evidence: EvidenceId::derive(&["ev1"]),
            kind: EvidenceKind::TransactionEvidence,
            record_count: 1,
            manifest: Some(ManifestId::derive(&["m1"])),
            digest: Some(IntegrityDigest::sha256("ab".repeat(32)).unwrap()),
        };
        let event = lifecycle.into_audit_event(EventSlot::default()).unwrap();
        let policy = detail_policy(&event);
        assert_eq!(
            policy.get("evidence"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(policy.get("kind"), Some(&DataClassification::Public));
        assert_eq!(
            policy.get("manifest"),
            Some(&DataClassification::Operational)
        );
        assert_eq!(policy.get("digest"), Some(&DataClassification::Public));
        assert_eq!(policy.len(), event.details.len());
    }

    #[test]
    fn investigation_policy_treats_summary_as_confidential_and_rest_as_operational() {
        fn lifecycle(summary: Option<&str>) -> InvestigationLifecycle {
            InvestigationLifecycle {
                network: network(),
                source: "safeguard-audit-investigations".into(),
                parser: parser(),
                case: CaseId::derive(&["c1"]),
                actor: AuditorId::derive(&["aud-1"]),
                kind: LifecycleKind::Closed,
                sequence: 0,
                status: CaseStatus::Closed,
                summary: summary.map(str::to_owned),
            }
        }

        let with_summary = lifecycle(Some("closure reason: resolved"))
            .into_audit_event(EventSlot::default())
            .unwrap();
        let policy = detail_policy(&with_summary);
        assert_eq!(policy.get("case"), Some(&DataClassification::Operational));
        assert_eq!(policy.get("actor"), Some(&DataClassification::Operational));
        assert_eq!(policy.get("status"), Some(&DataClassification::Operational));
        assert_eq!(
            policy.get("summary"),
            Some(&DataClassification::Confidential)
        );
        assert_eq!(policy.len(), with_summary.details.len());

        let bare = lifecycle(None)
            .into_audit_event(EventSlot::default())
            .unwrap();
        let policy = detail_policy(&bare);
        assert!(!policy.contains_key("summary"));
        assert_eq!(policy.len(), bare.details.len());
    }

    #[test]
    fn nothing_is_ever_declared_restricted_or_higher() {
        // The registry is a declaration of *routine* metadata; genuinely
        // protected values stay undeclared and inherit the record's own
        // classification at disclosure.
        for kind in EventKind::ALL {
            for (_, classification) in declared(*kind) {
                assert!(
                    !classification.is_at_least(DataClassification::Restricted),
                    "{kind:?} declares {classification:?}, above the registry ceiling"
                );
            }
        }
    }

    #[test]
    fn kinds_without_declarations_yield_an_empty_policy() {
        // Observed and transfer-outcome events carry no declared keys; an
        // empty policy keeps the conservative default (their values, if
        // any, inherit the record's own classification).
        let mut event = safeguard_audit_core::AuditEvent::new(
            safeguard_audit_core::EventId::derive(&["x"]),
            EventKind::TransferDenied,
            network(),
            safeguard_audit_core::EventProvenance::new(
                safeguard_audit_core::OriginKind::Derived,
                "safeguard-audit",
                parser(),
            )
            .unwrap(),
        );
        event.details.insert("note".into(), "denied".into());
        assert!(detail_policy(&event).is_empty());

        let event = crate::authorization::access_recorded_event(
            &safeguard_audit_core::AuditAccessEntry::new(
                safeguard_audit_core::AccessEntryId::derive(&["a1"]),
                AuditorId::derive(&["a1"]),
                safeguard_audit_core::AccessAction::ReadRecord,
                "network:testnet".into(),
                None,
                safeguard_audit_core::AccessResult::Granted,
                Timestamp::from_unix_seconds(100),
            ),
            network(),
            "safeguard-audit-authorization",
            parser(),
            EventSlot::default(),
        )
        .unwrap();
        // Access entries carry operational detail keys that are not part
        // of the derived-lifecycle registry; their records still protect
        // at the record's own classification.
        assert!(detail_policy(&event).is_empty());
        assert!(!event.details.is_empty());
    }
}
