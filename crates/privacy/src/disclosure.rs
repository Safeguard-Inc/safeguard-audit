//! Record-level disclosure views.
//!
//! [`disclose_details`] and [`redacted_keys`] lift the pure redaction
//! vocabulary onto an [`AuditRecord`]: they classify each detail key with
//! the record's own `redactions` table and fall back to the record's
//! overall `classification` for keys the table does not name. That is the
//! enforcement seam the record model anticipated — the `redactions`
//! field has existed since the domain foundation; this is where it is
//! actually applied before a record's content reaches a reader.
//!
//! The ceiling is [`Option`]: `Some(ceiling)` redacts fields at or above
//! it, while `None` means no classification ceiling applies (the reader's
//! grants cover every classification, e.g. an `All` scope) and every
//! value passes through.
//!
//! [`RecordDisclosure`] packages a view into the shape a reader may
//! actually receive: the public identifiers and metadata pass through
//! untouched, every detail value is disclosed or redacted per the
//! ceiling, and the withheld keys are listed as proof. It is serializable
//! so exporters can emit it directly, and deterministic so the same
//! record and ceiling always project to the same bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use safeguard_audit_core::{
    AuditRecord, DataClassification, EventKind, NetworkId, RecordId, Timestamp,
};

/// The disclosed `details` view of `record` at `ceiling`.
///
/// Keys the record's `redactions` table declares below the ceiling pass
/// through untouched; every other key inherits the record's own
/// classification, so protected values are replaced with the redaction
/// marker rather than leaked. With `ceiling == None` no classification
/// redaction applies and every value passes through. Deterministic for a
/// fixed record and ceiling.
pub fn disclose_details(
    record: &AuditRecord,
    ceiling: Option<DataClassification>,
) -> BTreeMap<String, String> {
    let Some(ceiling) = ceiling else {
        return record.event.details.clone();
    };
    crate::redaction::redact_details(
        &record.event.details,
        &record.redactions,
        record.classification,
        ceiling,
    )
}

/// The detail keys of `record` withheld at `ceiling`, in sorted order.
///
/// The machine-readable proof that accompanies a disclosed view: a
/// consumer can see exactly which fields were treated as protected
/// without having to scan values for the marker. With `ceiling == None`
/// nothing is withheld.
pub fn redacted_keys(record: &AuditRecord, ceiling: Option<DataClassification>) -> Vec<String> {
    let Some(ceiling) = ceiling else {
        return Vec::new();
    };
    crate::redaction::redacted_keys(
        &record.event.details,
        &record.redactions,
        record.classification,
        ceiling,
    )
}

/// The disclosed projection of an [`AuditRecord`] at one ceiling.
///
/// This is the *only* shape a reader may receive. It carries the record's
/// public identifiers and metadata (which are public by construction —
/// references are never protected values), the disclosed `details` view,
/// and the sorted `redacted_keys` list proving which fields were
/// withheld. A protected value can never appear in a redacted
/// projection: disclosure is a projection, never an un-redaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordDisclosure {
    /// The record's deterministic identity.
    pub record_id: RecordId,
    /// The underlying event kind.
    pub kind: EventKind,
    /// The network the record belongs to.
    pub network: NetworkId,
    /// When the record was created.
    pub recorded_at: Timestamp,
    /// Detail values disclosed at the ceiling (protected values replaced
    /// with the redaction marker when a ceiling applies).
    pub details: BTreeMap<String, String>,
    /// The detail keys withheld at the ceiling, in sorted order.
    pub redacted_keys: Vec<String>,
}

impl RecordDisclosure {
    /// Projects `record` at `ceiling`.
    ///
    /// `Some(ceiling)` redacts fields at or above the ceiling; `None`
    /// applies no classification ceiling (every classification is
    /// covered) and discloses every value. Deterministic: the same
    /// record and ceiling always produce the same projection, so
    /// disclosed output can be reproduced and verified.
    pub fn disclose(record: &AuditRecord, ceiling: Option<DataClassification>) -> Self {
        Self {
            record_id: record.record_id.clone(),
            kind: record.event.kind,
            network: record.event.network.clone(),
            recorded_at: record.recorded_at,
            details: disclose_details(record, ceiling),
            redacted_keys: redacted_keys(record, ceiling),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AuditEvent, AuditRecord, EventId, EventKind, EventProvenance, FixedClock, NetworkId,
        OriginKind, Timestamp, VersionLabel,
    };

    const TX_HASH: &str = "abababababababababababababababababababababababababababababababab";

    fn clock() -> FixedClock {
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000))
    }

    fn parser() -> VersionLabel {
        VersionLabel::new("1.0.0").unwrap()
    }

    fn event_with_details(pairs: &[(&str, &str)]) -> AuditEvent {
        let mut event = AuditEvent::new(
            EventId::derive(&["evt"]),
            EventKind::TransferDenied,
            NetworkId::new(NetworkId::TESTNET).unwrap(),
            EventProvenance::new(OriginKind::Derived, "safeguard-audit", parser())
                .unwrap()
                .with_derivation(
                    safeguard_audit_core::DerivationInfo::new(
                        "failed-tx-analysis",
                        vec![],
                        "reconstructed from the failed transaction",
                    )
                    .unwrap(),
                ),
        );
        for (k, v) in pairs {
            event.details.insert((*k).to_owned(), (*v).to_owned());
        }
        event
    }

    fn record(pairs: &[(&str, &str)]) -> AuditRecord {
        AuditRecord::from_event_classified(
            event_with_details(pairs),
            DataClassification::Confidential,
            &clock(),
        )
        .unwrap()
    }

    #[test]
    fn disclosed_view_redacts_protected_details_at_the_record_ceiling() {
        let mut r = record(&[("amount_ciphertext", "enc:deadbeef"), ("note", "denied")]);
        r.redactions.insert(
            "amount_ciphertext".into(),
            DataClassification::HighlyRestricted,
        );
        // The table declares the ciphertext protected; the undeclared
        // note inherits the record's confidential classification.
        let view = disclose_details(&r, Some(DataClassification::Confidential));
        assert_eq!(
            view.get("amount_ciphertext").unwrap(),
            crate::REDACTED_MARKER
        );
        assert_eq!(view.get("note").unwrap(), crate::REDACTED_MARKER);
        assert_eq!(
            redacted_keys(&r, Some(DataClassification::Confidential)),
            vec!["amount_ciphertext", "note"]
        );
    }

    #[test]
    fn disclosed_view_keeps_fields_the_table_declares_public() {
        // A restricted record can still carry public details: keys the
        // field table *declares* below the ceiling pass through, while
        // undeclared keys inherit the record's restricted classification
        // and stay withheld.
        let mut r = record(&[("transaction_hash", TX_HASH), ("amount", "1.5")]);
        r.classification = DataClassification::Restricted;
        r.redactions
            .insert("transaction_hash".into(), DataClassification::Public);
        r.redactions
            .insert("amount".into(), DataClassification::HighlyRestricted);
        let view = disclose_details(&r, Some(DataClassification::Confidential));
        assert_eq!(view.get("transaction_hash").unwrap(), TX_HASH);
        assert_eq!(view.get("amount").unwrap(), crate::REDACTED_MARKER);
        // The hash is not withheld; the amount is.
        assert_eq!(
            redacted_keys(&r, Some(DataClassification::Confidential)),
            vec!["amount"]
        );

        // Without the declaration, the same hash would inherit the
        // record's restricted classification and be withheld too.
        let mut plain = record(&[("transaction_hash", TX_HASH)]);
        plain.classification = DataClassification::Restricted;
        assert_eq!(
            disclose_details(&plain, Some(DataClassification::Confidential))
                .get("transaction_hash")
                .unwrap(),
            crate::REDACTED_MARKER
        );
    }

    #[test]
    fn an_empty_table_still_protects_at_the_record_level() {
        // Today's records carry an empty `redactions` table, so the
        // record's own classification is the floor: nothing undeclared
        // is silently public.
        let r = record(&[("note", "matched class B")]);
        assert_eq!(
            disclose_details(&r, Some(DataClassification::Confidential))
                .get("note")
                .unwrap(),
            crate::REDACTED_MARKER
        );
        // A senior auditor with a restricted ceiling sees it.
        assert_eq!(
            disclose_details(&r, Some(DataClassification::Restricted))
                .get("note")
                .unwrap(),
            "matched class B"
        );
    }

    #[test]
    fn disclosure_is_deterministic() {
        let r = record(&[("a", "1"), ("b", "2")]);
        let ceiling = Some(DataClassification::Confidential);
        assert_eq!(disclose_details(&r, ceiling), disclose_details(&r, ceiling));
        assert_eq!(redacted_keys(&r, ceiling), redacted_keys(&r, ceiling));
    }

    #[test]
    fn a_disclosed_projection_never_contains_a_protected_value() {
        let secret = "enc:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f";
        let mut r = record(&[("amount_ciphertext", secret), ("note", "denied")]);
        r.redactions.insert(
            "amount_ciphertext".into(),
            DataClassification::HighlyRestricted,
        );
        let view = RecordDisclosure::disclose(&r, Some(DataClassification::Confidential));

        // The projection's serialized bytes must not contain the value.
        let json = serde_json::to_string(&view).unwrap();
        assert!(
            !json.contains(secret),
            "protected value leaked into disclosure"
        );
        assert!(json.contains("[redacted]"));

        // Public identifiers survive for correlation.
        assert_eq!(view.record_id, r.record_id);
        assert_eq!(view.kind, EventKind::TransferDenied);
        assert_eq!(view.network, r.event.network);
        assert_eq!(view.recorded_at, r.recorded_at);
        assert_eq!(view.redacted_keys, vec!["amount_ciphertext", "note"]);
    }

    #[test]
    fn no_ceiling_discloses_every_value() {
        // `disclosure_ceiling` returns None when grants cover every
        // classification (an `All` scope, or a highly-restricted grant);
        // the projection must be able to express "no redaction".
        let mut r = record(&[("amount_ciphertext", "enc:beef"), ("note", "denied")]);
        r.redactions.insert(
            "amount_ciphertext".into(),
            DataClassification::HighlyRestricted,
        );
        let view = RecordDisclosure::disclose(&r, None);
        assert_eq!(view.details.get("amount_ciphertext").unwrap(), "enc:beef");
        assert_eq!(view.details.get("note").unwrap(), "denied");
        assert!(view.redacted_keys.is_empty());
    }

    #[test]
    fn projection_is_deterministic_and_round_trips() {
        let mut r = record(&[("a", "1"), ("b", "2"), ("secret", "s")]);
        r.redactions
            .insert("secret".into(), DataClassification::HighlyRestricted);
        let ceiling = Some(DataClassification::Confidential);
        let first = RecordDisclosure::disclose(&r, ceiling);
        let second = RecordDisclosure::disclose(&r, ceiling);
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        // And the projection survives the wire.
        let back: RecordDisclosure =
            serde_json::from_str(&serde_json::to_string(&first).unwrap()).unwrap();
        assert_eq!(back, first);
    }

    #[test]
    fn marker_bearing_keys_and_the_proof_list_always_agree() {
        let mut r = record(&[
            ("reason", "POLICY_DENIED"),
            ("amount", "1.5"),
            ("note", "class B"),
        ]);
        r.redactions
            .insert("amount".into(), DataClassification::HighlyRestricted);
        r.redactions
            .insert("note".into(), DataClassification::Restricted);
        let view = RecordDisclosure::disclose(&r, Some(DataClassification::Confidential));
        let marker_keys: Vec<&String> = view
            .details
            .iter()
            .filter(|(_, v)| crate::is_redacted(v))
            .map(|(k, _)| k)
            .collect();
        // All three keys are withheld: amount and note by the table
        // (highly-restricted and restricted), reason because it is
        // undeclared and inherits the record's confidential level, which
        // is at the ceiling.
        assert_eq!(view.redacted_keys.len(), marker_keys.len());
        assert_eq!(view.redacted_keys, vec!["amount", "note", "reason"]);
        assert!(marker_keys.contains(&&"amount".to_owned()));
    }
}
