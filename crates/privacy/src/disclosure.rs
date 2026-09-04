//! Record-level disclosure views.
//!
//! [`disclose_details`] and [`redacted_keys`] lift the pure redaction
//! vocabulary onto an [`AuditRecord`]: they classify each detail key with
//! the record's own `redactions` table and fall back to the record's
//! overall `classification` for keys the table does not name. That is the
//! enforcement seam the record model anticipated — the `redactions`
//! field has existed since the domain foundation; this is where it is
//! actually applied before a record's content reaches a reader.

use std::collections::BTreeMap;

use safeguard_audit_core::{AuditRecord, DataClassification};

use crate::redaction::redact_details;

/// The disclosed `details` view of `record` at `ceiling`.
///
/// Keys the record's `redactions` table declares below the ceiling pass
/// through untouched; every other key inherits the record's own
/// classification, so protected values are replaced with the redaction
/// marker rather than leaked. Deterministic for a fixed record and
/// ceiling.
pub fn disclose_details(
    record: &AuditRecord,
    ceiling: DataClassification,
) -> BTreeMap<String, String> {
    redact_details(
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
/// without having to scan values for the marker.
pub fn redacted_keys(record: &AuditRecord, ceiling: DataClassification) -> Vec<String> {
    crate::redaction::redacted_keys(
        &record.event.details,
        &record.redactions,
        record.classification,
        ceiling,
    )
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
        let view = disclose_details(&r, DataClassification::Confidential);
        assert_eq!(
            view.get("amount_ciphertext").unwrap(),
            crate::REDACTED_MARKER
        );
        assert_eq!(view.get("note").unwrap(), crate::REDACTED_MARKER);
        assert_eq!(
            redacted_keys(&r, DataClassification::Confidential),
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
        let view = disclose_details(&r, DataClassification::Confidential);
        assert_eq!(view.get("transaction_hash").unwrap(), TX_HASH);
        assert_eq!(view.get("amount").unwrap(), crate::REDACTED_MARKER);
        // The hash is not withheld; the amount is.
        assert_eq!(
            redacted_keys(&r, DataClassification::Confidential),
            vec!["amount"]
        );

        // Without the declaration, the same hash would inherit the
        // record's restricted classification and be withheld too.
        let mut plain = record(&[("transaction_hash", TX_HASH)]);
        plain.classification = DataClassification::Restricted;
        assert_eq!(
            disclose_details(&plain, DataClassification::Confidential)
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
            disclose_details(&r, DataClassification::Confidential)
                .get("note")
                .unwrap(),
            crate::REDACTED_MARKER
        );
        // A senior auditor with a restricted ceiling sees it.
        assert_eq!(
            disclose_details(&r, DataClassification::Restricted)
                .get("note")
                .unwrap(),
            "matched class B"
        );
    }

    #[test]
    fn disclosure_is_deterministic() {
        let r = record(&[("a", "1"), ("b", "2")]);
        let ceiling = DataClassification::Confidential;
        assert_eq!(disclose_details(&r, ceiling), disclose_details(&r, ceiling));
        assert_eq!(redacted_keys(&r, ceiling), redacted_keys(&r, ceiling));
    }
}
