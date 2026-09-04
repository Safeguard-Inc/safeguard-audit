//! Deterministic redaction of protected detail values.
//!
//! A record's `details` map is the only free-form content on the audit
//! envelope, and its per-field `redactions` table declares how sensitive
//! each key is. [`redact_details`] produces the view a reader may see at a
//! given disclosure ceiling: every value whose classification is at or
//! above the ceiling is replaced wholesale with [`REDACTED_MARKER`], keys
//! are never dropped, and nothing below the ceiling is touched.
//!
//! Redaction never *reveals*: a protected value is replaced, not
//! truncated or blurred, so no partial information survives. And it is
//! deterministic — same details, same table, same ceiling, same output —
//! so two runs over the same records cannot disagree about what was
//! withheld.

use std::collections::BTreeMap;

use safeguard_audit_core::privacy::FieldClassifications;
use safeguard_audit_core::DataClassification;

/// The marker substituted for a protected value in disclosed output.
///
/// Consumers should interpret redaction through the redacted-keys list,
/// not by scanning values: a legitimate detail value could in principle
/// equal this string. The marker exists so *display* never silently
/// omits a field — the reader sees that something was withheld.
pub const REDACTED_MARKER: &str = "[redacted]";

/// Whether `value` is the redaction marker.
pub fn is_redacted(value: &str) -> bool {
    value == REDACTED_MARKER
}

/// The classification a detail key is treated as: its declared table
/// entry when present, `default` otherwise.
///
/// Callers pass the record's own classification as `default`, so detail
/// keys the table does not name are never silently public — an empty
/// `redactions` table still protects at the record level.
pub fn field_classification(
    key: &str,
    redactions: &FieldClassifications,
    default: DataClassification,
) -> DataClassification {
    redactions.get(key).copied().unwrap_or(default)
}

/// Whether a field of `classification` may be disclosed at `ceiling`.
///
/// Mirrors the record-level rule the reporting service enforces: values
/// at or above the ceiling are excluded (`is_at_least`), values strictly
/// below it pass through.
pub fn is_disclosable(classification: DataClassification, ceiling: DataClassification) -> bool {
    !classification.is_at_least(ceiling)
}

/// Produces the redacted view of `details` at `ceiling`.
///
/// Every key survives. A key whose classification is at or above the
/// ceiling keeps its name but has its value replaced with
/// [`REDACTED_MARKER`]; every other value passes through byte-for-byte.
/// Undeclared keys are classified as `default` (the record's own
/// classification). The result is deterministic: the same inputs always
/// yield the same map.
pub fn redact_details(
    details: &BTreeMap<String, String>,
    redactions: &FieldClassifications,
    default: DataClassification,
    ceiling: DataClassification,
) -> BTreeMap<String, String> {
    details
        .iter()
        .map(|(key, value)| {
            let classification = field_classification(key, redactions, default);
            let disclosed = if is_disclosable(classification, ceiling) {
                value.clone()
            } else {
                REDACTED_MARKER.to_owned()
            };
            (key.clone(), disclosed)
        })
        .collect()
}

/// The detail keys whose values were redacted at `ceiling`, in sorted
/// order — the machine-readable proof of what was withheld.
pub fn redacted_keys(
    details: &BTreeMap<String, String>,
    redactions: &FieldClassifications,
    default: DataClassification,
    ceiling: DataClassification,
) -> Vec<String> {
    details
        .iter()
        .filter(|(key, _)| {
            let classification = field_classification(key, redactions, default);
            !is_disclosable(classification, ceiling)
        })
        .map(|(key, _)| key.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn table(pairs: &[(&str, DataClassification)]) -> FieldClassifications {
        pairs.iter().map(|(k, c)| ((*k).to_owned(), *c)).collect()
    }

    #[test]
    fn values_below_the_ceiling_pass_through_untouched() {
        let redactions = table(&[
            ("note", DataClassification::Public),
            ("policy_reference", DataClassification::Confidential),
        ]);
        let out = redact_details(
            &details(&[
                ("note", "bound to enforcement"),
                ("policy_reference", "v1.2"),
            ]),
            &redactions,
            DataClassification::Confidential,
            DataClassification::Restricted,
        );
        assert_eq!(out.get("note").unwrap(), "bound to enforcement");
        assert_eq!(out.get("policy_reference").unwrap(), "v1.2");
    }

    #[test]
    fn values_at_or_above_the_ceiling_are_replaced_wholesale() {
        let redactions = table(&[
            ("amount", DataClassification::HighlyRestricted),
            ("policy_internal", DataClassification::Restricted),
            ("public_note", DataClassification::Public),
        ]);
        let out = redact_details(
            &details(&[
                ("amount", "1234.567890"),
                ("policy_internal", "rule matched: class B"),
                ("public_note", "denied by policy"),
            ]),
            &redactions,
            DataClassification::Confidential,
            DataClassification::Confidential,
        );
        // Highly-restricted and restricted values are gone; nothing of the
        // original value survives (replaced, never truncated).
        assert_eq!(out.get("amount").unwrap(), REDACTED_MARKER);
        assert_eq!(out.get("policy_internal").unwrap(), REDACTED_MARKER);
        assert!(!out.get("amount").unwrap().contains("1234"));
        assert_eq!(out.get("public_note").unwrap(), "denied by policy");
    }

    #[test]
    fn undeclared_keys_inherit_the_default_classification() {
        // No table at all: every key is treated at the record's own
        // classification, so an empty table still protects.
        let out = redact_details(
            &details(&[("note", "matched class B")]),
            &FieldClassifications::new(),
            DataClassification::Confidential,
            DataClassification::Confidential,
        );
        assert_eq!(out.get("note").unwrap(), REDACTED_MARKER);

        // At a higher ceiling the same undeclared key is disclosed.
        let out = redact_details(
            &details(&[("note", "matched class B")]),
            &FieldClassifications::new(),
            DataClassification::Confidential,
            DataClassification::Restricted,
        );
        assert_eq!(out.get("note").unwrap(), "matched class B");
    }

    #[test]
    fn redaction_is_deterministic_and_preserves_keys() {
        let redactions = table(&[("amount", DataClassification::HighlyRestricted)]);
        let source = details(&[
            ("amount", "1.5"),
            ("reason", "POLICY_DENIED"),
            ("note", "flagged"),
        ]);
        let ceiling = DataClassification::Confidential;
        let a = redact_details(
            &source,
            &redactions,
            DataClassification::Confidential,
            ceiling,
        );
        let b = redact_details(
            &source,
            &redactions,
            DataClassification::Confidential,
            ceiling,
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), source.len(), "keys are preserved, never dropped");
        assert!(a.contains_key("amount"));
        assert!(a.contains_key("reason"));
    }

    #[test]
    fn redacted_keys_list_is_the_machine_readable_proof() {
        let redactions = table(&[
            ("amount", DataClassification::HighlyRestricted),
            ("reason", DataClassification::Public),
            ("policy_internal", DataClassification::Restricted),
        ]);
        let source = details(&[
            ("amount", "1.5"),
            ("reason", "POLICY_DENIED"),
            ("policy_internal", "class B"),
        ]);
        let ceiling = DataClassification::Confidential;
        let keys = redacted_keys(
            &source,
            &redactions,
            DataClassification::Confidential,
            ceiling,
        );
        assert_eq!(keys, vec!["amount", "policy_internal"]);

        let view = redact_details(
            &source,
            &redactions,
            DataClassification::Confidential,
            ceiling,
        );
        // The list agrees with the view: exactly the marker-bearing keys.
        let from_view: Vec<String> = view
            .iter()
            .filter(|(_, v)| is_redacted(v))
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(keys, from_view);
    }

    #[test]
    fn the_disclosable_predicate_mirrors_the_report_ceiling_rule() {
        // Strictly below the ceiling passes; at or above is excluded —
        // the same `is_at_least` rule the reporting service applies to
        // whole records.
        assert!(is_disclosable(
            DataClassification::Confidential,
            DataClassification::Restricted
        ));
        assert!(!is_disclosable(
            DataClassification::Restricted,
            DataClassification::Restricted
        ));
        assert!(!is_disclosable(
            DataClassification::HighlyRestricted,
            DataClassification::Restricted
        ));
    }
}
