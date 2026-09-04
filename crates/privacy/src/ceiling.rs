//! Deriving a disclosure ceiling from an auditor's granted scopes.
//!
//! Redaction is only meaningful when the ceiling matches what the reader
//! is actually allowed to see. An auditor's grants are [`AccessScope`]s,
//! and classification grants are directional: `authorization::scopes`
//! covers a classification request only when the grant is at least as
//! sensitive (`granted >= requested`). This module maps the granted
//! classification scopes onto the disclosure ceiling that discloses
//! exactly the classifications the authorizer would cover:
//!
//! * no `All` and no `Classification` grant → `Some(Public)` — no field
//!   classified at `public` or above is disclosed;
//! * the most sensitive `Classification(g)` grant → the least level
//!   strictly above `g`, so fields up to and including `g` pass through
//!   (`classification < ceiling`) while more sensitive fields redact;
//! * `All`, or a `HighlyRestricted` grant → `None` — every
//!   classification is covered, so no classification redaction applies.
//!
//! The mapping is defined to stay in step with the authorizer: a field of
//! classification `c` is disclosed at the derived ceiling exactly when
//! `covers_classification(granted, c)` would answer yes.
//!
//! `None` must not be read as "redact everything": callers that receive
//! `None` disclose without a classification ceiling (the holder is
//! covered for every classification). Decrypted values remain a separate
//! surface governed by the future `DecryptionProvider` boundary, never by
//! a classification grant alone.

use safeguard_audit_core::{AccessScope, DataClassification};

/// The classification strictly more sensitive than `classification`, or
/// `None` when there is none (nothing is more sensitive than
/// `HighlyRestricted`).
fn next_level(classification: DataClassification) -> Option<DataClassification> {
    match classification {
        DataClassification::Public => Some(DataClassification::Operational),
        DataClassification::Operational => Some(DataClassification::Confidential),
        DataClassification::Confidential => Some(DataClassification::Restricted),
        DataClassification::Restricted => Some(DataClassification::HighlyRestricted),
        DataClassification::HighlyRestricted => None,
    }
}

/// The disclosure ceiling implied by `granted` scopes.
///
/// `Some(ceiling)` means: disclose detail fields whose classification is
/// strictly below `ceiling`, redact the rest. `None` means no
/// classification ceiling applies — every classification is covered, so
/// redaction should not be applied on classification grounds.
pub fn disclosure_ceiling(granted: &[AccessScope]) -> Option<DataClassification> {
    let mut most_sensitive: Option<DataClassification> = None;
    for scope in granted {
        match scope {
            AccessScope::All => return None,
            AccessScope::Classification(c) => {
                most_sensitive = Some(match most_sensitive {
                    Some(current) => current.max(*c),
                    None => *c,
                });
            }
            // Non-classification scopes never affect classification
            // coverage; the authorizer requires a classification grant
            // for classified data no matter what else is granted.
            _ => {}
        }
    }
    match most_sensitive {
        // No classification grant at all: nothing classified is covered.
        None => Some(DataClassification::Public),
        Some(most_sensitive) => next_level(most_sensitive),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::is_disclosable;
    use safeguard_audit_core::{NetworkId, TokenReference};

    fn classification(c: DataClassification) -> AccessScope {
        AccessScope::Classification(c)
    }

    fn token_scope() -> AccessScope {
        let net = NetworkId::new(NetworkId::TESTNET).unwrap();
        AccessScope::Token(TokenReference::for_contract(
            net,
            safeguard_audit_core::ContractId::new(&format!("C{}", "A".repeat(55))).unwrap(),
        ))
    }

    #[test]
    fn no_classification_grant_discloses_nothing() {
        // Even other grants (network, token) never imply a classification
        // ceiling; without a classification scope nothing classified is
        // disclosed.
        assert_eq!(disclosure_ceiling(&[]), Some(DataClassification::Public));
        assert_eq!(
            disclosure_ceiling(&[token_scope()]),
            Some(DataClassification::Public)
        );
        // Public itself is at the ceiling: nothing at or above public
        // passes, and every classification is at or above public.
        let ceiling = disclosure_ceiling(&[]).unwrap();
        assert!(!is_disclosable(DataClassification::Public, ceiling));
        assert!(!is_disclosable(DataClassification::Confidential, ceiling));
    }

    #[test]
    fn the_ceiling_is_one_level_above_the_grant() {
        // A confidential grant discloses public through confidential and
        // redacts restricted and above — exactly what the authorizer
        // covers.
        let ceiling =
            disclosure_ceiling(&[classification(DataClassification::Confidential)]).unwrap();
        assert_eq!(ceiling, DataClassification::Restricted);
        assert!(is_disclosable(DataClassification::Confidential, ceiling));
        assert!(is_disclosable(DataClassification::Public, ceiling));
        assert!(!is_disclosable(DataClassification::Restricted, ceiling));
        assert!(!is_disclosable(
            DataClassification::HighlyRestricted,
            ceiling
        ));
    }

    #[test]
    fn a_restricted_grant_discloses_up_to_restricted() {
        let ceiling =
            disclosure_ceiling(&[classification(DataClassification::Restricted)]).unwrap();
        assert_eq!(ceiling, DataClassification::HighlyRestricted);
        assert!(is_disclosable(DataClassification::Restricted, ceiling));
        assert!(!is_disclosable(
            DataClassification::HighlyRestricted,
            ceiling
        ));
    }

    #[test]
    fn all_or_highly_restricted_means_no_classification_ceiling() {
        assert_eq!(disclosure_ceiling(&[AccessScope::All]), None);
        assert_eq!(
            disclosure_ceiling(&[classification(DataClassification::HighlyRestricted)]),
            None
        );
        // `All` anywhere wins over narrower classification grants.
        assert_eq!(
            disclosure_ceiling(&[
                classification(DataClassification::Confidential),
                AccessScope::All
            ]),
            None
        );
    }

    #[test]
    fn multiple_grants_take_the_most_sensitive() {
        // A restricted grant alongside a confidential one raises the
        // ceiling to what the restricted grant covers.
        let ceiling = disclosure_ceiling(&[
            classification(DataClassification::Confidential),
            classification(DataClassification::Restricted),
        ])
        .unwrap();
        assert_eq!(ceiling, DataClassification::HighlyRestricted);
        assert!(is_disclosable(DataClassification::Restricted, ceiling));
    }

    #[test]
    fn the_derived_ceiling_agrees_with_classification_coverage() {
        // For every grant level, a field of any classification is
        // disclosed exactly when a grant at that level would cover it
        // (the authorizer's directional rule: granted >= requested).
        let all = [
            DataClassification::Public,
            DataClassification::Operational,
            DataClassification::Confidential,
            DataClassification::Restricted,
            DataClassification::HighlyRestricted,
        ];
        for granted in all {
            let ceiling = disclosure_ceiling(&[classification(granted)]);
            for field in all {
                let covered = granted >= field;
                let disclosed = match ceiling {
                    Some(ceiling) => is_disclosable(field, ceiling),
                    None => true,
                };
                assert_eq!(
                    disclosed, covered,
                    "grant {granted:?} must disclose {field:?} exactly when covered"
                );
            }
        }
    }
}
