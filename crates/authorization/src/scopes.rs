//! Scope containment.
//!
//! Scoped access is the guarantee that an auditor authorized for one scope
//! never automatically receives another. The single primitive here is
//! [`contains`]: does a *granted* scope cover a *requested* scope?
//!
//! The rules are deliberately conservative:
//!
//! * `All` covers everything (administrators only, by policy).
//! * A scope covers a request of the *same kind* and, where the kind has
//!   structure, only when the granted value is at least as broad:
//!   a `Token` scope does not cover a `Contract` request, and a
//!   `Classification(Confidential)` grant does not cover a
//!   `Classification(Restricted)` request.
//! * A granted `TimeRange` must fully contain the requested range.
//! * Unknown kinds never match each other — a scope of an unrecognized
//!   shape cannot accidentally authorize anything.

use safeguard_audit_core::{AccessScope, DataClassification, TimeRange};

/// Whether a granted scope covers the requested scope.
///
/// Returns `true` only when the grant is at least as broad as the request.
/// This is the *only* scope test the authorizer performs; there is no
/// fallback path and no "close enough" matching.
pub fn contains(granted: &AccessScope, requested: &AccessScope) -> bool {
    match granted {
        AccessScope::All => true,
        AccessScope::Network(n) => {
            matches!(requested, AccessScope::Network(r) if r == n)
        }
        AccessScope::Token(t) => {
            matches!(requested, AccessScope::Token(r) if r == t)
        }
        AccessScope::Contract(c) => {
            matches!(requested, AccessScope::Contract(r) if r == c)
        }
        AccessScope::AccountClass(c) => {
            matches!(requested, AccessScope::AccountClass(r) if r == c)
        }
        AccessScope::Investigation(c) => {
            matches!(requested, AccessScope::Investigation(r) if r == c)
        }
        AccessScope::TimeRange(grant) => {
            matches!(requested, AccessScope::TimeRange(req) if range_contains(grant, req))
        }
        AccessScope::EventKind(k) => {
            matches!(requested, AccessScope::EventKind(r) if r == k)
        }
        AccessScope::Classification(c) => {
            matches!(requested, AccessScope::Classification(r) if classification_covers(*c, *r))
        }
    }
}

/// Whether any scope in `granted` covers `requested`.
pub fn any_contains(granted: &[AccessScope], requested: &AccessScope) -> bool {
    granted.iter().any(|scope| contains(scope, requested))
}

/// Whether a granted classification covers a requested one: the grant must
/// be at least as sensitive as the request (a `HighlyRestricted` grant
/// covers `Restricted` requests, never the reverse).
fn classification_covers(granted: DataClassification, requested: DataClassification) -> bool {
    granted >= requested
}

/// Whether the granted range fully contains the requested range. Both
/// ranges are inclusive; an unbounded side on the grant covers any
/// request bound on that side.
fn range_contains(granted: &TimeRange, requested: &TimeRange) -> bool {
    let start_ok = match (granted.start(), requested.start()) {
        (Some(g), Some(r)) => g <= r,
        // A grant with no start covers any requested start.
        (None, _) => true,
        // A grant with a start does not cover an unbounded request start.
        (Some(_), None) => false,
    };
    let end_ok = match (granted.end(), requested.end()) {
        (Some(g), Some(r)) => g >= r,
        (None, _) => true,
        (Some(_), None) => false,
    };
    start_ok && end_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AccessScope, CaseId, ContractId, ContractReference, DataClassification, EventKind,
        NetworkId, TimeRange, Timestamp, TokenReference,
    };

    fn net() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn token(ref_: &str) -> TokenReference {
        TokenReference::for_contract(net(), ContractId::new(ref_).unwrap())
    }

    fn contract(ref_: &str) -> ContractReference {
        ContractReference::new(net(), ContractId::new(ref_).unwrap())
    }

    #[test]
    fn all_covers_everything() {
        assert!(contains(
            &AccessScope::All,
            &AccessScope::Network(NetworkId::new("testnet").unwrap())
        ));
        assert!(contains(
            &AccessScope::All,
            &AccessScope::Token(token("C1"))
        ));
        assert!(contains(
            &AccessScope::All,
            &AccessScope::Classification(DataClassification::HighlyRestricted)
        ));
    }

    #[test]
    fn same_kind_matching() {
        let net = NetworkId::new(NetworkId::TESTNET).unwrap();
        let other = NetworkId::new(NetworkId::MAINNET).unwrap();
        assert!(contains(
            &AccessScope::Network(net.clone()),
            &AccessScope::Network(net.clone())
        ));
        assert!(!contains(
            &AccessScope::Network(net),
            &AccessScope::Network(other)
        ));

        let t1 = token("C1");
        let t2 = token("C2");
        assert!(contains(
            &AccessScope::Token(t1.clone()),
            &AccessScope::Token(t1.clone())
        ));
        assert!(!contains(&AccessScope::Token(t1), &AccessScope::Token(t2)));

        let c1 = contract("C1");
        let c2 = contract("C2");
        assert!(contains(
            &AccessScope::Contract(c1.clone()),
            &AccessScope::Contract(c1.clone())
        ));
        assert!(!contains(
            &AccessScope::Contract(c1),
            &AccessScope::Contract(c2)
        ));

        let case = CaseId::derive(&["case-1"]);
        assert!(contains(
            &AccessScope::Investigation(case.clone()),
            &AccessScope::Investigation(case)
        ));

        assert!(contains(
            &AccessScope::EventKind(EventKind::AuditAccess),
            &AccessScope::EventKind(EventKind::AuditAccess)
        ));
        assert!(!contains(
            &AccessScope::EventKind(EventKind::AuditAccess),
            &AccessScope::EventKind(EventKind::AccountFrozen)
        ));
    }

    #[test]
    fn cross_kind_never_matches() {
        // A token scope does not cover a contract request, and vice versa.
        let token_scope = AccessScope::Token(token("C1"));
        let contract_scope = AccessScope::Contract(contract("C1"));
        assert!(!contains(&token_scope, &contract_scope));
        assert!(!contains(&contract_scope, &token_scope));
        // A network scope covers nothing but network requests.
        let net = AccessScope::Network(NetworkId::new(NetworkId::TESTNET).unwrap());
        assert!(!contains(&net, &token_scope));
    }

    #[test]
    fn classification_is_directional() {
        let confidential = AccessScope::Classification(DataClassification::Confidential);
        let restricted = AccessScope::Classification(DataClassification::Restricted);
        let highly = AccessScope::Classification(DataClassification::HighlyRestricted);
        // A more sensitive grant covers less sensitive requests.
        assert!(contains(&restricted, &confidential));
        assert!(contains(&highly, &restricted));
        assert!(contains(&highly, &confidential));
        // Never the reverse.
        assert!(!contains(&confidential, &restricted));
        assert!(!contains(&restricted, &highly));
    }

    #[test]
    fn time_ranges_require_full_containment() {
        let t0 = Timestamp::from_unix_seconds(100);
        let t1 = Timestamp::from_unix_seconds(200);
        let t2 = Timestamp::from_unix_seconds(300);

        let wide = AccessScope::TimeRange(TimeRange::new(Some(t0), Some(t2)).unwrap());
        let narrow = AccessScope::TimeRange(TimeRange::new(Some(t1), Some(t1)).unwrap());
        let wider = AccessScope::TimeRange(TimeRange::new(Some(t0), None).unwrap());
        let unbounded = AccessScope::TimeRange(TimeRange::all());

        assert!(contains(&wide, &narrow));
        assert!(contains(&unbounded, &wide));
        assert!(contains(&wider, &narrow));
        // The request extends past the grant's end.
        let late = AccessScope::TimeRange(TimeRange::new(Some(t1), Some(t2)).unwrap());
        assert!(!contains(&narrow, &late));
        // A bounded grant cannot cover an unbounded request.
        assert!(!contains(&wide, &unbounded));
        assert!(!contains(&wide, &wider));
    }

    #[test]
    fn any_scope_matches_is_a_disjunction() {
        let net = AccessScope::Network(NetworkId::new(NetworkId::TESTNET).unwrap());
        let grants = vec![
            AccessScope::Token(token("C1")),
            AccessScope::Classification(DataClassification::Restricted),
        ];
        assert!(any_contains(&grants, &AccessScope::Token(token("C1"))));
        assert!(any_contains(
            &grants,
            &AccessScope::Classification(DataClassification::Confidential)
        ));
        assert!(!any_contains(&grants, &net));
        // `All` anywhere covers everything.
        let grants_with_all = vec![AccessScope::All];
        assert!(any_contains(&grants_with_all, &net));
    }
}
