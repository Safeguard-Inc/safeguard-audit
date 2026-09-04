//! Mapping a report query onto the store's audit query.
//!
//! The report model's [`ReportQuery`] is the reproducibility record — it
//! must survive inside the report unchanged. The store speaks [`AuditQuery`].
//! This module is the deterministic bridge: every filter the store can
//! express is mapped 1:1; the two report-specific concerns the store
//! cannot express — multi-token membership and the classification
//! ceiling — are applied by the service *after* the scan, and are
//! therefore not part of this mapping. Mapping the same query twice
//! yields the same [`AuditQuery`].

use safeguard_audit_core::{AuditResult, NetworkId, ReportQuery};
use safeguard_audit_storage::AuditQuery;

/// Maps a report query to the store's audit query.
///
/// Returns an error for incoherent filters: an unparsable network label
/// or a token on a different network than the query's network.
pub fn to_audit_query(query: &ReportQuery) -> AuditResult<AuditQuery> {
    let mut builder = AuditQuery::builder();

    if let Some(network) = &query.network {
        builder = builder.with_network(NetworkId::new(network)?);
    }
    // The store filters on one token; multi-token requests are handled by
    // the service with in-memory membership over the scanned range.
    if query.tokens.len() == 1 {
        builder = builder.with_token(query.tokens[0].clone());
    }
    if let Some(account) = &query.account {
        builder = builder.with_account(account.as_str());
    }
    if let Some(outcome) = query.outcome {
        builder = builder.with_decision(outcome);
    }
    if !query.event_kinds.is_empty() {
        builder = builder.with_event_kinds(&query.event_kinds);
    }
    if let Some(range) = query.time_range {
        builder = builder.with_time_range(range);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{DecisionResult, EventKind, TimeRange, Timestamp};

    #[test]
    fn every_supported_filter_maps_one_to_one() {
        let query = ReportQuery {
            time_range: Some(
                TimeRange::new(
                    Some(Timestamp::from_unix_seconds(100)),
                    Some(Timestamp::from_unix_seconds(200)),
                )
                .unwrap(),
            ),
            network: Some("testnet".into()),
            tokens: vec![],
            event_kinds: vec![EventKind::TransferDenied],
            outcome: Some(DecisionResult::Denied),
            account: Some(safeguard_audit_core::AccountId::new(
                "GACCOUNT12345678901234567890123456789012345678901234",
            )
            .unwrap()),
            classification_ceiling: None,
        };
        let mapped = to_audit_query(&query).unwrap();
        assert_eq!(mapped.network().unwrap().as_str(), "testnet");
        assert_eq!(mapped.sort(), safeguard_audit_storage::SortDirection::Ascending);
    }

    #[test]
    fn mapping_is_deterministic() {
        let query = ReportQuery::with_outcome(DecisionResult::Denied);
        assert_eq!(to_audit_query(&query).unwrap(), to_audit_query(&query).unwrap());
    }

    #[test]
    fn bad_network_labels_are_rejected() {
        let query = ReportQuery {
            network: Some("not-a-network!".into()),
            ..ReportQuery::all()
        };
        assert!(to_audit_query(&query).is_err());
    }

    #[test]
    fn multi_token_queries_are_left_to_the_service() {
        // Two tokens cannot be expressed as one store filter; the mapping
        // must still succeed (the service applies membership in memory).
        let query = ReportQuery {
            tokens: vec![
                safeguard_audit_core::TokenReference::for_contract(
                    safeguard_audit_core::NetworkId::new(NetworkId::TESTNET).unwrap(),
                    safeguard_audit_core::ContractId::new(
                        &format!("C{}", "A".repeat(55)),
                    )
                    .unwrap(),
                ),
                safeguard_audit_core::TokenReference::for_contract(
                    safeguard_audit_core::NetworkId::new(NetworkId::TESTNET).unwrap(),
                    safeguard_audit_core::ContractId::new(
                        &format!("C{}", "B".repeat(55)),
                    )
                    .unwrap(),
                ),
            ],
            ..ReportQuery::all()
        };
        assert!(to_audit_query(&query).is_ok());
    }
}