//! The audit query model.
//!
//! Queries are pure predicates over records plus a filter description that
//! stores can translate into backend queries. Every store must answer the
//! same questions: by token, account, transaction, policy, decision,
//! event kind, time range, and network — always bounded by pagination at
//! the interface, never returning unbounded collections.

use safeguard_audit_core::{
    AuditError, AuditRecord, DecisionResult, EventKind, NetworkId, TimeRange, TokenReference,
};

/// Direction of the deterministic history order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    /// Oldest first (the natural audit order).
    #[default]
    Ascending,
    /// Newest first.
    Descending,
}

/// A query over audit records.
///
/// All filters are optional and AND together; empty filters match
/// everything. Construction goes through [`AuditQueryBuilder`], which
/// rejects contradictory combinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    network: Option<NetworkId>,
    token: Option<TokenReference>,
    account: Option<String>,
    transaction: Option<String>,
    policy: Option<String>,
    decision: Option<DecisionResult>,
    event_kinds: Vec<EventKind>,
    time_range: Option<TimeRange>,
    sort: SortDirection,
}

impl AuditQuery {
    /// Builds a new query with no filters.
    pub fn builder() -> AuditQueryBuilder {
        AuditQueryBuilder::default()
    }

    /// Whether the record matches every filter in this query.
    pub fn matches(&self, record: &AuditRecord) -> bool {
        let event = &record.event;
        if let Some(network) = &self.network {
            if &event.network != network {
                return false;
            }
        }
        if let Some(token) = &self.token {
            if event.token.as_ref() != Some(token) {
                return false;
            }
        }
        if let Some(account) = &self.account {
            let involved = [
                event.actor.as_ref().map(|a| a.account().as_str()),
                event.subject.as_ref().map(|a| a.account().as_str()),
            ];
            if !involved.iter().flatten().any(|a| *a == account) {
                return false;
            }
        }
        if let Some(tx_hash) = &self.transaction {
            if !event
                .transaction
                .as_ref()
                .is_some_and(|t| t.hash().as_str() == tx_hash)
            {
                return false;
            }
        }
        if let Some(policy) = &self.policy {
            let matches_policy = event
                .decision
                .as_ref()
                .is_some_and(|d| d.policy().policy().as_str() == policy);
            if !matches_policy {
                return false;
            }
        }
        if let Some(decision) = &self.decision {
            let matches_decision = event.outcome == Some(*decision)
                || event
                    .decision
                    .as_ref()
                    .is_some_and(|d| d.result() == *decision);
            if !matches_decision {
                return false;
            }
        }
        if !self.event_kinds.is_empty() && !self.event_kinds.contains(&event.kind) {
            return false;
        }
        if let Some(range) = &self.time_range {
            let at = event.observed_at.unwrap_or(record.recorded_at);
            if !range.contains(at) {
                return false;
            }
        }
        true
    }

    /// The network filter, if any.
    pub fn network(&self) -> Option<&NetworkId> {
        self.network.as_ref()
    }

    /// The sort direction.
    pub fn sort(&self) -> SortDirection {
        self.sort
    }
}

/// Builder for [`AuditQuery`]; rejects contradictory filters.
#[derive(Debug, Clone, Default)]
pub struct AuditQueryBuilder {
    network: Option<NetworkId>,
    token: Option<TokenReference>,
    account: Option<String>,
    transaction: Option<String>,
    policy: Option<String>,
    decision: Option<DecisionResult>,
    event_kinds: Vec<EventKind>,
    time_range: Option<TimeRange>,
    sort: SortDirection,
}

impl AuditQueryBuilder {
    /// Filters to one network.
    pub fn with_network(mut self, network: NetworkId) -> Self {
        self.network = Some(network);
        self
    }

    /// Filters to one token.
    pub fn with_token(mut self, token: TokenReference) -> Self {
        self.token = Some(token);
        self
    }

    /// Filters to records involving an account (actor or subject).
    pub fn with_account(mut self, account: &str) -> Self {
        self.account = Some(account.to_owned());
        self
    }

    /// Filters to one transaction hash.
    pub fn with_transaction(mut self, hash: &str) -> Self {
        self.transaction = Some(hash.to_owned());
        self
    }

    /// Filters to decisions produced by one policy contract.
    pub fn with_policy(mut self, policy: &str) -> Self {
        self.policy = Some(policy.to_owned());
        self
    }

    /// Filters to one recorded outcome/decision.
    pub fn with_decision(mut self, decision: DecisionResult) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Filters to one or more event kinds.
    pub fn with_event_kinds(mut self, kinds: &[EventKind]) -> Self {
        self.event_kinds = kinds.to_vec();
        self
    }

    /// Filters to a time range (by observed time, falling back to record
    /// time for records without one).
    pub fn with_time_range(mut self, range: TimeRange) -> Self {
        self.time_range = Some(range);
        self
    }

    /// Sets the result order (ascending by default).
    pub fn sorted(mut self, direction: SortDirection) -> Self {
        self.sort = direction;
        self
    }

    /// Validates and builds the query.
    pub fn build(self) -> Result<AuditQuery, AuditError> {
        if let (Some(network), Some(token)) = (&self.network, &self.token) {
            if token.network() != network {
                return Err(AuditError::InvalidQuery(format!(
                    "token filter is on network `{}` but the query is on `{}`",
                    token.network(),
                    network
                )));
            }
        }
        Ok(AuditQuery {
            network: self.network,
            token: self.token,
            account: self.account,
            transaction: self.transaction,
            policy: self.policy,
            decision: self.decision,
            event_kinds: self.event_kinds,
            time_range: self.time_range,
            sort: self.sort,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AccountId, AccountReference, AuditEvent, ContractId, EventKind, EventProvenance,
        FixedClock, NetworkId, OriginKind, Timestamp, VersionLabel,
    };

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn record(kind: EventKind, token: &str, account: &str, ts: i64) -> AuditRecord {
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "test", VersionLabel::new("1").unwrap())
                .unwrap();
        let mut event = AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[kind.as_str(), token, account]),
            kind,
            network(),
            provenance,
        );
        event.token = Some(TokenReference::for_contract(
            network(),
            ContractId::new(token).unwrap(),
        ));
        event.actor = Some(AccountReference::new(
            network(),
            AccountId::new(account).unwrap(),
        ));
        event.observed_at = Some(Timestamp::from_unix_seconds(ts));
        event.outcome = match kind {
            EventKind::TransferDenied => Some(DecisionResult::Denied),
            EventKind::TransferFlagged => Some(DecisionResult::Flagged),
            EventKind::TransferAuthorized => Some(DecisionResult::Allowed),
            _ => None,
        };
        let clock = FixedClock::at(Timestamp::from_unix_seconds(ts));
        AuditRecord::from_event(event, &clock).unwrap()
    }

    #[test]
    fn queries_filter_and_combine() {
        let denied_a = record(EventKind::TransferDenied, "Ctoken1", "Gacct1", 100);
        let denied_b = record(EventKind::TransferDenied, "Ctoken2", "Gacct2", 200);
        let frozen_a = record(EventKind::AccountFrozen, "Ctoken1", "Gacct1", 150);

        let q = AuditQuery::builder()
            .with_decision(DecisionResult::Denied)
            .build()
            .unwrap();
        assert!(q.matches(&denied_a));
        assert!(!q.matches(&frozen_a));

        let q = AuditQuery::builder()
            .with_decision(DecisionResult::Denied)
            .with_account("Gacct1")
            .build()
            .unwrap();
        assert!(q.matches(&denied_a));
        assert!(!q.matches(&denied_b));

        let q = AuditQuery::builder()
            .with_event_kinds(&[EventKind::AccountFrozen])
            .build()
            .unwrap();
        assert!(q.matches(&frozen_a));
        assert!(!q.matches(&denied_a));
    }

    #[test]
    fn cross_network_filters_are_rejected() {
        let other = NetworkId::new(NetworkId::MAINNET).unwrap();
        let token = TokenReference::for_contract(network(), ContractId::new("Cx").unwrap());
        let err = AuditQuery::builder()
            .with_network(other)
            .with_token(token)
            .build();
        assert!(err.is_err());
    }
}
