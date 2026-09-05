//! The operator contract registry: admission control for ingestion.
//!
//! An audit deployment does not ingest *every* contract on a ledger —
//! it ingests the contracts it is responsible for (the enforcement
//! hooks and token contracts it audits). Which those are is an
//! *operator* decision and must be configuration, never a hard-coded
//! guess. The [`ContractRegistry`] is that configuration: per network,
//! it names the recognized contract addresses and an operator-chosen
//! label for each.
//!
//! The registry decides *admission only*. It never claims what an event
//! *means*: interpreting a recognized contract's topics is the verified
//! payload surface (`safeguard-hooks` schemas), which this crate does
//! not invent. Its practical outputs are admission checks and the
//! contract list an RPC feed filters by — events from unrecognized
//! contracts never enter the pipeline.

use std::collections::BTreeMap;

use safeguard_audit_core::{AuditError, AuditResult, ContractId, NetworkId};

/// A stable, operator-chosen label for a recognized contract (used in
/// logs and provenance, e.g. `safeguard-hooks-testnet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractLabel(String);

impl ContractLabel {
    /// Validates and wraps a label: 1-64 non-space printable ASCII chars.
    pub fn new(value: &str) -> AuditResult<Self> {
        let valid = (1..=64).contains(&value.len())
            && value
                .chars()
                .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"');
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(AuditError::invalid_identifier(
                "contract label",
                "must be 1-64 non-space printable ASCII chars",
            ))
        }
    }

    /// The label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContractLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-network admission list of recognized contracts.
#[derive(Debug, Clone, Default)]
pub struct ContractRegistry {
    by_network: BTreeMap<String, BTreeMap<ContractId, ContractLabel>>,
}

impl ContractRegistry {
    /// An empty registry (no contracts admitted on any network).
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits `contract` on `network` under `label`.
    ///
    /// Registering the same contract twice replaces its label; the
    /// admission set stays a set.
    pub fn register(
        &mut self,
        network: NetworkId,
        contract: ContractId,
        label: ContractLabel,
    ) -> &mut Self {
        self.by_network
            .entry(network.as_str().to_owned())
            .or_default()
            .insert(contract, label);
        self
    }

    /// Whether `contract` is admitted on `network`.
    pub fn recognized(&self, network: &NetworkId, contract: &str) -> bool {
        self.by_network
            .get(network.as_str())
            .is_some_and(|entries| entries.keys().any(|c| c.as_str() == contract))
    }

    /// The label for a recognized contract, when one is registered.
    pub fn label(&self, network: &NetworkId, contract: &str) -> Option<&ContractLabel> {
        self.by_network
            .get(network.as_str())
            .and_then(|entries| entries.iter().find(|(c, _)| c.as_str() == contract))
            .map(|(_, label)| label)
    }

    /// The contract addresses admitted on `network`, sorted — the list an
    /// RPC `getEvents` filter is built from.
    pub fn contract_ids(&self, network: &NetworkId) -> Vec<String> {
        self.by_network
            .get(network.as_str())
            .map(|entries| {
                entries
                    .keys()
                    .map(|c| c.as_str().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    /// How many contracts are admitted on `network`.
    pub fn admitted_on(&self, network: &NetworkId) -> usize {
        self.contract_ids(network).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(label: &str) -> NetworkId {
        NetworkId::new(label).unwrap()
    }

    fn contract(seed: char) -> ContractId {
        ContractId::new(&format!("C{}", seed.to_string().repeat(55))).unwrap()
    }

    #[test]
    fn registry_admits_and_labels_per_network() {
        let mut registry = ContractRegistry::new();
        registry.register(
            net("testnet"),
            contract('A'),
            ContractLabel::new("safeguard-hooks-testnet").unwrap(),
        );
        registry.register(
            net("testnet"),
            contract('B'),
            ContractLabel::new("compliance-token-testnet").unwrap(),
        );

        let testnet = net("testnet");
        assert!(registry.recognized(&testnet, contract('A').as_str()));
        assert!(registry.recognized(&testnet, contract('B').as_str()));
        assert_eq!(registry.admitted_on(&testnet), 2);
        assert_eq!(
            registry
                .label(&testnet, contract('B').as_str())
                .unwrap()
                .as_str(),
            "compliance-token-testnet"
        );
        // The same address on a different network is a different contract.
        let mainnet = net("mainnet");
        assert!(!registry.recognized(&mainnet, contract('A').as_str()));
        assert_eq!(registry.admitted_on(&mainnet), 0);
        // Unrecognized addresses and networks are never admitted.
        assert!(!registry.recognized(&testnet, contract('Z').as_str()));
    }

    #[test]
    fn contract_lists_are_sorted_and_ready_for_rpc_filters() {
        let mut registry = ContractRegistry::new();
        let testnet = net("testnet");
        registry.register(
            testnet.clone(),
            contract('B'),
            ContractLabel::new("b").unwrap(),
        );
        registry.register(
            testnet.clone(),
            contract('A'),
            ContractLabel::new("a").unwrap(),
        );
        let ids = registry.contract_ids(&testnet);
        assert_eq!(ids.len(), 2);
        assert!(
            ids[0] < ids[1],
            "filter list must be deterministically sorted"
        );
        assert_eq!(ids[0], contract('A').as_str());
    }

    #[test]
    fn labels_are_validated() {
        assert!(ContractLabel::new("safeguard-hooks-testnet").is_ok());
        assert!(ContractLabel::new("").is_err());
        assert!(ContractLabel::new("has space").is_err());
    }

    #[test]
    fn re_registering_the_same_contract_updates_the_label_only() {
        let mut registry = ContractRegistry::new();
        let testnet = net("testnet");
        registry.register(
            testnet.clone(),
            contract('A'),
            ContractLabel::new("first").unwrap(),
        );
        registry.register(
            testnet.clone(),
            contract('A'),
            ContractLabel::new("second").unwrap(),
        );
        assert_eq!(registry.admitted_on(&testnet), 1);
        assert_eq!(
            registry
                .label(&testnet, contract('A').as_str())
                .unwrap()
                .as_str(),
            "second"
        );
    }
}
