//! Data classification for every field that enters an audit record.
//!
//! The audit layer can see more than it is allowed to repeat. Every value
//! recorded, logged, exported, or reported is therefore tagged with a
//! classification so redaction, access control, and safe serialization have
//! one shared vocabulary. Classification is the *policy*; the privacy
//! enforcement crate applies it.
//!
//! The classifications, most public to most protected:
//!
//! * `public` — ledger metadata anyone can read on-chain (addresses, hashes,
//!   ledger sequences, event names).
//! * `operational` — internal but non-sensitive operation metadata (parser
//!   versions, hook identifiers, correlation labels).
//! * `confidential` — non-public details that are still not highly
//!   sensitive (e.g. which account class a policy matched).
//! * `restricted` — protected data requiring an explicit authorization
//!   scope (policy decision internals, investigation context).
//! * `highly-restricted` — private financial data: decrypted balances,
//!   transfer amounts, view-key material. When it exists at all it is
//!   transient and gated behind a dedicated decryption authorization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Classifies how sensitive a piece of audit data is.
///
/// Variants are ordered by increasing sensitivity, so ordering comparisons
/// (`>=`) answer "is this at least as sensitive as that?" directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataClassification {
    /// Readable by anyone with network access (public ledger metadata).
    Public,
    /// Internal, non-sensitive operational metadata.
    Operational,
    /// Non-public but non-critical details.
    Confidential,
    /// Protected data requiring explicit authorization.
    Restricted,
    /// Private financial data gated behind dedicated decryption authz.
    HighlyRestricted,
}

impl DataClassification {
    /// The classification label used in wire formats and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
            Self::HighlyRestricted => "highly-restricted",
        }
    }

    /// Whether `self` is at least as sensitive as `other`.
    pub fn is_at_least(&self, other: Self) -> bool {
        *self >= other
    }

    /// Whether this classification may be written to ordinary logs.
    pub fn is_loggable(&self) -> bool {
        matches!(self, Self::Public | Self::Operational | Self::Confidential)
    }
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A field-level classification table: field name -> classification.
///
/// Records and events carry a table like this as redaction metadata so an
/// exporter or reporter can prove *which* fields were treated as what, and
/// redaction output can be reproduced deterministically.
pub type FieldClassifications = BTreeMap<String, DataClassification>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_reflects_sensitivity() {
        assert!(DataClassification::Public < DataClassification::Operational);
        assert!(DataClassification::Confidential < DataClassification::Restricted);
        assert!(DataClassification::Restricted < DataClassification::HighlyRestricted);
        assert!(DataClassification::HighlyRestricted.is_at_least(DataClassification::Public));
        assert!(!DataClassification::Public.is_at_least(DataClassification::Restricted));
    }

    #[test]
    fn serde_uses_stable_kebab_labels() {
        assert_eq!(
            serde_json::to_string(&DataClassification::HighlyRestricted).unwrap(),
            "\"highly-restricted\""
        );
        let back: DataClassification = serde_json::from_str("\"public\"").unwrap();
        assert_eq!(back, DataClassification::Public);
    }

    #[test]
    fn loggability_boundary() {
        assert!(DataClassification::Confidential.is_loggable());
        assert!(!DataClassification::Restricted.is_loggable());
        assert!(!DataClassification::HighlyRestricted.is_loggable());
    }

    #[test]
    fn classification_tables_are_usable() {
        let mut table = FieldClassifications::new();
        table.insert("transaction_hash".into(), DataClassification::Public);
        table.insert(
            "decrypted_amount".into(),
            DataClassification::HighlyRestricted,
        );
        assert_eq!(table.len(), 2);
    }
}
