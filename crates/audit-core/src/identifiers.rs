//! Identifiers and reference values used throughout the audit model.
//!
//! Two families live here:
//!
//! * **Derived identifiers** (`RecordId`, `EventId`, `CaseId`, ...) — stable,
//!   deterministic ids produced by hashing canonical input. Two systems that
//!   derive an id from the same inputs must agree on the id, which is what
//!   makes duplicate ingestion detectable and replay deterministic.
//! * **Reference values** (`AccountId`, `ContractId`, `TransactionHash`,
//!   `ReasonCode`, `NetworkId`) — opaque external identifiers carried as
//!   public transaction metadata. Format validation for a *specific*
//!   protocol (e.g. Soroban strkeys) belongs to the adapters; here we only
//!   enforce conservative structural limits so garbage cannot enter a
//!   record.
//!
//! ## Privacy rule
//!
//! Identifiers are addresses, hashes, and codes — public metadata. Nothing
//! here may hold balances, ciphertexts, or any protected value.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{AuditError, AuditResult};

/// Hex-encodes the SHA-256 digest of `input`.
///
/// Used for *structural* identity (derived ids, fingerprints) across the
/// crate. Evidence-level integrity hashing lives in the integrity module,
/// which composes canonical serialization with this primitive.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex_lower(&hasher.finalize())
}

/// Encodes bytes as lowercase hex without pulling in a hex dependency.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A deterministic identifier: `{prefix}_{32 hex chars}`.
///
/// The 32 hex characters are the first 16 bytes of the SHA-256 digest of
/// canonical input, giving a 128-bit identity that is stable across
/// processes and machines but effectively collision-free for audit-scale
/// histories. The prefix scopes the domain (`rec_`, `evt_`, `case_`, ...)
/// so ids from different domains can never collide even when hashes do not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableId {
    prefix: &'static str,
    value: String,
}

impl StableId {
    /// Number of hex characters in a derived id body.
    pub const BODY_HEX_LEN: usize = 32;

    /// Derives an id from a list of textual parts.
    ///
    /// The parts are canonicalized as a JSON array of strings before
    /// hashing, so the result is order-sensitive (reordering inputs changes
    /// the id) but unambiguous (concatenation tricks cannot collide).
    pub fn derive(prefix: &'static str, parts: &[&str]) -> Self {
        let canonical =
            serde_json::to_vec(parts).expect("serializing a slice of strings cannot fail");
        Self::derive_bytes(prefix, &canonical)
    }

    /// Derives an id from raw canonical bytes (e.g. a canonical record).
    pub fn derive_bytes(prefix: &'static str, bytes: &[u8]) -> Self {
        let digest = sha256_hex(bytes);
        let value = format!("{prefix}_{}", &digest[..Self::BODY_HEX_LEN]);
        Self { prefix, value }
    }

    /// Validates `prefix` and the external `value` it precedes.
    fn checked(prefix: &'static str, value: &str) -> AuditResult<Self> {
        validate_prefix(prefix)?;
        if value.len() < prefix.len() + 1 + 1
            || !value.starts_with(&format!("{prefix}_"))
            || !value[prefix.len() + 1..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(AuditError::invalid_identifier(
                "stable id",
                format!("`{value}` is not a valid `{prefix}_<hex>` id"),
            ));
        }
        Ok(Self {
            prefix,
            value: value.to_owned(),
        })
    }

    /// The fully qualified id, e.g. `rec_ab12...`.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

fn validate_prefix(prefix: &str) -> AuditResult<()> {
    let valid = (1..=8).contains(&prefix.len())
        && prefix
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
        && prefix.chars().all(|c| c.is_ascii_lowercase() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(AuditError::invalid_identifier(
            "stable id prefix",
            format!("`{prefix}` must be 1-8 lowercase chars or underscores"),
        ))
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

/// Generates a typed, serde-compatible, deterministic id newtype.
///
/// Serialization is transparent (the id is a plain JSON string) and
/// deserialization re-validates the string against the type's own prefix,
/// so a malformed or cross-domain id cannot be deserialized into the wrong
/// type.
macro_rules! id_type {
    ($(#[$meta:meta])* $vis:vis struct $name:ident; prefix: $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis struct $name(StableId);

        impl $name {
            /// The id prefix, e.g. `"rec"`.
            $vis const PREFIX: &'static str = $prefix;

            /// Deterministically derives an id from canonical textual parts.
            $vis fn derive(parts: &[&str]) -> Self {
                Self(StableId::derive($prefix, parts))
            }

            /// Deterministically derives an id from canonical bytes.
            $vis fn derive_bytes(bytes: &[u8]) -> Self {
                Self(StableId::derive_bytes($prefix, bytes))
            }

            /// Validates and wraps an externally supplied id string.
            $vis fn from_checked(value: &str) -> AuditResult<Self> {
                Ok(Self(StableId::checked($prefix, value)?))
            }

            /// The fully qualified id string.
            $vis fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl FromStr for $name {
            type Err = AuditError;
            fn from_str(s: &str) -> AuditResult<Self> {
                Self::from_checked(s)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0.value
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                self.0.as_str()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                Self::from_checked(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_type! {
    /// Identifies a single persisted audit record. Derived from the canonical
    /// serialization of the normalized event it records, so re-recording the
    /// same event derives the same id (the deduplication key).
    pub struct RecordId;
    prefix: "rec"
}

id_type! {
    /// Identifies a normalized event. Derived from stable *source* identity
    /// parts (network, contract, transaction, operation, event index, kind),
    /// never from arrival time.
    pub struct EventId;
    prefix: "evt"
}

id_type! {
    /// Identifies an investigation case.
    pub struct CaseId;
    prefix: "case"
}

id_type! {
    /// Identifies an evidence artifact or manifest.
    pub struct EvidenceId;
    prefix: "evid"
}

id_type! {
    /// Identifies a generated report.
    pub struct ReportId;
    prefix: "rep"
}

id_type! {
    /// Identifies a decryption or access request for audit logging.
    pub struct RequestId;
    prefix: "req"
}

id_type! {
    /// Identifies an auditor identity.
    pub struct AuditorId;
    prefix: "aud"
}

id_type! {
    /// Identifies an audit-access log entry.
    pub struct AccessEntryId;
    prefix: "acc"
}

id_type! {
    /// Identifies a finding attached to an investigation.
    pub struct FindingId;
    prefix: "find"
}

id_type! {
    /// Identifies a note attached to an investigation.
    pub struct NoteId;
    prefix: "note"
}

id_type! {
    /// Identifies an integrity or evidence manifest.
    pub struct ManifestId;
    prefix: "mfst"
}

/// A Stellar/Soroban network label.
///
/// Values are lowercase `[a-z0-9-]` strings; the well-known networks are
/// provided as associated constants. Unknown lowercase labels are accepted
/// so private/emulated networks can be named without schema changes, but
/// validation keeps the field from carrying free-form text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NetworkId(String);

impl NetworkId {
    /// The public Stellar network.
    pub const MAINNET: &'static str = "mainnet";
    /// The Stellar test network.
    pub const TESTNET: &'static str = "testnet";
    /// The Stellar future network.
    pub const FUTURENET: &'static str = "futurenet";
    /// A standalone/local containerized network.
    pub const STANDALONE: &'static str = "standalone";
    /// A local emulated or development network.
    pub const LOCAL: &'static str = "local";
    /// A simulated/offline network (no ledger).
    pub const SIMULATED: &'static str = "simulated";

    /// Validates and wraps a network label.
    pub fn new(label: &str) -> AuditResult<Self> {
        let valid = (1..=32).contains(&label.len())
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if valid {
            Ok(Self(label.to_owned()))
        } else {
            Err(AuditError::invalid_identifier(
                "network id",
                "must be 1-32 chars of [a-z0-9-]",
            ))
        }
    }

    /// The label, e.g. `"testnet"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the main public network.
    pub fn is_mainnet(&self) -> bool {
        self.0 == Self::MAINNET
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NetworkId {
    type Err = AuditError;
    fn from_str(s: &str) -> AuditResult<Self> {
        Self::new(s)
    }
}

/// Conservative structural limit shared by reference-value newtypes.
const REF_MAX_LEN: usize = 128;

/// A Stellar account address (public metadata).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccountId(String);

impl AccountId {
    /// Validates and wraps an account address. Protocol-level strkey
    /// validation is left to adapters; here we enforce printable ASCII and a
    /// length bound that covers every real Stellar address.
    pub fn new(value: &str) -> AuditResult<Self> {
        validate_ref("account id", value)?;
        Ok(Self(value.to_owned()))
    }

    /// The address string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AccountId {
    type Err = AuditError;
    fn from_str(s: &str) -> AuditResult<Self> {
        Self::new(s)
    }
}

/// A Soroban contract address (public metadata).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContractId(String);

impl ContractId {
    /// Validates and wraps a contract address.
    pub fn new(value: &str) -> AuditResult<Self> {
        validate_ref("contract id", value)?;
        Ok(Self(value.to_owned()))
    }

    /// The address string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ContractId {
    type Err = AuditError;
    fn from_str(s: &str) -> AuditResult<Self> {
        Self::new(s)
    }
}

/// A transaction hash or reference (public metadata).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransactionHash(String);

impl TransactionHash {
    /// Validates and wraps a transaction hash. Hex or strkey encodings are
    /// accepted structurally; format enforcement belongs to adapters.
    pub fn new(value: &str) -> AuditResult<Self> {
        validate_ref("transaction hash", value)?;
        Ok(Self(value.to_owned()))
    }

    /// The hash string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransactionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TransactionHash {
    type Err = AuditError;
    fn from_str(s: &str) -> AuditResult<Self> {
        Self::new(s)
    }
}

/// A machine-readable reason/decision code (public metadata).
///
/// Examples: `POLICY_DENIED`, `FROZEN_ACCOUNT`, `UNAUTHORIZED_OPERATION`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReasonCode(String);

impl ReasonCode {
    /// Validates and wraps a reason code. Codes are uppercase ASCII
    /// `[A-Z0-9._-]`, 1-64 chars, so they can appear in CLI output, logs,
    /// and machine-readable errors without escaping concerns.
    pub fn new(value: &str) -> AuditResult<Self> {
        let valid = (1..=64).contains(&value.len())
            && value.chars().all(|c| {
                c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(AuditError::invalid_identifier(
                "reason code",
                "must be 1-64 chars of [A-Z0-9._-]",
            ))
        }
    }

    /// The code string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ReasonCode {
    type Err = AuditError;
    fn from_str(s: &str) -> AuditResult<Self> {
        Self::new(s)
    }
}

fn validate_ref(kind: &'static str, value: &str) -> AuditResult<()> {
    let valid = !value.is_empty()
        && value.len() <= REF_MAX_LEN
        && value.chars().all(|c| c.is_ascii_graphic());
    if valid {
        Ok(())
    } else {
        Err(AuditError::invalid_identifier(
            kind,
            format!("must be 1-{REF_MAX_LEN} printable ASCII chars"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_ids_are_deterministic_and_order_sensitive() {
        let a = EventId::derive(&["mainnet", "tx-abc", "0"]);
        let b = EventId::derive(&["mainnet", "tx-abc", "0"]);
        let c = EventId::derive(&["mainnet", "tx-abc", "1"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.as_str().starts_with("evt_"));
        assert_eq!(a.as_str().len(), "evt_".len() + StableId::BODY_HEX_LEN);
        assert!(a.as_str()[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derived_ids_from_bytes_are_stable() {
        let a = RecordId::derive_bytes(b"canonical-record");
        let b = RecordId::derive_bytes(b"canonical-record");
        assert_eq!(a, b);
        assert_ne!(a, RecordId::derive_bytes(b"other"));
    }

    #[test]
    fn reordering_parts_changes_the_id() {
        let a = EventId::derive(&["network", "contract", "tx"]);
        let b = EventId::derive(&["tx", "contract", "network"]);
        assert_ne!(a, b);
    }

    #[test]
    fn checked_ids_accept_wellformed_values_and_reject_garbage() {
        let known = format!("rec_{}", "ab".repeat(16));
        assert_eq!(
            RecordId::from_checked(&known).unwrap().as_str(),
            known.as_str()
        );
        assert!(RecordId::from_checked("rec_zz").is_err());
        assert!(RecordId::from_checked("wrong_ab12").is_err());
        assert!(RecordId::from_checked("").is_err());
    }

    #[test]
    fn prefixes_cannot_collide_across_domains() {
        let record = RecordId::derive_bytes(b"same");
        let event = EventId::derive_bytes(b"same");
        assert_ne!(record.as_str(), event.as_str());
    }

    #[test]
    fn network_ids_validate() {
        assert_eq!(NetworkId::new("mainnet").unwrap().as_str(), "mainnet");
        assert!(NetworkId::new("Mainnet").is_err());
        assert!(NetworkId::new("has space").is_err());
        assert!(NetworkId::new("private-net-2").is_ok());
        assert!(!NetworkId::new("simulated").unwrap().is_mainnet());
        assert!(NetworkId::new("mainnet").unwrap().is_mainnet());
    }

    #[test]
    fn reference_values_accept_real_shapes() {
        // Stellar G-address and C-contract length shapes.
        let g = format!("G{}", "A".repeat(55));
        assert_eq!(AccountId::new(&g).unwrap().as_str(), g.as_str());
        let c = format!("C{}", "A".repeat(55));
        assert_eq!(ContractId::new(&c).unwrap().as_str(), c.as_str());
        assert!(AccountId::new("not an address").is_err());
        assert!(TransactionHash::new(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn reason_codes_are_upper_snake() {
        assert_eq!(
            ReasonCode::new("POLICY_DENIED").unwrap().as_str(),
            "POLICY_DENIED"
        );
        assert_eq!(
            ReasonCode::new("FROZEN_ACCOUNT.1").unwrap().as_str(),
            "FROZEN_ACCOUNT.1"
        );
        assert!(ReasonCode::new("policy denied").is_err());
        assert!(ReasonCode::new("").is_err());
    }

    #[test]
    fn ids_round_trip_serde_as_plain_strings() {
        let id = EventId::derive(&["testnet", "c", "tx", "1"]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        let back: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
