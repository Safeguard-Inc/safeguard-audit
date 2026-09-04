//! Source-position cursors.
//!
//! A source cursor is the stable position inside one [`EventSource`] that
//! the indexer has consumed up to — a ledger sequence, an RPC cursor, a
//! fixture ordinal. Cursors are opaque to everything except the source
//! that minted them and the checkpoint store that persists them; this
//! module only validates their shape so garbage cannot enter a checkpoint.
//!
//! Cursor strings are non-space printable ASCII, 1-512 chars, so they
//! survive CLI arguments, JSON, and query strings unchanged. This mirrors
//! the [`RawEventItem`] position contract exactly — a cursor is, after
//! all, the position of the last consumed item.
//!
//! [`EventSource`]: safeguard_audit_core::EventSource
//! [`RawEventItem`]: safeguard_audit_core::RawEventItem

use std::fmt;
use std::str::FromStr;

/// A validated, opaque source position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceCursor(String);

impl SourceCursor {
    /// Validates and wraps a source position string.
    pub fn new(value: &str) -> Result<Self, CursorError> {
        let valid = (1..=512).contains(&value.len())
            && value
                .chars()
                .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"');
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(CursorError(
                "cursor must be 1-512 non-space printable ASCII chars".to_owned(),
            ))
        }
    }

    /// The cursor string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SourceCursor {
    type Err = CursorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl serde::Serialize for SourceCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SourceCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// A cursor failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid source cursor: {0}")]
pub struct CursorError(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cursors_round_trip() {
        for value in ["ledger:423", "c-1234", "soroban-rpc:abc.def:42"] {
            let cursor = SourceCursor::new(value).unwrap();
            assert_eq!(cursor.as_str(), value);
            assert_eq!(SourceCursor::from_str(value).unwrap(), cursor);
        }
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        assert!(SourceCursor::new("").is_err());
        assert!(SourceCursor::new(&"x".repeat(513)).is_err());
        assert!(SourceCursor::new("has space").is_err());
        assert!(SourceCursor::new("has\"quote").is_err());
        assert!(SourceCursor::new("tab\there").is_err());
    }

    #[test]
    fn serde_round_trips_and_revalidates() {
        let cursor = SourceCursor::new("ledger:7").unwrap();
        let json = serde_json::to_string(&cursor).unwrap();
        assert_eq!(json, "\"ledger:7\"");
        assert_eq!(serde_json::from_str::<SourceCursor>(&json).unwrap(), cursor);
        assert!(serde_json::from_str::<SourceCursor>("\"bad cursor\"").is_err());
    }
}
