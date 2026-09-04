//! The ingestion scheme registry.
//!
//! A raw item names the *scheme* its payload conforms to, and the
//! normalizer routes on that label. This module is the single registry of
//! known schemes, their wire labels, and whether this build implements
//! them — so an unknown label and a known-but-unimplemented label fail
//! differently, and a source can never smuggle payloads past the registry
//! by inventing labels.
//!
//! ## Why only two schemes today
//!
//! The registry enumerates payload classes the system can actually
//! attribute, not every feed the system might one day attach:
//!
//! * `hooks-state-event` — the raw on-chain state events `safeguard-hooks`
//!   emits (`account_frozen`, `account_unfrozen`, `token_bound`,
//!   `token_unbound`, `compliance_config_changed`). Observed events; the
//!   parser reconstructs their on-chain placement from the payload.
//! * `audit-envelope` — an already-normalized [`AuditEvent`] envelope.
//!   Re-ingesting envelopes (backfill, cross-store transfer, replay
//!   reconstruction) must round-trip the same canonical form, so this
//!   scheme is the envelope's own JSON, validated on the way in.
//!
//! Transfer *outcomes* are deliberately not a raw scheme: a denied
//! transfer is never emitted on-chain, so it cannot arrive as a source
//! event. The audit layer derives it from authoritative transaction
//! metadata in a later stage rather than pretending a source produced it.
//!
//! [`AuditEvent`]: safeguard_audit_core::AuditEvent

use std::str::FromStr;

/// A known ingestion scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Raw on-chain state events from `safeguard-hooks`.
    HooksStateEvent,
    /// Already-normalized audit envelopes (re-ingest).
    AuditEnvelope,
}

impl Scheme {
    /// The stable wire label for this scheme.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::HooksStateEvent => "hooks-state-event",
            Self::AuditEnvelope => "audit-envelope",
        }
    }

    /// The payload version this build parses for the scheme.
    pub fn supported_version(&self) -> u32 {
        match self {
            Self::HooksStateEvent => 1,
            Self::AuditEnvelope => 1,
        }
    }

    /// Whether payloads of this scheme declare a version field.
    pub fn declares_version(&self) -> bool {
        match self {
            Self::HooksStateEvent => false,
            Self::AuditEnvelope => true,
        }
    }

    /// All known schemes, for registry tests.
    pub const ALL: &'static [Scheme] = &[Self::HooksStateEvent, Self::AuditEnvelope];
}

impl FromStr for Scheme {
    type Err = ();

    fn from_str(label: &str) -> Result<Self, Self::Err> {
        match label {
            "hooks-state-event" => Ok(Self::HooksStateEvent),
            "audit-envelope" => Ok(Self::AuditEnvelope),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable_and_round_trip() {
        for scheme in Scheme::ALL {
            assert_eq!(Scheme::from_str(scheme.as_label()), Ok(*scheme));
            assert!(!scheme.as_label().contains(' '));
        }
    }

    #[test]
    fn unknown_labels_do_not_parse() {
        assert!(Scheme::from_str("rpc-events").is_err());
        assert!(Scheme::from_str("").is_err());
        assert!(Scheme::from_str("hooks-compliance").is_err());
    }

    #[test]
    fn versions_are_explicit() {
        assert_eq!(Scheme::HooksStateEvent.supported_version(), 1);
        assert_eq!(Scheme::AuditEnvelope.supported_version(), 1);
        // Raw hooks events carry no version field; the parser version is
        // pinned by the normalizer configuration instead.
        assert!(!Scheme::HooksStateEvent.declares_version());
        assert!(Scheme::AuditEnvelope.declares_version());
    }
}
