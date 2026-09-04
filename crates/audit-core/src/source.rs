//! The ingestion boundary: anything that yields raw source events.
//!
//! The core domain never talks to a concrete provider — a Soroban ledger,
//! an RPC feed, the simulator, or a fixture file all arrive through the
//! same narrow door: an [`EventSource`] that yields
//! [`RawEventItem`]s, each with a stable position the indexer can
//! checkpoint against.
//!
//! A raw item is deliberately dumb: a scheme label naming how its JSON
//! payload should be parsed, the JSON payload itself, and a position that
//! is stable for the source (a ledger sequence, an RPC cursor, a fixture
//! ordinal). Nothing here parses, classifies, or judges payloads — that is
//! the normalizer's job. This crate only defines the door.

use std::error::Error;

use serde::{Deserialize, Serialize};

/// A raw, provider-shaped event before normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEventItem {
    /// Which parsing scheme the payload conforms to (e.g.
    /// `hooks-compliance`, `audit-envelope`, `transfer-outcome`). The
    /// normalizer owns the scheme registry.
    scheme: String,
    /// The raw payload as JSON text. Never parsed here.
    payload: String,
    /// A stable position for this item within the source, used for
    /// checkpointing. Positions are opaque to everything except the source
    /// that minted them.
    position: String,
}

impl RawEventItem {
    /// Builds a raw event item after validating the labels.
    pub fn new(
        scheme: impl Into<String>,
        payload: impl Into<String>,
        position: impl Into<String>,
    ) -> Result<Self, SourceError> {
        let scheme = scheme.into();
        let payload = payload.into();
        let position = position.into();
        validate_label("scheme", &scheme, 64)?;
        validate_label("position", &position, 512)?;
        if payload.len() > 4 * 1024 * 1024 {
            return Err(SourceError::InvalidItem(
                "payload exceeds the 4 MiB item limit".into(),
            ));
        }
        Ok(Self {
            scheme,
            payload,
            position,
        })
    }

    /// The parsing scheme label.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The raw JSON payload.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// The stable source position.
    pub fn position(&self) -> &str {
        &self.position
    }
}

fn validate_label(kind: &str, value: &str, max: usize) -> Result<(), SourceError> {
    let valid = (1..=max).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"');
    if valid {
        Ok(())
    } else {
        Err(SourceError::InvalidItem(format!(
            "{kind} label must be 1-{max} non-space printable ASCII chars"
        )))
    }
}

/// One page of raw items plus the position of the next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePage {
    items: Vec<RawEventItem>,
    /// Position to resume from for the next page, or `None` at the end.
    next: Option<String>,
}

impl SourcePage {
    /// Builds a page.
    pub fn new(items: Vec<RawEventItem>, next: Option<String>) -> Self {
        Self { items, next }
    }

    /// An empty final page.
    pub fn end() -> Self {
        Self::new(Vec::new(), None)
    }

    /// The items in this page.
    pub fn items(&self) -> &[RawEventItem] {
        &self.items
    }

    /// The resume position for the next page, when more exist.
    pub fn next_position(&self) -> Option<&str> {
        self.next.as_deref()
    }

    /// Whether the source has more items after this page.
    pub fn has_more(&self) -> bool {
        self.next.is_some()
    }
}

/// Errors raised by event sources.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The source could not produce a page (network, decode, backend).
    #[error("source fetch failed: {0}")]
    FetchFailed(String),

    /// A resume position was unknown or invalid to this source.
    #[error("invalid source position: {0}")]
    InvalidPosition(String),

    /// A page limit was outside the source's supported range.
    #[error("page limit {0} is outside the supported range")]
    LimitOutOfRange(usize),

    /// An item violated the source item contract.
    #[error("invalid source item: {0}")]
    InvalidItem(String),
}

impl SourceError {
    /// Maps onto the core error taxonomy for uniform pipeline handling.
    pub fn into_core(self) -> crate::AuditError {
        crate::AuditError::SourceFailure(self.to_string())
    }
}

/// A result alias for source operations.
pub type SourceResult<T> = Result<T, SourceError>;

/// A provider of raw source events.
///
/// Implementations are single-reader and forward-only: the indexer asks
/// for items after a position, the source answers with a bounded page and
/// the next resume position, and the caller persists that position in its
/// checkpoint. Sources must be able to resume from any position they ever
/// reported, because the indexer may stop and restart at any checkpoint.
pub trait EventSource {
    /// The source's own error type (usually [`SourceError`]).
    type Error: Error;

    /// A stable source name used in checkpoints and provenance, e.g.
    /// `soroban-testnet` or `simulator` or `fixture:approved-transfer`.
    fn source_name(&self) -> &str;

    /// Fetches up to `limit` items that come after `after` (the position of
    /// the last item already consumed, or `None` to start at the
    /// beginning).
    ///
    /// The returned page must never re-serve items at or before `after`,
    /// even across restarts: resuming from a checkpoint position must
    /// yield exactly the items the indexer has not consumed yet.
    fn fetch_after(&mut self, after: Option<&str>, limit: usize)
        -> Result<SourcePage, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test source replaying a fixed list of items.
    struct VecSource {
        items: Vec<RawEventItem>,
    }

    impl EventSource for VecSource {
        type Error = SourceError;
        fn source_name(&self) -> &str {
            "test-vec"
        }
        fn fetch_after(&mut self, after: Option<&str>, limit: usize) -> SourceResult<SourcePage> {
            if limit == 0 || limit > 1000 {
                return Err(SourceError::LimitOutOfRange(limit));
            }
            let start = match after {
                None => 0,
                Some(pos) => {
                    let idx = self
                        .items
                        .iter()
                        .position(|i| i.position() == pos)
                        .ok_or_else(|| SourceError::InvalidPosition(pos.to_owned()))?
                        + 1;
                    idx
                }
            };
            let end = (start + limit).min(self.items.len());
            let items = self.items[start..end].to_vec();
            let next = if end < self.items.len() {
                Some(self.items[end - 1].position().to_owned())
            } else {
                None
            };
            Ok(SourcePage::new(items, next))
        }
    }

    fn item(id: &str) -> RawEventItem {
        RawEventItem::new("hooks-compliance", "{}", id).unwrap()
    }

    #[test]
    fn raw_items_validate_their_labels() {
        assert!(RawEventItem::new("hooks-compliance", "{}", "ledger:42").is_ok());
        assert!(RawEventItem::new("", "{}", "p").is_err());
        assert!(RawEventItem::new("has space", "{}", "p").is_err());
    }

    #[test]
    fn sources_resume_from_positions() {
        let mut source = VecSource {
            items: vec![item("1"), item("2"), item("3")],
        };
        let page1 = source.fetch_after(None, 2).unwrap();
        assert_eq!(page1.items().len(), 2);
        assert!(page1.has_more());
        let page2 = source.fetch_after(page1.next_position(), 2).unwrap();
        assert_eq!(page2.items().len(), 1);
        assert!(!page2.has_more());
        // Resuming from the start again re-serves everything (indexer
        // checkpoints prevent that, not the source).
        let again = source.fetch_after(None, 10).unwrap();
        assert_eq!(again.items().len(), 3);
    }

    #[test]
    fn unknown_positions_error_cleanly() {
        let mut source = VecSource {
            items: vec![item("1")],
        };
        assert!(matches!(
            source.fetch_after(Some("nope"), 5),
            Err(SourceError::InvalidPosition(_))
        ));
    }
}
