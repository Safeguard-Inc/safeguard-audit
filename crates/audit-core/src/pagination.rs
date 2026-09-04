//! Cursor-based pagination primitives.
//!
//! Every query interface that can return large result sets pages with
//! opaque cursors rather than offsets. Cursors are stable across inserts
//! (they point at a *position*, not a count), which matters for an
//! append-only audit history that grows while an operator pages through it.
//!
//! The concrete encoding of a cursor position is the store's business: the
//! store hands out an opaque [`Cursor`] string and later accepts it back.
//! This module only defines the wire shapes and their validation.

use serde::{Deserialize, Serialize};

use crate::errors::{AuditError, AuditResult};

/// The largest page a single request may return.
pub const MAX_PAGE_SIZE: usize = 1000;

/// An opaque, stable position in a result sequence.
///
/// Cursors use only URL-safe printable ASCII so they survive CLI arguments,
/// JSON, and query strings unchanged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Cursor(String);

impl Cursor {
    /// Validates and wraps a cursor value produced by a store.
    pub fn new(value: &str) -> AuditResult<Self> {
        let valid = (1..=128).contains(&value.len())
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '_' | '-' | '.' | '~' | ':' | '/' | '+' | '=' | '|')
            });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(AuditError::invalid_identifier(
                "cursor",
                "must be 1-128 URL-safe printable ASCII chars",
            ))
        }
    }

    /// The opaque cursor string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A page request: a bounded count plus an optional position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    limit: usize,
    cursor: Option<Cursor>,
}

impl PageRequest {
    /// A request for the first `limit` items (1..=[`MAX_PAGE_SIZE`]).
    pub fn new(limit: usize) -> AuditResult<Self> {
        Self::with_cursor(limit, None)
    }

    /// A request for `limit` items at or after `cursor`.
    pub fn with_cursor(limit: usize, cursor: Option<Cursor>) -> AuditResult<Self> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(AuditError::ValidationFailure(format!(
                "page limit {limit} is outside 1..={MAX_PAGE_SIZE}"
            )));
        }
        Ok(Self { limit, cursor })
    }

    /// The requested page size.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The position to resume from, if any.
    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

/// One page of results plus the position of the next page, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<Cursor>,
}

impl<T> Page<T> {
    /// An empty page with no continuation.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }

    /// Builds a page from its items and optional continuation cursor.
    pub fn new(items: Vec<T>, next_cursor: Option<Cursor>) -> Self {
        Self { items, next_cursor }
    }

    /// The items in this page.
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Consumes the page and returns its items.
    pub fn into_items(self) -> Vec<T> {
        self.items
    }

    /// The cursor to pass for the next page, or `None` at the end.
    pub fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }

    /// Whether more results exist after this page.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limits_are_bounded() {
        assert!(PageRequest::new(0).is_err());
        assert!(PageRequest::new(MAX_PAGE_SIZE + 1).is_err());
        assert!(PageRequest::new(1).is_ok());
        assert_eq!(PageRequest::new(50).unwrap().limit(), 50);
    }

    #[test]
    fn cursors_validate_character_set() {
        assert!(Cursor::new("abc_123-xyz.~+/=:").is_ok());
        assert!(Cursor::new("").is_err());
        assert!(Cursor::new("has space").is_err());
        assert!(Cursor::new(&"x".repeat(129)).is_err());
        assert!(Cursor::new(&"x".repeat(128)).is_ok());
    }

    #[test]
    fn pages_carry_their_continuation() {
        let cursor = Cursor::new("pos-7").unwrap();
        let page = Page::new(vec![1, 2, 3], Some(cursor.clone()));
        assert_eq!(page.items(), &[1, 2, 3]);
        assert_eq!(page.next_cursor(), Some(&cursor));
        assert!(page.has_more());

        let last = Page::<i32>::empty();
        assert!(last.next_cursor().is_none());
        assert!(!last.has_more());
        assert_eq!(last.into_items(), Vec::<i32>::new());
    }

    #[test]
    fn cursor_and_page_serde_are_transparent() {
        let cursor = Cursor::new("pos-7").unwrap();
        let json = serde_json::to_string(&cursor).unwrap();
        assert_eq!(json, "\"pos-7\"");
        assert_eq!(serde_json::from_str::<Cursor>(&json).unwrap(), cursor);

        let request = PageRequest::with_cursor(25, Some(cursor)).unwrap();
        let json = serde_json::to_string(&request).unwrap();
        let back: PageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, request);
    }
}
