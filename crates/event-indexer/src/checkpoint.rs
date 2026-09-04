//! Checkpoints: where the indexer left off, durably.
//!
//! A checkpoint answers one question: "which source position has this
//! indexer already consumed up to?" The indexer loads it before fetching,
//! and saves it *after* a page's records are durably in the store — never
//! before, so a crash between write and checkpoint simply re-serves the
//! page, which deduplication absorbs.
//!
//! A checkpoint is scoped to a source name, so a stale checkpoint from a
//! different source can never be resumed against the wrong feed, and a
//! fresh indexer starts with no position (from the beginning of the
//! source).
//!
//! ## Contract
//!
//! [`CheckpointStore::save`] must be atomic and durable: after it
//! returns, a crash must not resurrect the previous position (or the
//! indexer could re-process a window and hit `FailOnDuplicate`). The
//! in-memory implementation here is for tests and single-process runs; a
//! production store (file, KV, SQL) must honor the same contract.

use std::collections::HashMap;

use crate::cursor::SourceCursor;
use crate::errors::{IndexerError, IndexerResult};

/// A validated source-name label (mirrors the provenance source rule).
fn validate_source_name(name: &str) -> IndexerResult<()> {
    let valid = (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"');
    if valid {
        Ok(())
    } else {
        Err(IndexerError::Checkpoint(
            "source name must be 1-64 non-space printable ASCII chars".to_owned(),
        ))
    }
}

/// The persisted state of one source's ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    source_name: String,
    /// The last consumed position; `None` means nothing consumed yet.
    position: Option<SourceCursor>,
}

impl Checkpoint {
    /// A fresh checkpoint for `source_name` (nothing consumed yet).
    pub fn fresh(source_name: &str) -> IndexerResult<Self> {
        validate_source_name(source_name)?;
        Ok(Self {
            source_name: source_name.to_owned(),
            position: None,
        })
    }

    /// A checkpoint at `position` for `source_name`.
    pub fn at(source_name: &str, position: SourceCursor) -> IndexerResult<Self> {
        validate_source_name(source_name)?;
        Ok(Self {
            source_name: source_name.to_owned(),
            position: Some(position),
        })
    }

    /// The source this checkpoint belongs to.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    /// The last consumed position, when any.
    pub fn position(&self) -> Option<&SourceCursor> {
        self.position.as_ref()
    }

    /// Whether the checkpoint has consumed anything yet.
    pub fn is_fresh(&self) -> bool {
        self.position.is_none()
    }
}

/// The durable checkpoint store contract.
///
/// Implementations are cheap and synchronous; the indexer calls `load`
/// once per run and `save` once per committed page.
pub trait CheckpointStore {
    /// Loads the checkpoint position for `source_name`, if one exists.
    fn load(&self, source_name: &str) -> IndexerResult<Option<SourceCursor>>;

    /// Atomically and durably saves `checkpoint`.
    fn save(&mut self, checkpoint: &Checkpoint) -> IndexerResult<()>;
}

/// An in-memory checkpoint store.
///
/// Loses everything on process exit — safe for tests and single-run
/// fixtures, never a substitute for durable checkpointing in production.
#[derive(Debug, Default)]
pub struct InMemoryCheckpointStore {
    positions: HashMap<String, SourceCursor>,
}

impl InMemoryCheckpointStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CheckpointStore for InMemoryCheckpointStore {
    fn load(&self, source_name: &str) -> IndexerResult<Option<SourceCursor>> {
        Ok(self.positions.get(source_name).cloned())
    }

    fn save(&mut self, checkpoint: &Checkpoint) -> IndexerResult<()> {
        match checkpoint.position() {
            Some(position) => {
                self.positions
                    .insert(checkpoint.source_name().to_owned(), position.clone());
                Ok(())
            }
            None => Ok(()), // a fresh checkpoint is trivially persisted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoints_validate_their_labels() {
        assert!(Checkpoint::fresh("soroban-testnet").is_ok());
        assert!(Checkpoint::fresh("").is_err());
        assert!(Checkpoint::fresh("has space").is_err());
        let cursor = SourceCursor::new("ledger:10").unwrap();
        assert!(Checkpoint::at("fixture:approved", cursor).is_ok());
    }

    #[test]
    fn fresh_checkpoints_have_no_position() {
        let cp = Checkpoint::fresh("simulator").unwrap();
        assert!(cp.is_fresh());
        assert!(cp.position().is_none());
    }

    #[test]
    fn in_memory_store_round_trips_per_source() {
        let mut store = InMemoryCheckpointStore::new();
        assert!(store.load("src-a").unwrap().is_none());
        store
            .save(&Checkpoint::at("src-a", SourceCursor::new("ledger:5").unwrap()).unwrap())
            .unwrap();
        store
            .save(&Checkpoint::at("src-b", SourceCursor::new("ledger:1").unwrap()).unwrap())
            .unwrap();
        // Positions are scoped per source and independently resumable.
        assert_eq!(store.load("src-a").unwrap().unwrap().as_str(), "ledger:5");
        assert_eq!(store.load("src-b").unwrap().unwrap().as_str(), "ledger:1");
        // Advancing one source leaves the other untouched.
        store
            .save(&Checkpoint::at("src-a", SourceCursor::new("ledger:9").unwrap()).unwrap())
            .unwrap();
        assert_eq!(store.load("src-a").unwrap().unwrap().as_str(), "ledger:9");
        assert_eq!(store.load("src-b").unwrap().unwrap().as_str(), "ledger:1");
        assert!(store.load("src-c").unwrap().is_none());
    }

    #[test]
    fn saving_a_fresh_checkpoint_is_a_noop() {
        let mut store = InMemoryCheckpointStore::new();
        store.save(&Checkpoint::fresh("src").unwrap()).unwrap();
        assert!(store.load("src").unwrap().is_none());
    }
}
