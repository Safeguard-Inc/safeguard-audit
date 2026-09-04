//! Errors surfaced by the in-memory store.
//!
//! The memory store speaks the storage crate's [`StoreError`] taxonomy —
//! callers must not have to branch on which store they talk to. This module
//! re-exports the taxonomy and adds nothing of its own.

pub use safeguard_audit_storage::{StoreError, StoreResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_is_reachable() {
        let err = StoreError::NotFound("rec_x".into());
        assert!(err.to_string().contains("rec_x"));
    }
}
