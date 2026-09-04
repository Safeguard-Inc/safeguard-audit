//! # safeguard-audit-integration-tests
//!
//! End-to-end integration coverage for the audit pipeline. This crate is
//! deliberately dependency-light on production code paths and test-only in
//! intent: its tests drive the real pipeline — raw fixture sources through
//! the normalizer, indexer, store, replay, and integrity verification —
//! exactly the way an operator or the CLI would, so a change in any one
//! crate cannot quietly break the contract between the others.
