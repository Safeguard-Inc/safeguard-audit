//! Audit-layer constants, versioning, and defaults.
//!
//! The audit model carries schema versions so that records, evidence, and
//! reports written by one build can be rejected loudly by a build whose
//! schema no longer matches — never silently reinterpreted.

/// The current record schema version.
///
/// Bump this only on a breaking change to the persisted record shape, and
/// update the schemas/ JSON Schema documents in the same change. Old
/// versions are never rewritten; readers either understand them or report a
/// version mismatch.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// The default classification applied when a record's content sensitivity
/// is not otherwise stated.
///
/// Defaulting to `confidential` is the conservative choice: the audit layer
/// may legitimately hold restricted metadata, and an operator must
/// explicitly downgrade a record rather than have the system silently treat
/// protected content as public.
pub const DEFAULT_RECORD_CLASSIFICATION: crate::privacy::DataClassification =
    crate::privacy::DataClassification::Confidential;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants_are_explicit() {
        assert_eq!(RECORD_SCHEMA_VERSION, 1);
        assert_eq!(
            DEFAULT_RECORD_CLASSIFICATION,
            crate::privacy::DataClassification::Confidential
        );
    }
}
