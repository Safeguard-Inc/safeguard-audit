//! Canonical serialization helpers.
//!
//! Deterministic hashing (record digests, evidence manifests, derived ids)
//! is only deterministic if the bytes being hashed are. These helpers
//! produce canonical JSON:
//!
//! * object keys are serialized in sorted order (serde_json's default `Map`
//!   is a `BTreeMap`, so map key order can never leak into the bytes), and
//! * struct field order is fixed by declaration, so the same struct always
//!   serializes to the same bytes.
//!
//! Two processes serializing the same value therefore produce identical
//! bytes, which is the precondition for reproducible digests and reports.

use serde::Serialize;

use crate::errors::AuditResult;

/// Serializes `value` to canonical JSON bytes.
///
/// Canonical here means: sorted object keys, no insignificant whitespace,
/// struct fields in declaration order. The same `value` always produces the
/// same bytes, on every platform and process.
pub fn canonical_json<T: Serialize>(value: &T) -> AuditResult<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

/// Serializes `value` to a canonical JSON string.
pub fn canonical_json_string<T: Serialize>(value: &T) -> AuditResult<String> {
    Ok(serde_json::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(serde::Serialize)]
    struct Sample {
        name: &'static str,
        tags: BTreeMap<&'static str, u32>,
    }

    #[test]
    fn identical_values_produce_identical_bytes() {
        let a = Sample {
            name: "x",
            tags: BTreeMap::from([("b", 2), ("a", 1)]),
        };
        let b = Sample {
            name: "x",
            tags: BTreeMap::from([("a", 1), ("b", 2)]),
        };
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
    }

    #[test]
    fn map_insertion_order_never_leaks() {
        let mut one = BTreeMap::new();
        one.insert("z", 1);
        one.insert("a", 2);
        let mut two = BTreeMap::new();
        two.insert("a", 2);
        two.insert("z", 1);
        assert_eq!(canonical_json(&one).unwrap(), canonical_json(&two).unwrap());
    }

    #[test]
    fn different_values_differ() {
        let a = canonical_json(&"value-a").unwrap();
        let b = canonical_json(&"value-b").unwrap();
        assert_ne!(a, b);
    }
}
