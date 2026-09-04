//! Runtime verification of the committed normalization test vectors.
//!
//! Every file under `test-vectors/normalization/valid` must normalize
//! successfully and deterministically; every file under
//! `test-vectors/normalization/malformed` must fail with the failure
//! class its `expect` field declares. New vectors can be added without
//! touching code — the corpus is the executable contract.

use std::path::{Path, PathBuf};

use safeguard_audit_core::{NetworkId, RawEventItem, VersionLabel};
use safeguard_audit_normalizer::{NormalizeConfig, Normalizer, NormalizerError};
use serde::Deserialize;

/// The workspace-relative vectors root, resolved at compile time so the
/// test works from any working directory.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("normalization")
}

#[derive(Deserialize)]
struct Vector {
    scheme: String,
    /// The failure class a malformed vector must produce.
    #[serde(default)]
    expect: Option<String>,
    /// Human-readable documentation of why the vector exists.
    #[serde(default)]
    note: Option<String>,
    payload: serde_json::Value,
}

fn normalizer() -> Normalizer {
    Normalizer::new(NormalizeConfig::new(
        NetworkId::new(NetworkId::TESTNET).unwrap(),
        "safeguard-hooks",
        VersionLabel::new("1.0.0").unwrap(),
    ))
}

fn read_vectors(dir: &str) -> Vec<(PathBuf, Vector)> {
    let root = vectors_root().join(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("vectors dir {dir} must exist: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let vector: Vector = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("decode {}: {e}", path.display()));
            (path, vector)
        })
        .collect()
}

fn run(vector: &Vector) -> Result<safeguard_audit_normalizer::NormalizedEvent, NormalizerError> {
    let payload = serde_json::to_string(&vector.payload).expect("payload is JSON");
    let item = RawEventItem::new(vector.scheme.clone(), payload, "vector").unwrap();
    normalizer().normalize(&item)
}

#[test]
fn every_valid_vector_normalizes_deterministically() {
    let vectors = read_vectors("valid");
    assert!(
        !vectors.is_empty(),
        "valid vectors corpus must not be empty"
    );
    for (path, vector) in vectors {
        let name = path.file_name().unwrap().to_string_lossy();
        let note = vector.note.as_deref().unwrap_or("(no note)");
        let first =
            run(&vector).unwrap_or_else(|e| panic!("valid vector {name} failed ({note}): {e}"));
        // Normalized envelopes must satisfy their own invariants.
        first.event.validate().unwrap_or_else(|e| {
            panic!("valid vector {name} produced an invalid envelope ({note}): {e}")
        });
        // Determinism: a second pass yields the identical envelope.
        let second = run(&vector)
            .unwrap_or_else(|e| panic!("valid vector {name} failed on re-run ({note}): {e}"));
        assert_eq!(
            first.event, second.event,
            "vector {name} is not deterministic ({note})"
        );
    }
}

#[test]
fn every_malformed_vector_fails_with_its_declared_class() {
    let vectors = read_vectors("malformed");
    assert!(
        !vectors.is_empty(),
        "malformed vectors corpus must not be empty"
    );
    for (path, vector) in vectors {
        let name = path.file_name().unwrap().to_string_lossy();
        let expect = vector
            .expect
            .as_deref()
            .unwrap_or_else(|| panic!("malformed vector {name} must declare `expect`"));
        let err =
            run(&vector).expect_err(&format!("malformed vector {name} unexpectedly normalized"));
        let ok = match expect {
            "malformed" => matches!(err, NormalizerError::MalformedPayload { .. }),
            "invalid" => matches!(err, NormalizerError::ValidationFailed { .. }),
            "unsupported-version" => matches!(err, NormalizerError::UnsupportedVersion { .. }),
            "unsupported-scheme" => matches!(err, NormalizerError::UnsupportedScheme(_)),
            other => panic!("vector {name} declares unknown expect class `{other}`"),
        };
        assert!(ok, "vector {name} failed with the wrong class: {err}");
    }
}
