//! Runtime verification of the committed evidence test vectors.
//!
//! Every file under `test-vectors/evidence` is a complete evidence
//! package (artifact plus integrity manifest) with the verification
//! verdict it must produce at structure level: artifact content digest,
//! manifest aggregate, and whether the package verifies overall. The
//! walker reconstructs the package, runs the same verification the
//! service would, and compares. New vectors can be added without touching
//! code; the corpus is the executable contract for evidence integrity.

use std::path::{Path, PathBuf};

use safeguard_audit_core::{EvidenceArtifact, IntegrityStatus};
use safeguard_audit_evidence::{EvidenceManifest, EvidencePackage};
use serde::Deserialize;

/// The workspace-relative vectors root, resolved at compile time so the
/// test works from any working directory.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("evidence")
}

#[derive(Deserialize)]
struct Vector {
    scheme: String,
    #[serde(default)]
    note: Option<String>,
    artifact: EvidenceArtifact,
    manifest: EvidenceManifest,
    expect: Expectation,
}

#[derive(Deserialize)]
struct Expectation {
    verified: bool,
    artifact: bool,
    aggregate: bool,
}

fn read_vectors() -> Vec<(PathBuf, Vector)> {
    let root = vectors_root();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_json(&root, &mut files);
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

/// Collects every JSON file under `dir`, recursing into subdirectories.
fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("vectors dir must exist: {e}")) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_json(&path, out);
        } else if path.extension().is_some_and(|x| x == "json") {
            out.push(path);
        }
    }
}

/// Runs structure-level verification, mapping construction or
/// verification failure to an all-false verdict (an invalid package
/// cannot verify).
fn run_vector(vector: &Vector) -> (bool, bool, bool) {
    let package = match EvidencePackage::new(vector.artifact.clone(), vector.manifest.clone()) {
        Ok(package) => package,
        Err(_) => return (false, false, false),
    };
    match safeguard_audit_evidence::verify_package_structure(&package) {
        Ok(verification) => (
            verification.verified(),
            verification.artifact_verified(),
            verification.aggregate() == IntegrityStatus::Verified,
        ),
        Err(_) => (false, false, false),
    }
}

#[test]
fn every_vector_produces_its_declared_verdict() {
    let vectors = read_vectors();
    assert!(
        vectors.len() >= 4,
        "the evidence vector corpus must stay populated"
    );
    for (path, vector) in &vectors {
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(
            vector.scheme, "evidence-package",
            "{name} must declare scheme evidence-package"
        );
        let (verified, artifact, aggregate) = run_vector(vector);
        assert_eq!(
            verified,
            vector.expect.verified,
            "vector {name} verified mismatch: {}",
            vector.note.as_deref().unwrap_or("")
        );
        assert_eq!(
            artifact,
            vector.expect.artifact,
            "vector {name} artifact digest mismatch: {}",
            vector.note.as_deref().unwrap_or("")
        );
        assert_eq!(
            aggregate,
            vector.expect.aggregate,
            "vector {name} aggregate mismatch: {}",
            vector.note.as_deref().unwrap_or("")
        );
    }
}
