//! Runtime verification of the committed reporting test vectors.
//!
//! Every file under `test-vectors/reporting` declares a report query and
//! whether it must map cleanly onto the store's audit query. The walker
//! runs the same mapping the service uses and compares. New vectors can
//! be added without touching code; the corpus is the executable contract
//! for the query mapping (including the rejection of incoherent wire
//! queries such as inverted time ranges).

use std::path::{Path, PathBuf};

use safeguard_audit_core::ReportQuery;
use safeguard_audit_reporting::to_audit_query;
use serde::Deserialize;

/// The workspace-relative vectors root, resolved at compile time so the
/// test works from any working directory.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("reporting")
}

#[derive(Deserialize)]
struct Vector {
    scheme: String,
    #[serde(default)]
    note: Option<String>,
    query: ReportQuery,
    expect: Expectation,
}

#[derive(Deserialize)]
struct Expectation {
    ok: bool,
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

#[test]
fn every_vector_maps_as_declared() {
    let vectors = read_vectors();
    assert!(
        vectors.len() >= 7,
        "the reporting vector corpus must stay populated"
    );
    for (path, vector) in &vectors {
        let name = path.file_name().unwrap().to_string_lossy();
        assert_eq!(
            vector.scheme,
            "report-query-mapping",
            "{name} must declare scheme report-query-mapping"
        );
        let mapped = to_audit_query(&vector.query);
        assert_eq!(
            mapped.is_ok(),
            vector.expect.ok,
            "vector {name} mapping mismatch: {}",
            vector.note.as_deref().unwrap_or("")
        );
    }
}