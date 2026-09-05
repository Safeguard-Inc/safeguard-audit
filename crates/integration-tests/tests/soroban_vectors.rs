//! Runtime verification of the committed Soroban wire vectors.
//!
//! Every file under `test-vectors/soroban` declares a wire event and
//! whether it must map cleanly onto normalized metadata (passing the
//! single wire `validate()` door and the `to_normalized` mapping). The
//! walker runs the same path the ingestion pipeline uses — the same
//! `SorobanEvent::validate` and `to_normalized` the source and mapping
//! call — and compares against the declared expectation. New vectors
//! can be added without touching code; the corpus is the executable
//! contract for wire coherence (TOID ids, ledger positivity, topic
//! cardinality, hash shape, strict UTC close times).

use std::path::{Path, PathBuf};

use safeguard_audit_core::NetworkId;
use safeguard_audit_soroban::{to_normalized, SorobanEvent};
use serde::Deserialize;

/// The workspace-relative vectors root, resolved at compile time so the
/// test works from any working directory.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("soroban")
}

#[derive(Deserialize)]
struct Vector {
    network: String,
    #[serde(default)]
    note: Option<String>,
    event: SorobanEvent,
    expect: Expectation,
}

#[derive(Deserialize)]
struct Expectation {
    ok: bool,
}

fn read_vectors(dir: &str) -> Vec<(String, Vector)> {
    let dir = vectors_root().join(dir);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        let vector: Vector = serde_json::from_str(&raw).unwrap_or_else(|error| {
            panic!(
                "{} does not parse as a soroban vector: {error}",
                path.display()
            )
        });
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        out.push((name, vector));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn every_vector_maps_as_declared() {
    let mut checked = 0;
    for (subdir, expected_ok) in [("valid", true), ("invalid", false)] {
        for (name, vector) in read_vectors(subdir) {
            checked += 1;
            // Each vector declares its own expectation; a declaration
            // that contradicts its directory is an authoring error.
            assert_eq!(
                vector.expect.ok, expected_ok,
                "vector {name} declares ok:{} but sits in {subdir}/",
                vector.expect.ok
            );
            // The network names the vectors' network; parse failures
            // are vector errors, not mapping results.
            let network = NetworkId::new(&vector.network)
                .unwrap_or_else(|error| panic!("vector {name} names an invalid network: {error}"));
            let outcome = to_normalized(&vector.event, network).is_ok();
            assert_eq!(
                outcome,
                expected_ok,
                "vector {name} (in {subdir}/) did not map as declared: {}",
                vector.note.as_deref().unwrap_or("no note")
            );
        }
    }
    assert_eq!(checked, 12, "the soroban corpus must stay populated");
}
