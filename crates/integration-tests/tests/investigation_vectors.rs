//! Runtime verification of the committed investigation vectors.
//!
//! Every file under `test-vectors/investigation/lifecycle/valid` declares
//! a case-status transition the core model must allow; every file under
//! `.../invalid` declares one it must reject. The walker checks each
//! against the real `CaseStatus::can_transition`, so the corpus is the
//! executable contract for lifecycle legality — new vectors need no code.

use std::path::{Path, PathBuf};

use safeguard_audit_core::CaseStatus;
use serde::Deserialize;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("investigation")
        .join("lifecycle")
}

#[derive(Deserialize)]
struct Vector {
    scheme: String,
    #[serde(default)]
    note: Option<String>,
    from: String,
    to: String,
    allowed: bool,
}

fn parse_status(label: &str) -> CaseStatus {
    match label {
        "open" => CaseStatus::Open,
        "investigating" => CaseStatus::Investigating,
        "escalated" => CaseStatus::Escalated,
        "resolved" => CaseStatus::Resolved,
        "closed" => CaseStatus::Closed,
        other => panic!("unsupported status {other}"),
    }
}

fn read_vectors(dir: &str) -> Vec<(PathBuf, Vector)> {
    let root = vectors_root().join(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("vectors dir {} must exist: {e}", root.display()))
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

#[test]
fn every_valid_transition_is_allowed_by_the_model() {
    let vectors = read_vectors("valid");
    assert!(
        vectors.len() >= 7,
        "the valid lifecycle corpus must stay populated"
    );
    for (path, vector) in &vectors {
        assert_eq!(vector.scheme, "investigation-lifecycle");
        let from = parse_status(&vector.from);
        let to = parse_status(&vector.to);
        assert!(
            vector.allowed && from.can_transition(to),
            "{} ({:?} -> {:?}) must be legal: {}",
            path.display(),
            from,
            to,
            vector.note.as_deref().unwrap_or("")
        );
    }
}

#[test]
fn every_invalid_transition_is_rejected_by_the_model() {
    let vectors = read_vectors("invalid");
    assert!(
        vectors.len() >= 4,
        "the invalid lifecycle corpus must stay populated"
    );
    for (path, vector) in &vectors {
        let from = parse_status(&vector.from);
        let to = parse_status(&vector.to);
        assert!(
            !vector.allowed && !from.can_transition(to),
            "{} ({:?} -> {:?}) must be illegal: {}",
            path.display(),
            from,
            to,
            vector.note.as_deref().unwrap_or("")
        );
    }
}

#[test]
fn status_labels_round_trip_through_as_str() {
    // Guards the corpus against typos in status labels.
    for dir in ["valid", "invalid"] {
        for (path, vector) in &read_vectors(dir) {
            assert_eq!(
                parse_status(&vector.from).as_str(),
                vector.from,
                "{} label drift",
                path.display()
            );
            assert_eq!(
                parse_status(&vector.to).as_str(),
                vector.to,
                "{} label drift",
                path.display()
            );
        }
    }
}
