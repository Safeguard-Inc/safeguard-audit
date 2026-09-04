//! Runtime verification of the committed authorization test vectors.
//!
//! Every file under `test-vectors/authorization` declares an access
//! request — a role, granted scopes (as stable `describe()` labels), a
//! credential expiry, an action, a requested scope, and a decision time —
//! and the decision the authorizer must reach. The walker registers the
//! grant, asks for the decision, and compares allowed/reason. New vectors
//! can be added without touching code; the corpus is the executable
//! contract for the authorization service.

use std::path::{Path, PathBuf};

use safeguard_audit_authorization::{reason, Authorizer, Credential, Grant, Registry};
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditorId, AuditorRole, DataClassification, FixedClock,
    NetworkId, Timestamp,
};
use serde::Deserialize;

/// The workspace-relative vectors root, resolved at compile time so the
/// test works from any working directory.
fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
        .join("authorization")
}

#[derive(Deserialize)]
struct Vector {
    scheme: String,
    #[serde(default)]
    note: Option<String>,
    role: String,
    granted_scopes: Vec<String>,
    credential_expires_at: i64,
    #[serde(default)]
    unknown_auditor: bool,
    action: String,
    requested_scope: String,
    now: i64,
    expect: Expectation,
}

#[derive(Deserialize)]
struct Expectation {
    allowed: bool,
    reason: String,
}

fn parse_scope(label: &str) -> AccessScope {
    if label == "all" {
        return AccessScope::All;
    }
    if let Some(net) = label.strip_prefix("network:") {
        return AccessScope::Network(NetworkId::new(net).expect("network label"));
    }
    if let Some(cls) = label.strip_prefix("classification:") {
        let classification = match cls {
            "public" => DataClassification::Public,
            "operational" => DataClassification::Operational,
            "confidential" => DataClassification::Confidential,
            "restricted" => DataClassification::Restricted,
            "highly-restricted" => DataClassification::HighlyRestricted,
            other => panic!("unsupported classification label {other}"),
        };
        return AccessScope::Classification(classification);
    }
    panic!("vector uses unsupported scope label {label:?}");
}

fn parse_role(role: &str) -> AuditorRole {
    match role {
        "read-only-reviewer" => AuditorRole::ReadOnlyReviewer,
        "auditor" => AuditorRole::Auditor,
        "senior-auditor" => AuditorRole::SeniorAuditor,
        "investigator" => AuditorRole::Investigator,
        "compliance-officer" => AuditorRole::ComplianceOfficer,
        "administrator" => AuditorRole::Administrator,
        other => panic!("unsupported role {other}"),
    }
}

fn parse_action(action: &str) -> AccessAction {
    match action {
        "read-record" => AccessAction::ReadRecord,
        "query" => AccessAction::Query,
        "inspect-transaction" => AccessAction::InspectTransaction,
        "inspect-policy" => AccessAction::InspectPolicy,
        "inspect-denied" => AccessAction::InspectDenied,
        "create-investigation" => AccessAction::CreateInvestigation,
        "view-investigation" => AccessAction::ViewInvestigation,
        "generate-evidence" => AccessAction::GenerateEvidence,
        "generate-report" => AccessAction::GenerateReport,
        "export-records" => AccessAction::ExportRecords,
        "request-protected-data" => AccessAction::RequestProtectedData,
        "verify-integrity" => AccessAction::VerifyIntegrity,
        other => panic!("unsupported action {other}"),
    }
}

fn read_vectors() -> Vec<(PathBuf, Vector)> {
    let root = vectors_root();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("vectors dir must exist: {e}"))
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

fn run_vector(vector: &Vector) -> (bool, String) {
    let auditor = AuditorId::derive(&["vector-auditor"]);
    let now = Timestamp::from_unix_seconds(vector.now);

    // An unknown-auditor vector registers no grant.
    let mut registry = Registry::new();
    if !vector.unknown_auditor {
        let mut grant = Grant::new(auditor.clone(), parse_role(&vector.role));
        for label in &vector.granted_scopes {
            grant = grant.with_scope(parse_scope(label));
        }
        if !grant.scopes.is_empty() {
            grant = grant.with_credential(Credential::new(
                auditor.clone(),
                "vector-material",
                Timestamp::from_unix_seconds(vector.credential_expires_at),
            ));
            registry.register(grant).unwrap();
        }
    }

    let authorizer = Authorizer::new(registry, FixedClock::at(now));
    let requested = parse_scope(&vector.requested_scope);
    let decision = authorizer
        .authorize(&auditor, parse_action(&vector.action), &requested)
        .unwrap();
    (decision.allowed(), decision.reason().unwrap_or("").to_owned())
}

#[test]
fn every_vector_produces_its_declared_decision() {
    let vectors = read_vectors();
    assert!(
        vectors.len() >= 6,
        "the authorization vector corpus must stay populated"
    );
    for (path, vector) in &vectors {
        let name = path.file_name().unwrap().to_string_lossy();
        let (allowed, got_reason) = run_vector(vector);
        assert_eq!(
            allowed,
            vector.expect.allowed,
            "vector {name} allowed mismatch (expected {}): {}",
            vector.expect.allowed,
            vector.note.as_deref().unwrap_or("")
        );
        assert_eq!(
            got_reason,
            vector.expect.reason,
            "vector {name} reason mismatch: {}",
            vector.note.as_deref().unwrap_or("")
        );
    }
}

#[test]
fn reason_labels_in_vectors_are_known() {
    // Guards the corpus against typos in reason codes.
    let known = [
        reason::GRANTED,
        reason::ACTION_DENIED,
        reason::SCOPE_OUT_OF_BOUNDS,
        reason::CREDENTIAL_EXPIRED,
        reason::CREDENTIAL_INVALID,
        reason::UNKNOWN_AUDITOR,
    ];
    for (path, vector) in &read_vectors() {
        assert_eq!(
            vector.scheme, "authorization-decision",
            "{} must declare scheme authorization-decision",
            path.display()
        );
        assert!(
            known.contains(&vector.expect.reason.as_str()),
            "{} declares unknown reason {}",
            path.display(),
            vector.expect.reason
        );
    }
}
