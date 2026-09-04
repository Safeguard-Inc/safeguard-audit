//! `authorize-access` — a runnable walk-through of the authorization
//! services.
//!
//! Registers auditors with roles, scopes, and expiring credentials, asks
//! the authorizer for decisions across the outcome space (granted,
//! denied by role, out-of-scope, expired), and records every decision as
//! an `audit-access` event in a store — the audit trail auditing itself.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p safeguard-audit-integration-tests --example authorize-access
//! ```
//!
//! This is a demonstration harness, not a production binary: the registry
//! and store are in-memory, and credentials are opaque test material (no
//! real identity provider is involved).

use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry, StoreAccessLog};
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditorId, AuditorRole, FixedClock, NetworkId, PageRequest,
    Timestamp, VersionLabel,
};
use safeguard_audit_memory_store::MemoryEventStore;
use safeguard_audit_storage::{AuditQuery, EventStore};

fn main() {
    let network = NetworkId::new(NetworkId::TESTNET).unwrap();
    let now = Timestamp::from_unix_seconds(1_700_000_000);

    // --- Registry: three auditors with real least-privilege shapes. ---
    let mut registry = Registry::new();
    let senior = AuditorId::derive(&["senior-auditor-01"]);
    let reviewer = AuditorId::derive(&["read-only-01"]);
    let lapsed = AuditorId::derive(&["lapsed-credential-01"]);

    registry
        .register(
            Grant::new(senior.clone(), AuditorRole::SeniorAuditor)
                .with_scope(AccessScope::Network(network.clone()))
                .with_credential(Credential::new(
                    senior.clone(),
                    "issued-senior-credential",
                    Timestamp::from_unix_seconds(1_900_000_000),
                )),
        )
        .expect("senior grant is valid");

    registry
        .register(
            Grant::new(reviewer.clone(), AuditorRole::ReadOnlyReviewer)
                .with_scope(AccessScope::Network(network.clone()))
                .with_credential(Credential::new(
                    reviewer.clone(),
                    "issued-reviewer-credential",
                    Timestamp::from_unix_seconds(1_900_000_000),
                )),
        )
        .expect("reviewer grant is valid");

    registry
        .register(
            Grant::new(lapsed.clone(), AuditorRole::ReadOnlyReviewer)
                .with_scope(AccessScope::Network(network.clone()))
                .with_credential(Credential::new(
                    lapsed.clone(),
                    "lapsed-credential",
                    // Already expired: every decision for this auditor must
                    // deny, even though the role and scope are fine.
                    Timestamp::from_unix_seconds(1_600_000_000),
                )),
        )
        .expect("lapsed grant is valid");

    let authorizer = Authorizer::new(registry, FixedClock::at(now));
    let mut store = MemoryEventStore::new();
    let log = StoreAccessLog::new(
        network.clone(),
        "safeguard-audit-authorization",
        VersionLabel::new("1.0.0").unwrap(),
        FixedClock::at(now),
    );

    // --- Ask the questions an operator would ask. ---------------------
    let cases = [
        (
            &senior,
            "senior reads a record on testnet",
            AccessAction::ReadRecord,
            AccessScope::Network(network.clone()),
        ),
        (
            &senior,
            "senior generates a report on testnet",
            AccessAction::GenerateReport,
            AccessScope::Network(network.clone()),
        ),
        (
            &senior,
            "senior exports records on mainnet (out of scope)",
            AccessAction::ExportRecords,
            AccessScope::Network(NetworkId::new(NetworkId::MAINNET).unwrap()),
        ),
        (
            &reviewer,
            "read-only reviewer reads on testnet",
            AccessAction::ReadRecord,
            AccessScope::Network(network.clone()),
        ),
        (
            &reviewer,
            "read-only reviewer requests protected data (denied by role)",
            AccessAction::RequestProtectedData,
            AccessScope::Network(network.clone()),
        ),
        (
            &lapsed,
            "lapsed-credential auditor reads on testnet (credential expired)",
            AccessAction::ReadRecord,
            AccessScope::Network(network.clone()),
        ),
    ];

    for (auditor, what, action, scope) in cases {
        let decision = authorizer
            .authorize(auditor, action, &scope)
            .expect("authorize never fails on policy outcomes");
        let entry = authorizer
            .entry_for_decision(&decision, Some("rec_1234"))
            .expect("entry builds");
        log.record_into(&entry, &mut store)
            .expect("access entry is recorded");

        let outcome = match (decision.allowed(), decision.reason()) {
            (true, _) => "GRANTED",
            (false, Some(r)) => r,
            (false, None) => "DENIED",
        };
        println!("  [{outcome:<18}] {} — scope {}", what, decision.scope());
    }

    // --- Show the recorded audit-access trail. ------------------------
    let records = store
        .query(
            &AuditQuery::builder().build().unwrap(),
            &PageRequest::new(1000).unwrap(),
        )
        .unwrap()
        .items()
        .to_vec();
    println!(
        "\n{} audit-access record(s) persisted — the audit trail auditing itself:",
        records.len()
    );
    for record in records {
        let d = &record.event.details;
        println!(
            "  {} | auditor={} | action={} | result={} | at={}",
            d.get("entry").map(String::as_str).unwrap_or("?"),
            d.get("auditor").map(String::as_str).unwrap_or("?"),
            d.get("action").map(String::as_str).unwrap_or("?"),
            d.get("result").map(String::as_str).unwrap_or("?"),
            d.get("accessed_at").map(String::as_str).unwrap_or("?"),
        );
    }
    println!("\nOK: decisions are attributed, recorded, and replayable.");
}
