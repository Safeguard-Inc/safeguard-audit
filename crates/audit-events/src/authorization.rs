//! Authorization events.
//!
//! Two derived kinds live here:
//!
//! * `authorization-changed` — an auditor's grant or scope was changed by
//!   an administrator (or the change was observed), recorded so role
//!   history is itself auditable, and
//! * `audit-access` — an auditor accessed audit data; the audit trail
//!   auditing itself. Access entries come from the core authorization
//!   model and are recorded once; there is no meta-audit beyond this.

use safeguard_audit_core::{
    AccessResult, AuditAccessEntry, AuditEvent, AuditorId, AuditorRole, EventKind, NetworkId,
    VersionLabel,
};

use crate::event_id::{derived_audit_event_base, DerivationSource, EventSlot};
use crate::EventResult;

/// What kind of authorization change happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// A grant was added or extended.
    Granted,
    /// A grant was revoked.
    Revoked,
}

impl ChangeKind {
    /// The stable label for this change kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Revoked => "revoked",
        }
    }
}

/// A recorded authorization change to an auditor identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationChange {
    /// The network the change is recorded on (configuration domain).
    pub network: NetworkId,
    /// Stable source label (e.g. `safeguard-audit-admin`).
    pub source: String,
    /// Parser version.
    pub parser: VersionLabel,
    /// The auditor whose grants changed.
    pub subject: AuditorId,
    /// The acting administrator, when known.
    pub actor: Option<AuditorId>,
    /// Whether a grant was added or revoked.
    pub change: ChangeKind,
    /// The role granted/revoked.
    pub role: AuditorRole,
    /// The scope the change applies to (stable describe() label).
    pub scope: String,
}

impl AuthorizationChange {
    /// Derives the normalized `authorization-changed` event.
    pub fn into_audit_event(&self, slot: EventSlot) -> EventResult<AuditEvent> {
        let mut refs = vec![self.subject.as_str().to_owned(), self.scope.clone()];
        if let Some(actor) = &self.actor {
            refs.push(actor.as_str().to_owned());
        }
        let source_refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        let mut event = derived_audit_event_base(
            EventKind::AuthorizationChanged,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            DerivationSource {
                method: "authorization-change-recorded",
                note: "authorization grant or revocation recorded for the audit trail",
                source_refs: &source_refs,
                tx: None,
                source_events: Vec::new(),
            },
            slot,
        )?;
        event
            .details
            .insert("change".into(), self.change.as_str().to_owned());
        event
            .details
            .insert("role".into(), self.role.as_str().to_owned());
        event.details.insert("scope".into(), self.scope.clone());
        event
            .details
            .insert("subject".into(), self.subject.as_str().to_owned());
        if let Some(actor) = &self.actor {
            event
                .details
                .insert("actor".into(), actor.as_str().to_owned());
        }
        Ok(event)
    }
}

/// Records an auditor's access to audit data as a derived `audit-access`
/// event.
pub fn access_recorded_event(
    entry: &AuditAccessEntry,
    network: NetworkId,
    source: &str,
    parser: VersionLabel,
    slot: EventSlot,
) -> EventResult<AuditEvent> {
    let source_refs = [
        entry.auditor().as_str(),
        entry.action().as_str(),
        entry.scope(),
    ];
    let mut event = derived_audit_event_base(
        EventKind::AuditAccess,
        network,
        source,
        parser,
        DerivationSource {
            method: "audit-access-log",
            note: "auditor access to audit data recorded (the audit trail auditing itself)",
            source_refs: &source_refs,
            tx: None,
            source_events: Vec::new(),
        },
        slot,
    )?;
    event
        .details
        .insert("entry".into(), entry.entry_id().as_str().to_owned());
    event
        .details
        .insert("action".into(), entry.action().as_str().to_owned());
    event
        .details
        .insert("scope".into(), entry.scope().to_owned());
    event.details.insert(
        "result".into(),
        match entry.result() {
            AccessResult::Granted => "granted",
            AccessResult::Denied => "denied",
            AccessResult::OutOfScope => "out-of-scope",
        }
        .to_owned(),
    );
    if let Some(target) = entry.target() {
        event.details.insert("target".into(), target.to_owned());
    }
    // Attribution: the persisted record must answer *who* accessed and
    // *when*, not hide them behind the derived event id. The auditor id is
    // deliberately the `aud_...` reference, never credential material.
    event
        .details
        .insert("auditor".into(), entry.auditor().as_str().to_owned());
    event.details.insert(
        "accessed_at".into(),
        entry.accessed_at().as_unix_seconds().to_string(),
    );
    if let Some(classification) = entry.classification() {
        event
            .details
            .insert("classification".into(), classification.as_str().to_owned());
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::{
        AccessAction, AccessEntryId, AccessScope, AuditAccessEntry, Timestamp,
    };

    fn network() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    #[test]
    fn authorization_changes_project_with_role_and_scope() {
        let change = AuthorizationChange {
            network: network(),
            source: "safeguard-audit-admin".into(),
            parser: VersionLabel::new("1.0.0").unwrap(),
            subject: AuditorId::derive(&["aud-1"]),
            actor: Some(AuditorId::derive(&["aud-admin"])),
            change: ChangeKind::Revoked,
            role: AuditorRole::Investigator,
            scope: AccessScope::All.describe(),
        };
        let event = change.into_audit_event(EventSlot::default()).unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::AuthorizationChanged);
        assert_eq!(event.details.get("change").unwrap(), "revoked");
        assert_eq!(event.details.get("role").unwrap(), "investigator");
    }

    #[test]
    fn access_entries_become_audit_access_events() {
        let entry = AuditAccessEntry::new(
            AccessEntryId::derive(&["e1"]),
            AuditorId::derive(&["aud-2"]),
            AccessAction::ReadRecord,
            "network:testnet".into(),
            Some("rec_abcd".into()),
            AccessResult::Granted,
            Timestamp::from_unix_seconds(100),
        );
        let event = access_recorded_event(
            &entry,
            network(),
            "safeguard-audit",
            VersionLabel::new("1.0.0").unwrap(),
            EventSlot::default(),
        )
        .unwrap();
        assert!(event.validate().is_ok());
        assert_eq!(event.kind, EventKind::AuditAccess);
        assert_eq!(event.details.get("result").unwrap(), "granted");
        assert_eq!(event.details.get("target").unwrap(), "rec_abcd");
    }
}
