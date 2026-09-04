//! The audit-access log.
//!
//! Access to audit data must itself be auditable. This module turns every
//! [`AuthorizationDecision`] into an [`AuditAccessEntry`] and persists it
//! as a derived `audit-access` event through the [`EventStore`]:
//!
//! ```text
//! AuthorizationDecision
//!   ──► AuditAccessEntry (who / what / where / when / result)
//!   ──► audit-access AuditEvent (derived, provenance-stamped)
//!   ──► AuditRecord ──► store
//! ```
//!
//! ## No infinite recursion
//!
//! The audit trail auditing itself stops here. Recording an access entry
//! is *not* itself re-authorized — that would recurse forever. The entry
//! model holds no pointer back to a meta-audit of the audit; once the
//! event lands in the store, the trail is complete.

use safeguard_audit_core::{
    AuditAccessEntry, AuditRecord, Clock, DataClassification, EventKind, NetworkId, VersionLabel,
};
use safeguard_audit_events::{access_recorded_event, EventSlot};
use safeguard_audit_storage::{EventStore, InsertOutcome};

use crate::errors::{AuthorizationError, AuthorizationResult};

/// The access-log contract: persist one access entry.
///
/// The store-backed implementation records through the audit pipeline; a
/// test double may capture entries instead. Either way, recording is
/// fire-and-forget from the authorizer's perspective — a failure to record
/// is reported as [`AuthorizationError::AccessLogFailure`], never silently
/// swallowed.
pub trait AccessLog {
    /// Records one access entry. Implementations must be idempotent for
    /// the same entry id (re-recording the same decision is a no-op).
    fn record(&mut self, entry: &AuditAccessEntry) -> AuthorizationResult<()>;
}

/// Records access entries into an [`EventStore`] as `audit-access`
/// records.
///
/// `network` is the configuration domain the access is recorded on;
/// `source` and `parser` stamp provenance on the derived event so an
/// investigator can always tell *which* system and *which version* of the
/// authorization services produced the entry.
pub struct StoreAccessLog {
    network: NetworkId,
    source: String,
    parser: VersionLabel,
    clock: Box<dyn Clock>,
}

impl StoreAccessLog {
    /// Builds a store-backed access log.
    pub fn new(
        network: NetworkId,
        source: impl Into<String>,
        parser: VersionLabel,
        clock: impl Clock + 'static,
    ) -> Self {
        Self {
            network,
            source: source.into(),
            parser,
            clock: Box::new(clock),
        }
    }

    /// Records `entry` into `store`, deriving a deterministic `audit-access`
    /// event and record from it.
    pub fn record_into(
        &self,
        entry: &AuditAccessEntry,
        store: &mut dyn EventStore,
    ) -> AuthorizationResult<()> {
        let event = access_recorded_event(
            entry,
            self.network.clone(),
            &self.source,
            self.parser.clone(),
            EventSlot::default(),
        )
        .map_err(|e| AuthorizationError::AccessLogFailure(e.to_string()))?;

        debug_assert_eq!(event.kind, EventKind::AuditAccess);
        let record = AuditRecord::from_event_classified(
            event,
            DataClassification::Confidential,
            self.clock.as_ref(),
        )
        .map_err(|e| AuthorizationError::AccessLogFailure(e.to_string()))?;

        match store.insert(record) {
            Ok(InsertOutcome::Inserted) | Ok(InsertOutcome::Duplicate) => Ok(()),
            Err(e) => Err(AuthorizationError::AccessLogFailure(e.to_string())),
        }
    }
}

/// A store-bound access log adapter: wraps a store reference so callers
/// can pass a single `&mut AccessLog` to the authorizer.
pub struct AccessLogWithStore<'a> {
    log: StoreAccessLog,
    store: &'a mut dyn EventStore,
}

impl<'a> AccessLogWithStore<'a> {
    /// Binds a store-backed log to a store for the lifetime of the borrow.
    pub fn new(log: StoreAccessLog, store: &'a mut dyn EventStore) -> Self {
        Self { log, store }
    }
}

impl AccessLog for AccessLogWithStore<'_> {
    fn record(&mut self, entry: &AuditAccessEntry) -> AuthorizationResult<()> {
        self.log.record_into(entry, self.store)
    }
}

/// A no-op access log for systems that deliberately do not record access
/// (e.g. development runs). Labeled clearly: it provides no auditability.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAccessLog;

impl AccessLog for NoopAccessLog {
    fn record(&mut self, _entry: &AuditAccessEntry) -> AuthorizationResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_core::PageRequest;
    use safeguard_audit_core::{
        AccessAction, AccessEntryId, AccessResult, AccessScope, AuditorId, FixedClock, NetworkId,
        Timestamp,
    };
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::AuditQuery;

    fn entry(result: AccessResult) -> AuditAccessEntry {
        AuditAccessEntry::new(
            AccessEntryId::derive(&["a1", "read-record", "network:testnet", "1000"]),
            AuditorId::derive(&["a1"]),
            AccessAction::ReadRecord,
            AccessScope::Network(NetworkId::new(NetworkId::TESTNET).unwrap()).describe(),
            Some("rec_abcd".to_owned()),
            result,
            Timestamp::from_unix_seconds(1_000),
        )
    }

    fn log() -> StoreAccessLog {
        StoreAccessLog::new(
            NetworkId::new(NetworkId::TESTNET).unwrap(),
            crate::SOURCE_LABEL,
            VersionLabel::new("1.0.0").unwrap(),
            FixedClock::at(Timestamp::from_unix_seconds(1_000)),
        )
    }

    #[test]
    fn entries_land_in_the_store_as_audit_access_records() {
        let mut store = MemoryEventStore::new();
        log()
            .record_into(&entry(AccessResult::Granted), &mut store)
            .unwrap();

        assert_eq!(store.len(), 1);
        let page = store
            .query(
                &AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let items = page.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].event.kind, EventKind::AuditAccess);
        assert_eq!(items[0].event.details.get("result").unwrap(), "granted");
        assert_eq!(items[0].event.details.get("target").unwrap(), "rec_abcd");
    }

    #[test]
    fn re_recording_the_same_entry_is_idempotent() {
        let mut store = MemoryEventStore::new();
        let e = entry(AccessResult::Denied);
        log().record_into(&e, &mut store).unwrap();
        log().record_into(&e, &mut store).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_bound_adapter_records_through_the_trait() {
        let mut store = MemoryEventStore::new();
        let mut bound = AccessLogWithStore::new(log(), &mut store);
        bound.record(&entry(AccessResult::Granted)).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn noop_log_records_nothing_and_is_honest_about_it() {
        let mut noop = NoopAccessLog;
        assert!(noop.record(&entry(AccessResult::Granted)).is_ok());
    }
}
