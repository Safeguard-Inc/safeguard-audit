//! Building evidence packages from verified audit records.
//!
//! The builder is deliberately conservative. Before anything is sealed it
//! must, in order:
//!
//! 1. **authorize** — the acting auditor needs the `generate-evidence`
//!    action at the service's network scope; a denial is an error, never
//!    a silent pass;
//! 2. **prove the sources exist** — every named record must be in the
//!    audit store;
//! 3. **prove the sources are intact** — a record carrying a stored
//!    integrity block must still match its body; evidence is never built
//!    over records whose stored digest no longer verifies. Records the
//!    pipeline left unsealed are accepted with their digest recomputed
//!    and captured in the manifest, so later alteration stays detectable;
//! 4. **order deterministically** — the same record set always yields the
//!    same artifact and manifest, whatever order the ids were given in.
//!
//! Only then is the package sealed: the artifact's content digest is
//! computed over its canonical bytes (integrity slots excluded), and an
//! integrity manifest is built over the source records. The generation is
//! then recorded as a derived `evidence-generated` event in the audit
//! store, so the trail attests to its own evidence production.

use safeguard_audit_authorization::{reason, Authorizer};
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditorId, Clock, EvidenceArtifact, EvidenceId, EvidenceKind,
    EvidenceProvenance, NetworkId, RecordId, Timestamp, VersionLabel,
};
use safeguard_audit_events::EvidenceLifecycle;
use safeguard_audit_integrity::{build_manifest, hash_bytes, record_digest, ManifestOptions};
use safeguard_audit_storage::EventStore;

use crate::errors::{EvidenceError, EvidenceResult};
use crate::events::record_generation;
use crate::model::{EvidenceManifest, EvidencePackage};

/// Everything that defines one evidence build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBuildOptions {
    /// What kind of evidence to generate.
    pub kind: EvidenceKind,
    /// The source records, by id. Order is irrelevant — the builder
    /// canonicalizes it.
    pub record_ids: Vec<RecordId>,
    /// The auditor requesting the artifact (recorded as `generated_by`).
    pub generated_by: AuditorId,
}

impl EvidenceBuildOptions {
    /// Builds options; at least one source record is required.
    pub fn new(
        kind: EvidenceKind,
        record_ids: Vec<RecordId>,
        generated_by: AuditorId,
    ) -> EvidenceResult<Self> {
        if record_ids.is_empty() {
            return Err(EvidenceError::NoSourceRecords);
        }
        Ok(Self {
            kind,
            record_ids,
            generated_by,
        })
    }
}

/// The evidence generation service.
pub struct EvidenceBuilder {
    network: NetworkId,
    source: String,
    parser: VersionLabel,
    generator_version: VersionLabel,
    clock: Box<dyn Clock>,
    authorizer: Authorizer,
}

impl EvidenceBuilder {
    /// Builds the service for `network`, stamping artifacts with `clock`
    /// (deterministic in tests) and gating generation with `authorizer`.
    pub fn new(
        network: NetworkId,
        source: impl Into<String>,
        parser: VersionLabel,
        generator_version: VersionLabel,
        clock: impl Clock + 'static,
        authorizer: Authorizer,
    ) -> Self {
        Self {
            network,
            source: source.into(),
            parser,
            generator_version,
            clock: Box::new(clock),
            authorizer,
        }
    }

    /// The network this service operates on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Generates an evidence package over `options.record_ids`.
    ///
    /// Every named record must exist and verify; the record set is then
    /// canonically ordered (by record id) so generation is deterministic.
    /// The generation is recorded into `audit` as a derived
    /// `evidence-generated` event.
    pub fn build(
        &self,
        audit: &mut dyn EventStore,
        options: &EvidenceBuildOptions,
    ) -> EvidenceResult<EvidencePackage> {
        self.require(&options.generated_by)?;

        // Fetch and prove the sources.
        let mut records = Vec::with_capacity(options.record_ids.len());
        for id in &options.record_ids {
            let record = audit
                .get(id)
                .map_err(|_| EvidenceError::RecordMissing(id.clone()))?;
            records.push(record);
        }
        self.require_intact(&records)?;

        // Canonical order: the same set always builds the same package,
        // regardless of the order the ids were supplied in.
        records.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        let record_ids: Vec<RecordId> = records.iter().map(|r| r.record_id.clone()).collect();
        let source_events: Vec<_> = records.iter().map(|r| r.event.event_id.clone()).collect();

        let now = Timestamp::now(self.clock.as_ref());

        // Deterministic artifact identity: network, kind, source set.
        let mut id_parts: Vec<String> = vec![
            self.network.as_str().to_owned(),
            options.kind.as_str().to_owned(),
        ];
        id_parts.extend(record_ids.iter().map(|id| id.as_str().to_owned()));
        let id_refs: Vec<&str> = id_parts.iter().map(String::as_str).collect();
        let evidence_id = EvidenceId::derive(&id_refs);

        let provenance = EvidenceProvenance::new(
            record_ids,
            source_events,
            self.parser.clone(),
            self.generator_version.clone(),
        )
        .map_err(EvidenceError::from_core)?;

        let mut artifact = EvidenceArtifact::new(
            evidence_id.clone(),
            options.kind,
            provenance,
            now,
            Some(options.generated_by.clone()),
        );

        // Content digest over the artifact's canonical bytes (integrity
        // slots excluded); the manifest slot is attached after hashing.
        let digest = hash_bytes(&artifact.canonical_bytes().map_err(EvidenceError::from_core)?);
        artifact = artifact.with_digest(digest);

        // Ledger-bounded manifest range when every source record names a
        // ledger; otherwise the range is left open.
        let ledgers: Vec<i64> = records
            .iter()
            .filter_map(|r| r.event.order.ledger_sequence)
            .collect();
        let (from, to) = if ledgers.len() == records.len() && !ledgers.is_empty() {
            let min = *ledgers.iter().min().unwrap();
            let max = *ledgers.iter().max().unwrap();
            (Some(min), Some(max))
        } else {
            (None, None)
        };

        let core_manifest = build_manifest(
            &records,
            &ManifestOptions::new(from, to, self.generator_version.as_str())
                .map_err(EvidenceError::from_integrity)?,
            now,
        )
        .map_err(EvidenceError::from_integrity)?;

        let manifest = EvidenceManifest::from_integrity_manifest(
            core_manifest,
            evidence_id.clone(),
            self.parser.clone(),
            self.network.clone(),
        )?;
        artifact = artifact.with_manifest(manifest.manifest_id().clone());

        // The trail attests to its own evidence production.
        record_generation(
            &EvidenceLifecycle {
                network: self.network.clone(),
                source: self.source.clone(),
                parser: self.parser.clone(),
                evidence: evidence_id,
                kind: options.kind,
                record_count: records.len() as u64,
                manifest: Some(manifest.manifest_id().clone()),
                digest: artifact.digest().cloned(),
            },
            self.clock.as_ref(),
            audit,
        )?;

        EvidencePackage::new(artifact, manifest)
    }

    /// Authorizes `actor` for evidence generation at this service's
    /// network scope.
    fn require(&self, actor: &AuditorId) -> EvidenceResult<()> {
        let scope = AccessScope::Network(self.network.clone());
        let decision = self
            .authorizer
            .authorize(actor, AccessAction::GenerateEvidence, &scope)
            .map_err(|e| EvidenceError::Internal(format!("authorizer failure: {e}")))?;
        if decision.allowed() {
            Ok(())
        } else {
            let why = decision.reason().unwrap_or(reason::ACTION_DENIED);
            Err(EvidenceError::NotAuthorized(
                actor.as_str().to_owned(),
                format!("cannot generate evidence: {why}"),
            ))
        }
    }

    /// Refuses to build over records whose stored integrity does not
    /// verify: an altered source must not become evidence.
    ///
    /// The pipeline seals history at *verification* time, so stored
    /// records may legitimately carry no integrity block. A record with a
    /// stored block must still match its body (a mismatch means it was
    /// altered after sealing); a record without one is accepted and its
    /// digest is recomputed and captured in the manifest at generation
    /// time, so later alteration is detectable through the manifest
    /// either way.
    fn require_intact(&self, records: &[safeguard_audit_core::AuditRecord]) -> EvidenceResult<()> {
        for record in records {
            let Some(integrity) = &record.integrity else {
                continue;
            };
            let recomputed =
                record_digest(record).map_err(EvidenceError::from_integrity)?;
            if recomputed != integrity.digest {
                return Err(EvidenceError::TamperedSource(format!(
                    "record {} carries a stored digest that no longer matches its body",
                    record.record_id
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use safeguard_audit_authorization::{Credential, Grant, Registry};
    use safeguard_audit_core::{
        AuditEvent, AuditRecord, AuditorRole, EventKind, EventProvenance, FixedClock,
        OriginKind,
    };
    use safeguard_audit_integrity::seal_standalone;
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::EventStore;

    fn net() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn parser() -> VersionLabel {
        VersionLabel::new("1.0.0").unwrap()
    }

    fn generator() -> VersionLabel {
        VersionLabel::new("0.3.0").unwrap()
    }

    fn auditor(name: &str) -> AuditorId {
        AuditorId::derive(&[name])
    }

    pub(crate) fn authorizer(role: AuditorRole, actor: &AuditorId) -> Authorizer {
        let mut registry = Registry::new();
        registry
            .register(
                Grant::new(actor.clone(), role)
                    .with_scope(AccessScope::Network(net()))
                    .with_credential(Credential::new(
                        actor.clone(),
                        "material",
                        Timestamp::from_unix_seconds(9_999_999_999),
                    )),
            )
            .unwrap();
        Authorizer::new(registry, FixedClock::at(Timestamp::from_unix_seconds(100)))
    }

    fn record(seed: &str, ledger: Option<i64>) -> AuditRecord {
        let provenance =
            EventProvenance::new(OriginKind::OnChain, "soroban", parser()).unwrap();
        let mut event = AuditEvent::new(
            safeguard_audit_core::EventId::derive(&[seed]),
            EventKind::TransferDenied,
            net(),
            provenance,
        );
        event.order.ledger_sequence = ledger;
        seal_standalone(
            &AuditRecord::from_event_classified(
                event,
                safeguard_audit_core::DataClassification::Confidential,
                &FixedClock::at(Timestamp::from_unix_seconds(100)),
            )
            .unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn seeded_store(seeds: &[&str]) -> MemoryEventStore {
        let mut store = MemoryEventStore::new();
        for (i, seed) in seeds.iter().enumerate() {
            store
                .insert(record(seed, Some(100 + i as i64)))
                .unwrap();
        }
        store
    }

    fn builder(authorizer: Authorizer) -> EvidenceBuilder {
        EvidenceBuilder::new(
            net(),
            crate::SOURCE_LABEL,
            parser(),
            generator(),
            FixedClock::at(Timestamp::from_unix_seconds(200)),
            authorizer,
        )
    }

    fn options(kind: EvidenceKind, ids: Vec<RecordId>, actor: &AuditorId) -> EvidenceBuildOptions {
        EvidenceBuildOptions::new(kind, ids, actor.clone()).unwrap()
    }

    fn ids(store: &MemoryEventStore, count: usize) -> Vec<RecordId> {
        store
            .query(
                &safeguard_audit_storage::AuditQuery::builder().build().unwrap(),
                &safeguard_audit_core::PageRequest::new(count).unwrap(),
            )
            .unwrap()
            .items()
            .iter()
            .map(|r| r.record_id.clone())
            .collect()
    }

    #[test]
    fn building_over_verified_records_seals_artifact_and_manifest() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &aud));
        let mut store = seeded_store(&["a", "b"]);
        let opts = options(EvidenceKind::TransactionEvidence, ids(&store, 2), &aud);
        let package = b.build(&mut store, &opts).unwrap();
        assert_eq!(package.artifact().kind(), EvidenceKind::TransactionEvidence);
        assert!(package.artifact().digest().is_some());
        assert_eq!(package.manifest().record_count(), 2);
        assert_eq!(package.manifest().from_ledger(), Some(100));
        assert_eq!(package.manifest().to_ledger(), Some(101));
        // The generation is recorded in the audit store.
        let page = store
            .query(
                &safeguard_audit_storage::AuditQuery::builder().build().unwrap(),
                &safeguard_audit_core::PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let kinds: Vec<EventKind> = page.items().iter().map(|r| r.kind()).collect();
        assert!(kinds.contains(&EventKind::EvidenceGenerated));
    }

    #[test]
    fn building_is_deterministic_regardless_of_id_order() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &aud));
        let store = seeded_store(&["a", "b", "c"]);

        let mut rev = store.clone();
        let mut ids_rev = ids(&store, 3);
        ids_rev.reverse();
        let opts_rev = options(EvidenceKind::EnforcementEvidence, ids_rev, &aud);

        let mut fwd = store.clone();
        let opts_fwd = options(EvidenceKind::EnforcementEvidence, ids(&fwd, 3), &aud);

        let p_rev = b.build(&mut rev, &opts_rev).unwrap();
        let p_fwd = b.build(&mut fwd, &opts_fwd).unwrap();
        assert_eq!(p_rev, p_fwd);
        assert_eq!(
            p_rev.artifact().evidence_id(),
            p_fwd.artifact().evidence_id()
        );
    }

    #[test]
    fn missing_records_are_rejected() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &aud));
        let mut store = seeded_store(&["a"]);
        let mut opts = options(EvidenceKind::TransactionEvidence, ids(&store, 1), &aud);
        opts.record_ids.push(RecordId::derive(&["nope"]));
        let err = b.build(&mut store, &opts).unwrap_err();
        assert!(matches!(err, EvidenceError::RecordMissing(_)));
    }

    #[test]
    fn tampered_sources_are_refused() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &aud));
        // The store is append-only, so the realistic corruption is a stored
        // record whose integrity block no longer matches its body (as a
        // tampered store would present it). The gate must refuse it.
        let mut corrupted = record("a", Some(100));
        let wrong = corrupted
            .integrity
            .as_mut()
            .expect("sealed record carries integrity")
            .digest
            .clone();
        corrupted.integrity.as_mut().unwrap().digest =
            safeguard_audit_core::IntegrityDigest::sha256("ff".repeat(32)).unwrap();
        assert_ne!(wrong, corrupted.integrity.as_ref().unwrap().digest);
        let err = b.require_intact(&[corrupted]).unwrap_err();
        assert!(matches!(err, EvidenceError::TamperedSource(_)));
    }

    #[test]
    fn unsealed_records_build_with_their_digest_captured_in_the_manifest() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &aud));
        // The pipeline seals history at verification time, so stored
        // records may carry no integrity block. Such records are accepted;
        // the manifest recomputes and captures each record's digest from
        // its body, so later alteration is still detectable.
        let mut store = MemoryEventStore::new();
        let unsealed = AuditRecord::from_event_classified(
            AuditEvent::new(
                safeguard_audit_core::EventId::derive(&["u"]),
                EventKind::TransferDenied,
                net(),
                EventProvenance::new(OriginKind::OnChain, "soroban", parser()).unwrap(),
            ),
            safeguard_audit_core::DataClassification::Confidential,
            &FixedClock::at(Timestamp::from_unix_seconds(100)),
        )
        .unwrap();
        store.insert(unsealed).unwrap();
        let opts = options(EvidenceKind::TransactionEvidence, ids(&store, 1), &aud);
        let package = b.build(&mut store, &opts).unwrap();
        assert_eq!(package.manifest().record_count(), 1);
        // The manifest entry digest equals a fresh recomputation from the
        // stored body - the captured state, not a copied stored value.
        let stored = store
            .query(
                &safeguard_audit_storage::AuditQuery::builder().build().unwrap(),
                &safeguard_audit_core::PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let record = stored
            .items()
            .iter()
            .find(|r| r.kind() == EventKind::TransferDenied)
            .unwrap();
        assert_eq!(
            package.manifest().entries()[0].digest(),
            &record_digest(record).unwrap()
        );
    }

    #[test]
    fn unauthorized_actors_are_denied() {
        let aud = auditor("aud-1");
        let b = builder(authorizer(safeguard_audit_core::AuditorRole::ReadOnlyReviewer, &aud));
        let mut store = seeded_store(&["a"]);
        let opts = options(EvidenceKind::TransactionEvidence, ids(&store, 1), &aud);
        let err = b.build(&mut store, &opts).unwrap_err();
        assert!(matches!(err, EvidenceError::NotAuthorized(_, _)));
    }

    #[test]
    fn empty_source_sets_are_rejected() {
        let aud = auditor("aud-1");
        assert!(matches!(
            EvidenceBuildOptions::new(EvidenceKind::TransactionEvidence, vec![], aud),
            Err(EvidenceError::NoSourceRecords)
        ));
    }
}