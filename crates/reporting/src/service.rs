//! The report service: turning an authorized request into a sealed,
//! reproducible report.
//!
//! The pipeline is deliberately conservative. Before anything is sealed
//! it must, in order:
//!
//! 1. **authorize** — the requester needs the `generate-report` action at
//!    the service's network scope; a denial is an error, never a silent
//!    pass;
//! 2. **validate** — the request's query must map coherently onto the
//!    store's query model;
//! 3. **scan** — the matching range is read in deterministic history
//!    order, page by page;
//! 4. **filter** — the classification ceiling excludes rows at or above
//!    the query's sensitivity ceiling (reports never leak protected
//!    data), and multi-token requests keep only the named tokens;
//! 5. **seal** — summary counts and public transaction-reference rows are
//!    assembled, the report id derives deterministically from network +
//!    kind + canonical query, and the content digest is computed over the
//!    report's canonical bytes.
//!
//! The generation is then recorded as a derived `report-generated` event
//! in the audit store, so the trail attests to its own reporting. The
//! same store and the same request always produce the same report.

use std::collections::BTreeMap;

use safeguard_audit_authorization::{reason, Authorizer};
use safeguard_audit_core::report::REPORT_SCHEMA_VERSION;
use safeguard_audit_core::{
    AccessAction, AccessScope, AuditRecord, AuditorId, Clock, DataClassification, DecisionResult,
    EventKind, GeneratorVersions, NetworkId, PageRequest, Report, ReportId, ReportKind,
    ReportRequest, ReportSummary, Timestamp, VersionLabel,
};
use safeguard_audit_events::ReportLifecycle;
use safeguard_audit_integrity::hash_bytes;
use safeguard_audit_storage::EventStore;

use crate::errors::{ReportingError, ReportingResult};
use crate::events::record_report;
use crate::query::to_audit_query;

/// The report generation service.
pub struct ReportService {
    network: NetworkId,
    source: String,
    parser: VersionLabel,
    generator_version: VersionLabel,
    clock: Box<dyn Clock>,
    authorizer: Authorizer,
    /// Page size for scanning the store (report scans are bounded by
    /// pagination at the interface, never unbounded collections).
    page_size: usize,
}

impl ReportService {
    /// Builds the service for `network`, stamping reports with `clock`
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
            page_size: 100,
        }
    }

    /// The network this service operates on.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Generates a report for `request`.
    ///
    /// The report captures its own query (the reproducibility record);
    /// its id derives from network + kind + the canonical query, so
    /// re-running the same request reproduces the same report. The
    /// generation is recorded into `audit` as a derived
    /// `report-generated` event.
    pub fn generate(
        &self,
        audit: &mut dyn EventStore,
        request: &ReportRequest,
    ) -> ReportingResult<Report> {
        self.require(request.requested_by())?;
        self.validate_request(request)?;

        // Scan the matching range in deterministic history order.
        let audit_query = to_audit_query(request.query())
            .map_err(|e| ReportingError::InvalidRequest(e.to_string()))?;
        let records = self.scan(audit, &audit_query)?;

        // Privacy ceiling and multi-token membership cannot be expressed
        // as store filters; they are enforced here.
        let covered: Vec<&AuditRecord> = records
            .iter()
            .filter(|r| passes_filters(r, request))
            .collect();

        let now = Timestamp::now(self.clock.as_ref());
        let report_id = self.derive_report_id(request);

        let summary = summarize(&covered);
        let rows: Vec<_> = covered
            .iter()
            .filter_map(|r| r.event.transaction.clone())
            .collect();

        let versions = GeneratorVersions {
            report_schema: REPORT_SCHEMA_VERSION,
            parser_version: self.parser.clone(),
            generator_version: self.generator_version.clone(),
        };

        let mut report = Report::new(
            report_id.clone(),
            request.kind(),
            now,
            request.query().clone(),
            versions,
        )
        .with_generated_by(request.requested_by().clone())
        .with_rows(rows)
        .with_summary(summary);

        let digest = hash_bytes(&report.canonical_bytes().map_err(ReportingError::from_core)?);
        report = report.with_digest(digest);
        report
            .validate()
            .map_err(ReportingError::from_core)?;

        record_report(
            &ReportLifecycle {
                network: self.network.clone(),
                source: self.source.clone(),
                parser: self.parser.clone(),
                report: report_id,
                kind: request.kind(),
                record_count: report.summary().total_records,
                digest: report.digest().cloned(),
            },
            self.clock.as_ref(),
            audit,
        )?;

        Ok(report)
    }

    /// Authorizes `actor` for report generation at this service's network
    /// scope.
    fn require(&self, actor: &AuditorId) -> ReportingResult<()> {
        let scope = AccessScope::Network(self.network.clone());
        let decision = self
            .authorizer
            .authorize(actor, AccessAction::GenerateReport, &scope)
            .map_err(|e| ReportingError::Internal(format!("authorizer failure: {e}")))?;
        if decision.allowed() {
            Ok(())
        } else {
            let why = decision.reason().unwrap_or(reason::ACTION_DENIED);
            Err(ReportingError::NotAuthorized(
                actor.as_str().to_owned(),
                format!("cannot generate reports: {why}"),
            ))
        }
    }

    /// Validates the request: the kind must be generable and the query
    /// must be coherent.
    fn validate_request(&self, request: &ReportRequest) -> ReportingResult<()> {
        let supported = [
            ReportKind::ComplianceActivity,
            ReportKind::ApprovedTransactions,
            ReportKind::DeniedTransactions,
            ReportKind::FlaggedTransactions,
            ReportKind::EnforcementActivity,
            ReportKind::AccountActivity,
            ReportKind::TokenActivity,
            ReportKind::Investigations,
            ReportKind::Incidents,
            ReportKind::EvidenceSummary,
            ReportKind::IntegrityVerification,
        ];
        if !supported.contains(&request.kind()) {
            return Err(ReportingError::UnsupportedKind(request.kind()));
        }
        if let Some(ceiling) = request.query().classification_ceiling {
            if ceiling == DataClassification::Public || ceiling == DataClassification::Operational {
                return Err(ReportingError::InvalidRequest(format!(
                    "classification ceiling {ceiling} would not protect anything"
                )));
            }
        }
        Ok(())
    }

    /// Scans every page of the store matching `query`, in deterministic
    /// order.
    fn scan(
        &self,
        audit: &dyn EventStore,
        query: &safeguard_audit_storage::AuditQuery,
    ) -> ReportingResult<Vec<AuditRecord>> {
        let mut all = Vec::new();
        let mut cursor = None;
        loop {
            let request = PageRequest::with_cursor(self.page_size, cursor)
                .map_err(|e| ReportingError::InvalidRequest(e.to_string()))?;
            let page = audit
                .query(query, &request)
                .map_err(|e| ReportingError::Store(e.to_string()))?;
            let next = page.next_cursor().cloned();
            all.extend(page.into_items());
            if next.is_none() {
                return Ok(all);
            }
            cursor = next;
        }
    }

    /// Derives the deterministic report id from network + kind + the
    /// canonical query.
    fn derive_report_id(&self, request: &ReportRequest) -> ReportId {
        let canonical_query =
            safeguard_audit_core::serialization::canonical_json_string(request.query())
                .unwrap_or_else(|_| "unqueryable".to_owned());
        ReportId::derive(&[
            self.network.as_str(),
            request.kind().as_str(),
            &canonical_query,
        ])
    }
}

/// Whether a record survives the report's non-store filters: the
/// multi-token membership and the classification ceiling.
fn passes_filters(record: &AuditRecord, request: &ReportRequest) -> bool {
    let query = request.query();
    if !query.tokens.is_empty() {
        let Some(token) = &record.event.token else {
            return false;
        };
        if !query.tokens.contains(token) {
            return false;
        }
    }
    if let Some(ceiling) = query.classification_ceiling {
        if record.classification.is_at_least(ceiling) {
            return false;
        }
    }
    true
}

/// Assembles the count-only summary over the covered records.
fn summarize(records: &[&AuditRecord]) -> ReportSummary {
    let mut by_outcome: BTreeMap<DecisionResult, u64> = BTreeMap::new();
    let mut by_kind: BTreeMap<EventKind, u64> = BTreeMap::new();
    let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
    for record in records {
        let event = &record.event;
        if let Some(outcome) = event.outcome {
            *by_outcome.entry(outcome).or_default() += 1;
        }
        *by_kind.entry(event.kind).or_default() += 1;
        if let Some(reason) = &event.reason {
            *by_reason.entry(reason.as_str().to_owned()).or_default() += 1;
        }
    }
    ReportSummary {
        total_records: records.len() as u64,
        by_outcome,
        by_kind,
        by_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeguard_audit_authorization::{Credential, Grant, Registry};
    use safeguard_audit_core::{
        AccountReference, AuditEvent, EventProvenance, FixedClock, OriginKind, ReportQuery,
        TokenReference,
    };
    use safeguard_audit_memory_store::MemoryEventStore;
    use safeguard_audit_storage::InsertOutcome;

    fn net() -> NetworkId {
        NetworkId::new(NetworkId::TESTNET).unwrap()
    }

    fn clock() -> FixedClock {
        FixedClock::at(Timestamp::from_unix_seconds(1_700_000_000))
    }

    fn parser() -> VersionLabel {
        VersionLabel::new("1.0.0").unwrap()
    }

    fn generator() -> VersionLabel {
        VersionLabel::new("0.5.0").unwrap()
    }

    fn auditor(name: &str) -> AuditorId {
        AuditorId::derive(&[name])
    }

    fn authorizer(role: safeguard_audit_core::AuditorRole, actor: &AuditorId) -> Authorizer {
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
        Authorizer::new(registry, clock())
    }

    fn service(authorizer: Authorizer) -> ReportService {
        ReportService::new(
            net(),
            crate::SOURCE_LABEL,
            parser(),
            generator(),
            clock(),
            authorizer,
        )
    }

    fn seeded(seeds: &[(&str, EventKind, DecisionResult, Option<&str>, Timestamp)]) -> MemoryEventStore {
        let mut store = MemoryEventStore::new();
        for (seed, kind, outcome, reason, at) in seeds {
            let mut event = AuditEvent::new(
                safeguard_audit_core::EventId::derive(&[seed]),
                *kind,
                net(),
                EventProvenance::new(OriginKind::OnChain, "soroban", parser()).unwrap(),
            );
            event.outcome = Some(*outcome);
            event.observed_at = Some(*at);
            if let Some(reason) = reason {
                event.reason = Some(safeguard_audit_core::ReasonCode::new(reason).unwrap());
            }
            event.transaction = Some(safeguard_audit_core::TransactionReference::new(
                net(),
                safeguard_audit_core::TransactionHash::new(&format!("{seed:0<64}")).unwrap(),
            ));
            event.token = Some(TokenReference::for_contract(
                net(),
                safeguard_audit_core::ContractId::new(&format!("C{}", "A".repeat(55))).unwrap(),
            ));
            event.actor = Some(AccountReference::new(
                net(),
                safeguard_audit_core::AccountId::new(
                    "GACCOUNT12345678901234567890123456789012345678901234",
                )
                .unwrap(),
            ));
            let record = AuditRecord::from_event_classified(
                event,
                DataClassification::Confidential,
                &clock(),
            )
            .unwrap();
            assert_eq!(store.insert(record), Ok(InsertOutcome::Inserted));
        }
        store
    }

    fn request(kind: ReportKind, query: ReportQuery, actor: &AuditorId) -> ReportRequest {
        ReportRequest::new(
            kind,
            query,
            actor.clone(),
            Timestamp::from_unix_seconds(1_699_999_999),
        )
    }

    #[test]
    fn denied_transactions_report_summarizes_and_rows_only_denials() {
        let actor = auditor("senior-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor));
        let mut store = seeded(&[
            ("a", EventKind::TransferDenied, DecisionResult::Denied, Some("POLICY_DENIED"), Timestamp::from_unix_seconds(100)),
            ("b", EventKind::TransferAuthorized, DecisionResult::Allowed, None, Timestamp::from_unix_seconds(200)),
            ("c", EventKind::TransferDenied, DecisionResult::Denied, Some("POLICY_DENIED"), Timestamp::from_unix_seconds(300)),
        ]);
        let req = request(
            ReportKind::DeniedTransactions,
            ReportQuery::with_outcome(DecisionResult::Denied),
            &actor,
        );
        let report = svc.generate(&mut store, &req).unwrap();
        assert_eq!(report.summary().total_records, 2);
        assert_eq!(report.summary().by_outcome[&DecisionResult::Denied], 2);
        assert_eq!(report.summary().by_kind[&EventKind::TransferDenied], 2);
        assert_eq!(report.summary().by_reason["POLICY_DENIED"], 2);
        assert_eq!(report.rows().len(), 2);
        assert!(report.digest().is_some());
    }

    #[test]
    fn the_generation_is_recorded_on_the_trail() {
        let actor = auditor("senior-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor));
        let mut store = seeded(&[
            ("a", EventKind::TransferDenied, DecisionResult::Denied, None, Timestamp::from_unix_seconds(100)),
        ]);
        let req = request(ReportKind::DeniedTransactions, ReportQuery::with_outcome(DecisionResult::Denied), &actor);
        svc.generate(&mut store, &req).unwrap();
        let page = store
            .query(
                &safeguard_audit_storage::AuditQuery::builder().build().unwrap(),
                &PageRequest::new(10).unwrap(),
            )
            .unwrap();
        let kinds: Vec<EventKind> = page.items().iter().map(|r| r.event.kind).collect();
        assert!(kinds.contains(&EventKind::ReportGenerated));
    }

    #[test]
    fn generation_is_reproducible_under_a_fixed_clock() {
        let actor = auditor("senior-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor));
        let store = seeded(&[
            ("a", EventKind::TransferDenied, DecisionResult::Denied, None, Timestamp::from_unix_seconds(100)),
        ]);
        let mut s1 = store.clone();
        let mut s2 = store.clone();
        let req = request(ReportKind::DeniedTransactions, ReportQuery::with_outcome(DecisionResult::Denied), &actor);
        let first = svc.generate(&mut s1, &req).unwrap();
        let second = svc.generate(&mut s2, &req).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.report_id(), second.report_id());
    }

    #[test]
    fn classification_ceiling_excludes_protected_records() {
        let actor = auditor("senior-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor));
        let mut store = MemoryEventStore::new();
        let mut protected = AuditRecord::from_event_classified(
            AuditEvent::new(
                safeguard_audit_core::EventId::derive(&["p"]),
                EventKind::TransferDenied,
                net(),
                EventProvenance::new(OriginKind::OnChain, "soroban", parser()).unwrap(),
            ),
            DataClassification::Restricted,
            &clock(),
        )
        .unwrap();
        protected.event.outcome = Some(DecisionResult::Denied);
        store.insert(protected).unwrap();
        let req = request(
            ReportKind::DeniedTransactions,
            ReportQuery {
                classification_ceiling: Some(DataClassification::Confidential),
                ..ReportQuery::with_outcome(DecisionResult::Denied)
            },
            &actor,
        );
        let report = svc.generate(&mut store, &req).unwrap();
        assert_eq!(report.summary().total_records, 0, "restricted records are excluded at a confidential ceiling");
    }

    #[test]
    fn unauthorized_actors_are_denied() {
        let actor = auditor("reviewer-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::ReadOnlyReviewer, &actor));
        let mut store = MemoryEventStore::new();
        let req = request(ReportKind::ComplianceActivity, ReportQuery::all(), &actor);
        let err = svc.generate(&mut store, &req).unwrap_err();
        assert!(matches!(err, ReportingError::NotAuthorized(..)));
    }

    #[test]
    fn nonsensical_ceilings_are_rejected() {
        let actor = auditor("senior-1");
        let svc = service(authorizer(safeguard_audit_core::AuditorRole::SeniorAuditor, &actor));
        let mut store = MemoryEventStore::new();
        let req = request(
            ReportKind::ComplianceActivity,
            ReportQuery {
                classification_ceiling: Some(DataClassification::Public),
                ..ReportQuery::all()
            },
            &actor,
        );
        assert!(matches!(
            svc.generate(&mut store, &req),
            Err(ReportingError::InvalidRequest(_))
        ));
    }
}