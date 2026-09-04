# Reporting

Reporting turns audit history into reproducible, bounded summaries.
A compliance officer who needs to answer "what happened over this
range?" gets a report that names its own query, counts only what it
covers, rows only public transaction references, and carries a digest —
so the answer can be regenerated, verified, and shown to have come from
the records.

## Where the pieces live

| Concern | Location |
|---|---|
| Domain models (`Report`, `ReportRequest`, `ReportQuery`, `ReportKind`, `ReportSummary`, `GeneratorVersions`) | `audit-core` — `report.rs` |
| Generation event (`ReportLifecycle`) | `audit-events` — `report.rs` |
| Services (`ReportService`, `to_audit_query`) | `reporting` crate (`crates/reporting`) |
| Hashing primitives (`hash_bytes`) | `integrity` crate (`crates/integrity`) |

The split mirrors the rest of the repository: `audit-core` defines *what
a report is*; the `reporting` crate runs the *machinery*; `audit-events`
defines the generation event the trail records.

## What a report is

A report is four things bound together:

* **kind** — one of the eleven `ReportKind`s (compliance activity,
  approved/denied/flagged transactions, enforcement activity, account or
  token activity, investigations, incidents, evidence summaries,
  integrity verification);
* **query** — the exact `ReportQuery` the report was generated from,
  captured *inside* the report as the reproducibility record: time
  range, network, tokens, event kinds, outcome, account, and a
  classification ceiling;
* **summary** — count-only tables (total, by outcome, by kind, by
  reason) over the covered records — never rows of protected data;
* **body** — public `TransactionReference` rows (network + hash) for the
  covered records that name a transaction.

Plus the attribution and version metadata: generated-at, generated-by,
schema version, parser and generator versions, a deterministic report
id, and a content digest over the canonical report bytes.

## The generation pipeline

```text
request ──► authorize ──► validate ──► map to query ──► scan ──► filter ──► seal
 (kind+query)   │            │            │            (paged)   │          │
                 │            └ incoherent? refuse      │         ├─► classification ceiling
                 └ denied? refuse                      └─► multi-token membership
                                                                   │
                                                                   ▼
                                               summary + public-reference rows
                                                                   │
                                                                   ▼
                                  deterministic id (network+kind+query) + digest
                                                                   │
                                                                   ▼
                                  report-generated event recorded on the trail
```

1. **Authorize.** Generating reports requires the `generate-report`
   action at the service's network scope (`SeniorAuditor`,
   `ComplianceOfficer`, or `Administrator` by default). A denial is an
   error, never a silent pass.
2. **Validate.** The request's query must map coherently onto the
   store's query model — including rejecting inverted time ranges from
   the wire (serde bypasses `TimeRange::new`'s constructor validation)
   and ceilings that would protect nothing.
3. **Scan.** The matching range is read in deterministic history order,
   page by page, bounded by pagination at the interface.
4. **Filter.** The classification ceiling excludes records at or above
   the query's sensitivity ceiling — a report never leaks protected
   data. Multi-token requests keep only the named tokens.
5. **Seal.** The summary counts and public rows are assembled, the
   report id derives deterministically from network + kind + the
   canonical query, and the content digest covers the canonical report
   bytes (digest slot excluded).
6. **Record.** The generation lands in the audit store as a derived
   `report-generated` event carrying the report id, kind, covered-record
   count, and digest — the trail attests to its own reporting.

## Reproducibility

Because the report captures its own query, the same store and the same
request reproduce the same report: same id (network + kind + canonical
query), same digest, same content. Under an injected fixed clock, two
generations are byte-identical.

## Boundaries

* Reports are *bounded summaries*: count tables plus public transaction
  references. The classification ceiling is enforced at generation time;
  protected record content is never copied into a report body.
* The reporting crate generates reports. It does not decide policy,
  enforce transfers, or grant access — authorization decisions come from
  the authorization crate.