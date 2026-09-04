# Privacy

Privacy is a first-class boundary in the audit layer: the system can see
more than it is allowed to repeat. Confidential Token operations carry
financial meaning, so the repository separates *what is recorded* (public
metadata and references, by construction) from *what is disclosed* (only
what a reader's grants cover) and never lets a protected value reach a
reader because it happened to be stored nearby.

The rule in one sentence: **a value is disclosed only when its
classification is strictly below the reader's disclosure ceiling, and
redaction replaces, never reveals.**

## The classification vocabulary

Every value that can enter a record is classified. `audit-core` owns the
vocabulary (`DataClassification`, the per-field `FieldClassifications`
table); nothing below it decides what *should* be secret.

| Level | Meaning | Examples |
|---|---|---|
| `public` | Ledger-visible metadata | addresses, hashes, ledger sequences, event-kind labels |
| `operational` | Internal, non-sensitive metadata | parser versions, hook ids, correlation labels, record counts |
| `confidential` | Non-public but non-critical | which policy class matched, an investigation summary |
| `restricted` | Protected, needs an explicit scope | policy decision internals, investigation context |
| `highly-restricted` | Private financial data | decrypted balances, transfer amounts, view-key material |

Every `AuditRecord` carries an overall `classification` and a per-field
`redactions` table keyed by detail name. Values live in the envelope's
`details` map — short, validated strings. References (transactions,
accounts, tokens, decisions) are public metadata by design; amounts and
ciphertexts are not recorded here in the first place.

## Where the pieces live

| Concern | Location |
|---|---|
| Classification vocabulary (`DataClassification`, `FieldClassifications`) | `audit-core` — `privacy.rs` |
| Decryption boundary (`DecryptionProvider`, request/response) | `audit-core` — `decryption.rs` |
| Declared detail-key sensitivity for derived events (`detail_policy`) | `audit-events` — `classify.rs` |
| Enforcement (`redact_details`, `RecordDisclosure`, `disclosure_ceiling`) | `privacy` crate (`crates/privacy`) |
| Scope containment (`covers_classification`) | `authorization` — `scopes.rs` |

## Redaction

`privacy::redact_details` produces the view a reader may see: every
detail key survives, but a value whose classification is at or above the
ceiling is replaced wholesale with a stable `[redacted]` marker — never
truncated, blurred, or partially revealed. Two properties matter:

* **Determinism** — the same record, table, and ceiling always produce
  the same view and the same list of withheld keys, so disclosed output
  can be reproduced and verified.
* **No silent omission** — the marker and the `redacted_keys` proof list
  show *what* was withheld; consumers interpret redaction through that
  list, never by scanning values for the marker.

Fields the table does not name inherit the record's own classification.
An empty `redactions` table therefore still protects at the record level
instead of silently disclosing.

## Disclosure ceilings come from the authorizer

A ceiling is only safe when it discloses exactly what the reader is
granted. Classification scopes are directional: a more sensitive grant
covers less sensitive data (`authorization::scopes`). The privacy crate
maps granted scopes onto the disclosure ceiling:

* no `All` and no `Classification` grant → `Public` (nothing classified
  is disclosed);
* a `Classification(g)` grant → one level above `g` (fields up to and
  including `g` pass; more sensitive fields redact);
* `All`, or a `HighlyRestricted` grant → `None` (every classification is
  covered; no classification redaction applies).

The bump is deliberate: the reporting service's record-level rule
excludes records *at or above* its ceiling, so the field-level ceiling
must sit one level above the most sensitive covered classification for
disclosure to match access coverage exactly. Integration tests pin this
equivalence against the real `covers_classification` for every grant and
field combination.

`RecordDisclosure::disclose(record, ceiling)` is the shape a reader may
receive: public identifiers pass through, details are disclosed or
redacted per the ceiling, and the withheld keys are listed. It is
serializable so exporters can emit it directly, and deterministic.

## Field policies on real records

`audit-events` declares the sensitivity of every detail key its derived
events write (`classify.rs`). The record paths that actually write
history — report generation, evidence generation, and investigation
lifecycle steps — populate each record's `redactions` table from that
declaration before inserting it. Practical effect: a `report-generated`
record is `Confidential`, and without the declaration its operational
attribution (report id, kind, record count, digest) would be redacted at
a confidential ceiling; with it, those declared fields disclose while
anything undeclared — and the investigation `summary`, declared
confidential — stays protected. Nothing is ever declared `restricted` or
higher in the registry; genuinely protected values keep the conservative
undeclared default.

## The decryption boundary

`audit-core::decryption` defines the door through which a legitimate
view-key integration can decrypt *permitted* data — it does not invent
the cryptography. A `DecryptionRequest` names the requester, a bounded
target, a purpose, and exactly the fields requested; a provider must
authorize before decrypting and return only the granted subset; the
response values are transient by contract, and the audit layer records
the attributable fact of access — never the decrypted data. No provider
is implemented here; that waits for the verified upstream Confidential
Token architecture.

## Guarantees and honest limits

* Protected values are replaced, never leaked, truncated, or guessed —
  a serialized disclosed projection is tested to never contain the
  underlying value.
* Disclosure ceilings agree with the authorizer as implemented, not just
  by design (cross-crate tests).
* The privacy crate is the enforcement *capability*; today it is wired
  into the derived-event record paths and available to export and
  display surfaces.
* Nothing here decrypts, un-redacts, or decides policy. Classifying data
  as `public` because a registry says so is a *declaration*; data that
  was never declared stays protected by default.
