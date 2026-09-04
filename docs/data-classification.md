# Data classification

Classification is the shared vocabulary for "how sensitive is this
piece of audit data?" — used by redaction, access control, reporting
ceilings, safe serialization, and safe logging. It is a *policy*
vocabulary; the privacy crate and the authorizer apply it, and nothing
decides what *should* be secret by accident.

## The five levels

| Level | Who may see it | What it is for |
|---|---|---|
| `public` | Anyone with network access | Ledger-visible metadata: addresses, hashes, ledger sequences, event-kind labels |
| `operational` | Internal operators | Non-sensitive operation metadata: parser/hook versions, correlation labels, record counts |
| `confidential` | Authorized auditors (default record level) | Non-public details that are still not critical: which policy class matched, investigation summaries |
| `restricted` | Auditors with an explicit classification scope | Protected data: policy decision internals, investigation context |
| `highly-restricted` | Explicit + dedicated decryption authorization | Private financial data: decrypted balances, transfer amounts, view-key material — transient when present at all |

Levels are totally ordered: `public < operational < confidential <
restricted < highly-restricted`. "At least as sensitive as" is an
ordering comparison.

## Where data actually lives

The audit envelope is *designed* to contain only public metadata and
references. Concretely:

| Model / field | Classification | Why |
|---|---|---|
| `TransactionReference`, `OperationReference`, `AccountReference`, `TokenReference`, `LedgerReference`, `ContractReference`, network labels | `public` | Ledger-visible identifiers |
| `EventKind` labels | `public` | Event names are vocabulary, not secrets |
| `IntegrityDigest` values | `public` | Hashes of canonical content |
| Provenance labels, parser/hook/source versions, reason codes | `operational` | Internal but non-sensitive |
| Record counts, ids of generated reports/evidence/cases/actors | `operational` | Internal correlation labels |
| A record's overall `classification` | set at record creation | Most sensitive class of its content; `Confidential` by default |
| Investigation `summary` (closure reason, notes) | `confidential` | Short prose that can carry context |
| Policy decision internals, investigation context | `restricted` | Protected — requires the scope |
| Decrypted balances, transfer amounts, ciphertexts, view-key material | `highly-restricted` | Never recorded by this repository; transient behind the decryption boundary |

References are references: the system never duplicates token state,
policy bodies, or balances — only enough identity to point at the
authoritative source. Protected *values* (amounts, ciphertexts) have no
home on the envelope.

## Record-level rules

* Every `AuditRecord` carries one `classification` and a per-field
  `redactions` table. The record's classification is the default for
  anything its table does not name.
* Derived-event recorders stamp the table from the declared detail-key
  policy (`audit-events::classify`); observed events carry no details
  and no declarations, and protect at the record level.
* Disclosure redacts a detail value when its classification is *at or
  above* the ceiling (the same `is_at_least` rule the reporting service
  applies to whole records). A field-level ceiling sits one level above
  the most sensitive covered classification so disclosure matches access
  coverage exactly.
* `audit-events` never declares a key `restricted` or higher. Genuinely
  protected values, if they ever appear, stay undeclared and inherit the
  record's own classification — they cannot be laundered into routine
  metadata by a declaration.

## Access linkage

A record's classification maps to the scope that must be granted:
`Classification(Confidential)` data requires a grant that covers
`Confidential` or higher (grants are directional — a more sensitive
grant covers less sensitive data, never the reverse). `All` covers
everything, administrators only, by policy. Protected-data access is
itself recorded as an `audit-access` entry with full attribution.

## Reporting and export

Reports carry a `classification_ceiling` in their query: records at or
above the ceiling are excluded from the report body, and ceilings that
would protect nothing are rejected. Report bodies carry count tables and
public transaction references only — never detail values. When full
records must leave the system (evidence, export, display), they leave as
`RecordDisclosure` projections at the requester's ceiling, never as raw
records with their details.

## Logging and errors

* Never log anything `restricted` or `highly-restricted` — and no
  balances, ciphertexts, view keys, credentials, or decrypted data at
  any level.
* Error messages carry identifiers and short descriptions only; when a
  detail would expose protected data, the variant carries a stable code
  instead.
* Fixtures and test vectors contain synthetic data only; nothing in this
  repository stands in for a real confidential balance.

## Changing a classification

Classification changes are data-classification decisions, not code
touches. The audit trail is append-only: an interpretation that needs
correcting is recorded as a `record-corrected` event that supersedes the
original, never by silently mutating history.
