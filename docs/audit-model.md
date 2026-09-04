# Audit model

The persisted unit of history is the **audit record**. Everything else —
evidence, investigations, reports — is derived from records.

## The record

```text
AuditRecord
├── record_id        deterministic: sha256(canonical bytes of the event), prefix rec_
├── event            the normalized AuditEvent (see docs/event-model.md)
├── recorded_at      when THIS record was created (never part of identity)
├── schema_version   record schema (bump = breaking change, documented)
├── classification   most sensitive classification held by the content
├── redactions       field → classification table (drives redaction/export)
├── supersedes / correction_reason   present only on record-corrected records
└── integrity        digest + prev_digest + chained flag, filled on commit
```

## Deterministic identity

`record_id` derives from the canonical serialization of the embedded event,
which itself derives from stable *source* identifiers (network, contract,
transaction, operation, event index, kind). Consequences:

* **Duplicate ingestion is idempotent.** Re-recording the same source event
  derives the same record id, and the store reports a duplicate instead of
  writing twice.
* **Replay is deterministic.** Reconstructing history from the same sources
  reproduces the same records.
* **Arrival time is never identity.** `recorded_at` differs between two
  ingestions; `record_id` does not.

## Append-only semantics

There is no update or delete path — the `EventStore` trait has none, and
records carry no mutation. When an interpretation needs correcting:

1. The original record is **preserved unmodified**.
2. A new `record-corrected` record is appended with `supersedes` naming the
   original and a `correction_reason`.
3. The integrity chain (when chaining is enabled) covers both.

History is preserved, never rewritten.

## What a record may hold

Records carry **public metadata and references**: addresses, hashes, ledger
sequences, version labels, reason codes, policy/enforcement references, and
short validated detail strings. A record never carries amounts, balances,
ciphertexts, or decrypted private data — those exist only behind an
explicit, authorized, scoped, and itself-audited decryption flow, and are
never persisted by default. The classification and `redactions` table make
the treatment of every field explicit and machine-checkable.

## Records versus events

| | Raw event | Normalized `AuditEvent` | `AuditRecord` |
| --- | --- | --- | --- |
| Shape | provider-specific | one envelope, 18 kinds | event + bookkeeping |
| Provenance | implicit | explicit (observed/derived) | carried on the event |
| Identity | source ids | deterministic `evt_` id | deterministic `rec_` id |
| Stored? | no | transient | **yes, append-only** |

The normalized event is the thing ingestion validates and dedups; the
record is the thing storage persists, integrity chains, and queries serve.

## Versioning

Record and event schema versions are explicit integers on every value;
readers either understand a version or report a mismatch — they never
silently reinterpret. Bumping a schema is a deliberate change that moves
the `schemas/` documents in the same commit and is recorded in
`CHANGELOG.md`.
