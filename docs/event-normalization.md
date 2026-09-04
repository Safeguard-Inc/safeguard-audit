# Event normalization

Normalization is the stage that turns raw, provider-shaped payloads into
the provider-neutral [`AuditEvent`] envelope everything downstream
consumes. It lives in the `safeguard-audit-normalizer` crate
(`crates/event-normalizer`) and is deliberately a *pure function*: given
the same raw payload, scheme label, and configuration it always produces
the same envelope — the property that makes deduplication and replay
sound.

## Pipeline

```text
RawEventItem (scheme + JSON payload)
  → parse      decode the payload by scheme into a typed raw form
  → validate   semantic rules over the raw form
  → classify   project the raw form onto the normalized envelope
```

Each stage owns one concern and each is deterministic:

| Stage | Module | Owns |
|---|---|---|
| Parse | `parser.rs` | Structure: JSON validity, exact field sets, value types. Unknown fields are **rejected**, never silently dropped. |
| Validate | `validator.rs` | Semantics: type-dependent field presence, identifier shapes, schema-version gating, cross-field consistency. |
| Classify | `classifier.rs` | Projection onto `AuditEvent`: kind, provenance, placement metadata, deterministic event id. |
| Service | `normalizer.rs` | The one-call entry point: `Normalizer::normalize(item)` runs all stages and gates network consistency. |

The `Normalizer` service holds the pinned configuration — network,
emitting-source label, parser version — so the same payload always
classifies to the same envelope. The parser, validator, and classifier
are also exposed individually for tooling that needs to inspect a stage.

## Schemes

The scheme registry (`scheme.rs`) enumerates every payload class the
system can honestly attribute. Today exactly two exist:

* **`hooks-state-event`** — the raw on-chain state events
  `safeguard-hooks` actually emits (`account_frozen`,
  `account_unfrozen`, `token_bound`, `token_unbound`,
  `compliance_config_changed`). These classify as **observed** events
  with an on-chain provenance origin.
* **`audit-envelope`** — an already-normalized `AuditEvent` envelope
  re-ingested for backfill or replay. Its event id is authoritative and
  is **preserved**, never re-derived.

Transfer outcomes are deliberately **not** a raw scheme: a denied
transfer is never emitted on-chain (a revert discards its events), so it
cannot arrive as a source event. The audit layer derives it from
authoritative transaction metadata instead of pretending a source
produced it — see `docs/event-model.md`.

## What normalization guarantees

* **Determinism.** Same payload + same config = same envelope, same
  event id, same canonical bytes.
* **No silent reinterpretation.** Unknown fields, unsupported types, and
  unsupported versions are errors that name the offending field, never
  values that get guessed at.
* **Never arrival time.** Ordering metadata and identity come from
  ledger/close-time/placement data in the payload.
* **Privacy-safe failures.** Error messages name fields and give
  structural descriptions; they never echo payload contents that could
  carry protected values.
* **No invention.** The classifier adds nothing the raw form did not
  carry — no actor, no decision, no enforcement reference, no balances.

## Envelope contents

The normalized `AuditEvent` carries public metadata and references only:
event id and kind, schema version, network, provenance (origin/source/
parser version, plus derivation info for derived events), observed
timestamp, ordering metadata, and optional ledger/transaction/operation/
token/account/policy/enforcement references. No amounts, balances,
ciphertexts, or protected values exist on the envelope shape.

## Verification

* Unit tests cover every stage against the committed fixtures.
* `test-vectors/normalization` is an executable corpus: every file under
  `valid/` must normalize deterministically and every file under
  `malformed/` must fail with the failure class its `expect` field
  declares. Adding a vector is a code-free contract change.
* The end-to-end pipeline tests in `crates/integration-tests` drive the
  normalizer through the indexer exactly as production would.

[`AuditEvent`]: ../crates/audit-core/src/event.rs
