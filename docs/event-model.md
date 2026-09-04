# Event model

## One envelope, many sources

Raw events arrive in provider-specific shapes — a Soroban diagnostics
event, an RPC feed item, a simulator output, a fixture. A normalizer
converts each into the **`AuditEvent`** envelope: one shape with a typed
`EventKind`, source provenance, ordering metadata, and optional references.
Everything downstream (dedup, storage, integrity, queries, reports) speaks
only the envelope.

## Observed versus derived

The single most important distinction in the model:

* **Observed** (`origin: on-chain`) — a contract really emitted this and a
  ledger confirmed it. The audit layer records what it saw.
* **Derived** (`origin: derived` + derivation info) — no contract could
  emit this; an authorized process reconstructed it from authoritative
  metadata. The envelope's derivation info names the method, the source
  material, and why.

Why derived events exist at all: the enforcement layer (`safeguard-hooks`)
never emits per-operation approvals (any contract could spoof the hook
surface) and cannot emit denials (a revert discards its events). Transfer
outcomes are therefore *always* derived — reconstructed from the recorded
transaction and the correlated decision. The provenance model keeps the
difference visible on every record instead of blurring it. Simulated and
imported origins cover the simulator and external feeds.

## The kind registry

Eighteen kinds, serialized as stable kebab-case strings
(`docs/event-model.md` registry mirrors `audit-core`):

| Kind | Emitted by | Normalized as |
| --- | --- | --- |
| `account-frozen`, `account-unfrozen` | hooks contract | observed |
| `token-bound`, `token-unbound` | hooks contract | observed |
| `configuration-changed` | hooks contract | observed |
| `transfer-authorized/-denied/-flagged` | — | derived |
| `compliance-decision`, `policy-version-changed` | indexer/operator | derived |
| `authorization-changed`, `audit-access` | audit services | derived |
| `investigation-opened/-updated/-closed` | investigation service | derived |
| `evidence-generated`, `report-generated` | audit services | derived |
| `record-corrected` | audit services | derived |

Adding a kind is a deliberate registry change; normalizers reject anything
outside it (`unsupported-event`).

## Identity and ordering

* **Identity** derives from stable source parts (network, tx hash, op
  index, event index, kind) — never arrival time. The same source event
  observed twice derives the same `evt_` id, which is what makes duplicate
  ingestion idempotent.
* **Ordering** follows the on-chain hierarchy: ledger sequence, then
  transaction position, operation index, event index. Local machine time
  never orders history. Records without on-chain placement sort
  deterministically by recording time and record id, and any residual
  uncertainty is explicit rather than hidden.

## What an event never carries

No amounts, balances, ciphertexts, proofs, or view-key material. The
envelope's `details` map is string-valued and its allowed keys are
constrained by the normalizer, so nothing can smuggle protected or
free-form data into a record through the back door.

## Lifecycle

```text
Raw event ──► validate ──► classify kind ──► derive identity ──► stamp provenance
    ──► attach refs (tx/op/token/accounts/policy/enforcement) ──► AuditEvent
    ──► (validate envelope) ──► AuditRecord ──► store
```
