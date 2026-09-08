# Hooks events (audit bridge) — receiving side

The `safeguard-hooks` enforcement contract emits state-transition events
that this repository indexes. The canonical emitter-side reference is
`safeguard-hooks/interfaces/events/events.md`; this file records the
receiving contract for the audit polyrepo.

## Event catalog

| Event | Topic | Payload | Meaning |
| ----- | ----- | ------- | ------- |
| `Initialized` | `Initialized` | `admin` | Contract initialized with this authority |
| `AccountFrozen` | `AccountFrozen` | `token`, `account` | Admin froze the account on the token |
| `AccountUnfrozen` | `AccountUnfrozen` | `token`, `account` | Admin unfroze the account on the token |
| `TokenBound` | `TokenBound` | `token` | Admin admitted the token into scope |
| `TokenUnbound` | `TokenUnbound` | `token` | Admin removed the token from scope |
| `ComplianceConfigChanged` | `ComplianceConfigChanged` | `policy` (or none), `sac_passthrough` | Admin rewrote the compliance configuration |

## Semantics the audit layer relies on

* **Events describe state transitions only.** Idempotent repeats (freezing
  an already-frozen account, rewriting the identical configuration) emit
  nothing; the audit indexer must not fabricate records for absent events.
* **Approvals are never emitted.** Any contract can invoke the hook
  surface, so an approval record would be spoofable audit poison. The
  absence of a transition is the evidence for a rejected operation
  (rejection = revert = no state change).
* **No private data.** Topics and payloads carry addresses and booleans
  only — never amounts, balances, commitments, or proofs.
* **Ordering anchor.** Every real `set_config` bumps the monotonic
  `config_version()` on the hooks contract; the audit layer pairs a
  `ComplianceConfigChanged` event with the version to reconstruct the exact
  policy timeline a historical rejection refers to.

## Wire shape

Events cross the Soroban RPC as contract events whose topic vector starts
with the event name symbol and whose payload is the transition data. The
`soroban` adapter validates and classifies admitted events before they
enter the normalizer (`crates/soroban`, `crates/event-normalizer`).