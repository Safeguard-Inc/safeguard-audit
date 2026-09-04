# Authorization

Access to audit data is explicit, scoped, attributable, and itself
auditable. The authorization subsystem answers one question:

> May this auditor perform this action within this scope right now?

and records the answer as an `audit-access` event, so the audit trail
can always show *who* looked at *what*, *when*, and with *which result*.

## Where the pieces live

| Concern | Location |
|---|---|
| Domain models (`AuditorRole`, `AccessAction`, `AccessScope`, `AuthorizationDecision`, `AuditAccessEntry`) | `audit-core` — `authorization.rs` |
| Derived events (`audit-access`, `authorization-changed`) | `audit-events` — `authorization.rs` |
| Decision engine (`roles`, `permissions`, `scopes`, `credentials`, `registry`, `authorizer`, `access_log`) | `authorization` crate (`crates/authorization`) |

The split is deliberate. `audit-core` defines *what an authorization is*;
the `authorization` crate computes *whether one is granted*. Nothing in
`audit-core` evaluates roles or checks scopes, and nothing in the
`authorization` crate re-defines the models — it consumes them.

## The evaluation chain

```
identity (role)  ──► role permission matrix ──► action allowed?
granted scopes   ──► scope containment        ──► scope in bounds?
credential       ──► expiry / validity check  ──► still authorized?
                                   │
                                   ▼
                    AuthorizationDecision (granted / denied / out-of-scope)
                                   │
                                   ▼
                    AuditAccessEntry ──► audit-access event ──► store
```

Each stage lives in its own module and is independently testable:

1. **roles** — the default least-privilege matrix mapping each role to the
   actions it may perform. One auditable table, cumulative from
   `read-only-reviewer` (observe and verify only) up to `administrator`
   (the only full set).
2. **permissions** — per-identity sets seeded from the role matrix with
   explicit additive/subtractive overrides. Every check is explainable
   (`GrantedByRole`, `GrantedByOverride`, `ExplicitlyDenied`,
   `NotGranted`), and the registry rejects overrides that merely duplicate
   the role baseline as configuration noise.
3. **scopes** — containment. Does a granted scope cover a requested one?
   `All` covers everything (administrators only, by policy); scopes match
   only their own kind; classification grants are directional (a
   `HighlyRestricted` grant covers `Restricted` requests, never the
   reverse); a granted time range must fully contain the requested range.
4. **credentials** — identity proof with an expiry, verified against an
   injected clock. This crate deliberately does **not** implement
   credential cryptography; an upstream identity provider validates real
   material. What the authorizer needs is: registered, unrevoked,
   unexpired.
5. **registry** — who holds which role, scopes, and credential. Grants
   must carry at least one scope; role history is auditable because
   changes surface as `authorization-changed` events.
6. **authorizer** — composes the above into an attributed
   `AuthorizationDecision`. Order is the contract: credential first
   (expiry wins over everything), then action, then scope. Out-of-scope
   is a distinct outcome from denied, and an unknown auditor is a clean
   denial with a reason code, never an error.
7. **access_log** — persists each decision as an `audit-access` event
   through the `EventStore`. Idempotent per entry id; recording is never
   re-authorized (no infinite recursion — see below).

## Outcome space

Every decision is one of:

| Outcome | Meaning | Reason code |
|---|---|---|
| Granted | credential valid, action in role, scope covered | `GRANTED` |
| Denied | credential invalid/expired, or role lacks the action | `CREDENTIAL_*`, `ACTION_DENIED`, `UNKNOWN_AUDITOR` |
| OutOfScope | action allowed but no granted scope contains the request | `SCOPE_OUT_OF_BOUNDS` |

Callers must never treat a denial as an error: `authorize` returns
`Ok(decision)` for all three policy outcomes and only errors on
configuration problems.

## Scoping rules that matter

- A token scope does **not** cover a contract request, even for the same
  contract — kinds never cross.
- A `Classification(Confidential)` grant does **not** authorize
  `Classification(Restricted)` reads.
- A bounded time-range grant cannot cover an unbounded request.
- `All` is never granted implicitly. Only explicit policy grants it, and
  only the role matrix decides who may hold it.

## Privacy linkage

Records carry a `DataClassification` (see `docs/privacy.md`). The privacy
linkage lives in `scopes`: `scope_for_classification(c)` maps a record's
classification to the `AccessScope` that must be granted, and
`covers_classification(grants, c)` answers "may this auditor touch data
at level `c`?" Since containment is directional, a grant for
`Restricted` reaches restricted *and* less-sensitive data but never
`HighlyRestricted`.

## Audit-access logging and the recursion boundary

Access to audit data is itself audit data — which risks infinite
recursion if recording an access required an authorized access. The
boundary is explicit:

- Every decision becomes one `AuditAccessEntry`, which becomes one
  derived `audit-access` event, which is written to the store **once**,
  by the access log, without being re-authorized.
- The event carries attribution (`auditor`, `accessed_at`, and
  `classification` when protected data was touched) so the persisted
  record answers *who/what/when* directly.
- There is deliberately **no meta-audit of the audit**. The entry model
  holds no pointer to a second-level log.

## No fake guarantees

The authorizer verifies credentials *the registry knows about*. Real
credential material — signatures, keys, tokens — must be validated by an
upstream identity provider behind the `Credential` abstraction. This
crate says so plainly and never pretends a registered, unexpired
credential is cryptographically proven. Similarly, the `NoopAccessLog`
exists only for development and is labeled: it records nothing and
provides no auditability.

## Testing

- Unit tests per module (role matrix cumulative and least-privilege
  boundaries; override semantics; scope containment; credential expiry
  and revocation; registry invariants; authorizer decisions).
- `crates/integration-tests/tests/authorization.rs` — end-to-end
  scenarios including a four-hop privilege-escalation attempt where every
  hop is denied or out-of-scope and recorded as such.
- `test-vectors/authorization/*.json` — an executable corpus: each vector
  declares a grant, a request, and the expected decision, and a walker
  test asks the real authorizer. New vectors need no code changes.
- `crates/integration-tests/examples/authorize-access.rs` — runnable
  walk-through of the full outcome space with a persisted access trail.
