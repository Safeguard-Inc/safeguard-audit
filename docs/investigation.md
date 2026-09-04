# Investigation

Investigations turn *what happened* into a structured, auditable case.
When an operation is denied or flagged, an investigator opens a case,
links the records that prove what happened, records findings and notes,
and drives the case to a documented close — while every step lands on
the audit trail.

## Where the pieces live

| Concern | Location |
|---|---|
| Domain models (`InvestigationCase`, `CaseStatus`, `TimelineEntry`, `Finding`, `Note`, `RelatedReferences`) | `audit-core` — `investigation.rs` |
| Lifecycle event vocabulary (`InvestigationLifecycle`, `LifecycleKind`) | `audit-events` — `investigation.rs` |
| Services (`CaseStore`, `InMemoryCaseStore`, `CaseService`, `LifecycleStep`) | `investigation` crate (`crates/investigation`) |

The split mirrors the rest of the repository: `audit-core` defines *what
a case is*; the `investigation` crate runs the *workflow* and keeps the
two views — case state and audit history — consistent.

## Two stores, two views

A case is **mutable current state**: findings accumulate, statuses
change, a closed case is reopened. An audit record is **append-only
history**. These are fundamentally different things, so they live in
different stores:

* the **case store** (`CaseStore`) holds the current state of every
  case — in-memory by default, a durable adapter can be added without
  touching the service;
* the **audit store** (`EventStore`) holds the derived lifecycle events
  (`investigation-opened` / `investigation-updated` /
  `investigation-closed`) that make the history independently verifiable.

`CaseService` writes both: it mutates the case through the case store and
projects each step through `LifecycleStep` into the audit store. If the
service crashes between the two writes, re-running the step is
idempotent (the event identity is deterministic), so the views converge
without duplicating history.

## The lifecycle

```text
open(case) ──► assign(investigator) ──► investigating
  │                 │                       │
  │                 ├─► link records        ├─► escalated (needs review)
  │                 ├─► add finding         │
  │                 └─► add note            ▼
  │                                   resolved
  │                                       │
  └────────── admin reopen ◄──────────────▼
                           closed (reason recorded)
```

Status transitions are validated by the core model (`CaseStatus::
can_transition`), and the service adds two workflow rules on top:

* **closing requires a reason** — a closed case must say why it closed;
* **reopening requires an administrator** — a closed case is terminal
  unless an administrator explicitly reopens it.

The full transition contract is pinned by an executable corpus:
`test-vectors/investigation/lifecycle/` declares every legal and illegal
transition, and a walker test checks each against the model.

## Step identity and ordering

Every lifecycle step of a case is a distinct record. Two properties make
that true:

1. **Explicit kind.** The event kind is carried by the step
   (`LifecycleKind::Opened` / `Updated` / `Closed`), never inferred from
   the resulting status. Assigning a finding to a case that stays `Open`
   is an *update*, not a second *open*; reopening a closed case is an
   update too, never a claim that the case was newly created.
2. **Step sequence.** The zero-based sequence of the step within the
   case's history (its timeline length at commit time) is part of the
   event identity. Two steps of one case by the same actor therefore
   never collide in the store, while re-running the same step after a
   crash derives the same identity and is absorbed as a duplicate.

## Linking records

A case may reference reality, never ghosts: `link_record` verifies the
record exists in the audit store before adding it to the case's related
references, and records the linkage as a kinded timeline entry
(`denial`, `account-frozen`, `policy-decision`, ...). Findings can carry
supporting records; those references are checked the same way by the
caller-provided records.

## Authorization

The service holds an `Authorizer` (the real one from the authorization
crate) and requires:

* `CreateInvestigation` at the network scope to **open** a case,
* `CreateInvestigation` at the network scope to **mutate** a case
  (assign, transition, link, findings, notes, close),
* the **administrator role** to **reopen** a closed case.

A clean denial is a `NotAuthorized` outcome with a reason, never a panic
and never a silent pass. Finer case-level scoping (only the assigned
investigator may read a case) is layered by the caller on top of the
granted case scope.

## Findings and notes

* **Findings** classify what the investigation established
  (`PolicyVerdict`, `EnforcementVerdict`, `Anomaly`, `Pattern`,
  `Integrity`) with a severity and a bounded summary, and may cite
  supporting records. Their ids derive from the case and the step index,
  so the Nth finding of a case is deterministically the Nth finding.
* **Notes** are the investigator's scratchpad: an author, a bounded body,
  and a time. Both are recorded on the timeline and projected as
  `investigation-updated` events.

## Closure

Closing records `closed_at` and `closed_reason` on the case and emits an
`investigation-closed` event. After closure the case is terminal: any
mutation is rejected (`ClosedCase`) and only an administrator may reopen
it.

## Testing

* Unit tests per module: store round-trips and duplicate rejection,
  lifecycle step projection (kinds, sequence identity, idempotency),
  service open/assign/transition/link/finding/note workflows and their
  authorization gates.
* `crates/integration-tests/tests/investigation.rs` — the full scenario:
  a denied transfer is ingested, becomes a case, links its denial
  record, records a finding, and closes with a reason; both views
  (case-store state and audit-store history) are asserted.
* `test-vectors/investigation/lifecycle/` — executable transition
  corpus (see above).
* `crates/integration-tests/examples/create-investigation.rs` — runnable
  walk-through of the whole workflow.
* Invariants: case ids are deterministic per network+key across
  independent runs; lifecycle steps never collide in identity even under
  a fixed clock.

## Boundaries

* This crate never **enforces** policy — it investigates what happened.
* Cases are mutable state; the audit trail they generate is
  append-only. The two are deliberately separate stores, and the
  lifecycle events never duplicate case state — they record the steps.