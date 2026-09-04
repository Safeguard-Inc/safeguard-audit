# Contributing areas

Work is organized into well-bounded areas so contributors can take one
independently. Every change follows `CONTRIBUTING.md` (one improvement per
commit, boundaries hold, no fake security, privacy is structural).

| Area | What lives here | A good first change |
| ---- | --------------- | ------------------- |
| **Events** | `audit-events` + the kind registry in `audit-core` | Add a kind (registry + schema + fixture + tests); improve a parser/validation rule; document a derived-event method |
| **Indexing** | Phase 2 (normalizer/indexer crates) | Cursor handling, checkpoint validation, deduplication edge cases, replay/resume tests |
| **Storage** | `storage` + `memory-store` | A new backend adapter; query-optimization tests; pagination edge cases |
| **Integrity** | integrity crate (Phase 3) over the `audit-core` vocabulary | Hashing of canonical records; chained digest tests; manifest generation and tamper-detection cases |
| **Authorization** | authorization crate (Phase 4) over roles/scopes/actions | Role-permission matrix tests; scope-boundary cases; access-logging correctness |
| **Privacy** | privacy crate (Phase 8) | Redaction determinism; classification enforcement; disclosure-control tests; leakage prevention in logs/exports |
| **Investigation** | investigation crate (Phase 5) | Case lifecycle service tests; timeline ordering; findings/evidence linkage |
| **Reporting** | reporting crate (Phase 7) | A report kind's deterministic generation; reproducibility tests (same store + request = same report) |
| **Soroban** | Soroban/RPC adapters (Phase 9) | Adapter tests mapping real contract/event semantics onto normalized types |
| **Security** | suites in every phase + `docs/threat-model.md` | Explicit attack tests (unauthorized, out-of-scope, tampered, malformed, spoofed); threat-model review |
| **Performance** | benches (Phase 12) | Ingestion/query/verification benchmarks with honest cost models |
| **Documentation** | `docs/`, README, schemas | Example workflows, diagrams, compatibility notes, data-classification walkthroughs |

## Cross-cutting rules

* **Test the negative.** Security/privacy behavior is proven by tests that
  must *fail to access*: unauthorized auditor, wrong scope, expired grant,
  tampered record, malformed event, duplicate replay.
* **Synthetic data only.** Fixtures and examples are fabricated; never use
  real addresses, balances, or personal data.
* **Wire contracts move together.** A change to an event shape updates the
  matching `schemas/*.schema.json` and a fixture, and the schema checker
  must pass.

## Getting assigned

Open an issue via the issue templates (each area has one) or pick a topic
from `docs/architecture.md`'s phase list and propose the scope in a PR.
When in doubt about a boundary — is this enforcement? is this policy? — it
does not belong in this repository.
