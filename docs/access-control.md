# Access control

This document is the operator's guide to *enforcing* access control with
the authorization crate: what to register, how to ask for decisions, how
to record them, and what the boundaries are. For the internal design see
`docs/authorization.md`; for the identity model see
`docs/auditor-model.md`.

## The moving parts

```rust
use safeguard_audit_authorization::{Authorizer, Credential, Grant, Registry, StoreAccessLog};
use safeguard_audit_core::{AccessAction, AccessScope, AuditorId, AuditorRole, NetworkId};

let mut registry = Registry::new();

// 1. Register an auditor: role + scopes + credential.
registry.register(
    Grant::new(auditor_id, AuditorRole::SeniorAuditor)
        .with_scope(AccessScope::Network(NetworkId::new(NetworkId::TESTNET)?))
        .with_credential(Credential::new(
            auditor_id,
            "material-issued-by-identity-provider",
            expiry_timestamp,
        )),
)?;

// 2. Ask for a decision.
let decision = authorizer.authorize(
    &auditor_id,
    AccessAction::GenerateReport,
    &AccessScope::Network(NetworkId::new(NetworkId::TESTNET)?),
)?;

// 3. Record the decision as an audit-access event.
let entry = authorizer.entry_for_decision(&decision, Some("rec_1234"))?;
log.record_into(&entry, &mut store)?;
```

The full flow, with three auditors and the printed access trail, is
runnable:

```text
cargo run -p safeguard-audit-integration-tests --example authorize-access
```

## Rules for safe use

1. **A grant needs at least one scope.** The registry rejects scope-less
   grants: they could never authorize anything and are configuration
   errors, not policy outcomes.

2. **A grant needs a role.** The role seeds the permission set. Change the
   role to change the baseline; use explicit overrides (`allow`/`deny`
   on the permission set) for the exceptions — but note that an override
   duplicating the role baseline is rejected as noise.

3. **Check credential expiry at decision time.** The authorizer does this
   for you with its injected clock. An expired credential denies even an
   `administrator` — expiry is checked before any permission or scope.

4. **Never treat denials as errors.** `authorize` returns `Ok` for
   granted, denied, and out-of-scope. Distinguish the reasons by the
   decision's reason code:
   - `GRANTED`
   - `CREDENTIAL_INVALID` / `CREDENTIAL_EXPIRED` / `UNKNOWN_AUDITOR`
   - `ACTION_DENIED` — role lacks the action
   - `SCOPE_OUT_OF_BOUNDS` — action allowed, scope not covered

5. **Protect classification-scoped data.** Data classified `Restricted`
   or `HighlyRestricted` (the privacy model in `audit-core`) must only be
   served when the grants cover the record's classification:

   ```rust
   use safeguard_audit_authorization::scopes::covers_classification;
   if !covers_classification(grant.scopes, record.classification) {
       // deny; the record must not be serialized to this caller
   }
   ```

6. **Record every decision.** Route decisions through the access log so
   the trail answers who/what/when. Recording is idempotent per entry id,
   so replaying a decision is safe.

## What is out of scope here

- **Identity proof.** This repository verifies credentials the registry
  knows about; real cryptographic proof belongs to an upstream identity
  provider behind the `Credential` abstraction.
- **Authentication of end users.** The auditor model starts from an
  `AuditorId`; turning a login into an `AuditorId` is an integration
  concern.
- **Per-record ACLs at storage time.** Records are stored with a
  classification and redaction metadata; *enforcement* happens at the
  service boundary via the authorizer, before a record is serialized to a
  caller.

## Boundary summary

| Caller wants to | Use | Outcome |
|---|---|---|
| read within granted scope | `authorize(id, ReadRecord, scope)` | granted |
| read outside granted scope | `authorize(id, ReadRecord, other_scope)` | out-of-scope |
| generate a report as read-only | `authorize(id, GenerateReport, scope)` | denied |
| act after credential expiry | `authorize(id, AnyAction, scope)` | denied (expired) |
| escalate to another network | `authorize(id, AnyAction, foreign_net)` | out-of-scope |
| access protected data | classification scope must cover record's level | gated |
