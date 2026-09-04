# Auditor model

The auditor model answers three questions the audit trail must be able to
answer about any protected-data access:

1. **Who is acting?** — an [`AuditorIdentity`]: an id plus the role the
   identity holds.
2. **What may they do?** — a role, expanded by the authorization crate
   into a permission set, bounded by granted scopes.
3. **May they still act?** — a credential with an expiry, verified at the
   decision time.

## Identity is a reference, not a credential

`AuditorIdentity` names who is acting. It carries two fields:

| Field | Meaning |
|---|---|
| `auditor_id` | A deterministic `aud_<hex>` reference (see `identifiers`) |
| `role` | One of the six roles below |

Credential material is **never** part of an identity and never stored in
an audit record. The `authorization` crate's `Credential` keeps opaque
`material` for the identity provider to validate, and only a *hashed
reference* to the credential is ever usable for logging.

## Roles

Roles are coarse and ordered by increasing authority. The fine-grained
operations are `AccessAction`s (below), and the mapping between them is
the role matrix in `authorization::roles` — a single auditable table, not
scattered checks.

| Role | Baseline powers (summary) |
|---|---|
| `read-only-reviewer` | read records, query, inspect transactions/policy references, verify integrity |
| `auditor` | reviewer powers + inspect denied operations, view investigations |
| `senior-auditor` | auditor powers + generate evidence, generate reports, export records |
| `investigator` | read powers + create and view investigations, generate evidence |
| `compliance-officer` | senior powers + request protected data |
| `administrator` | the only full action set (also requires an explicit `all` scope) |

Roles are least-privilege by default: an identity gains exactly the
actions its role grants, and finer adjustments are explicit per-identity
overrides, never silent defaults. See `docs/authorization.md` for the
evaluation chain.

## Actions

`AccessAction` names the operations authorization controls:

- `read-record`, `query`
- `inspect-transaction`, `inspect-policy`, `inspect-denied`
- `create-investigation`, `view-investigation`
- `generate-evidence`, `generate-report`
- `export-records`
- `request-protected-data`
- `verify-integrity`

An action is always evaluated *together with a scope*: being allowed to
read records does not mean being allowed to read every record. The scope
bounds the action to a token, contract, network, account class,
investigation, time range, event kind, or data classification.

## Scoped access

An auditor authorized for one scope never automatically receives another.
Grants hold explicit scopes (see `authorization::scopes` for the
containment rules), and the containment test is the only path to a
granted decision — there is no fallback and no "close enough" matching.

## Lifecycle

```
administrator registers identity + role + scopes + credential
        │
        ▼
  (authorization-changed event recorded: grant)
        │
        ▼
   auditor acts ──► authorizer decides ──► audit-access event recorded
        │
        ▼
  administrator revokes or credential expires
        │
        ▼
  (authorization-changed event recorded: revocation)
```

Every step of the lifecycle is itself on the audit trail — role history
is auditable, and access history is the `audit-access` stream. The grant
table itself (the registry) is current state held by the authorization
service; history lives in the store.

## Privacy rules

- Identities are references. No credential material, view key, or secret
  ever appears in an identity, a grant record, or an access event.
- The access entry records the auditor id, the action, the scope label,
  the target reference, the result, the time, and (for protected-data
  access) the highest classification touched — nothing more.
- Access to protected data additionally requires a classification scope
  (`docs/authorization.md`, "Privacy linkage").

## Model location

The core models live in `audit-core` (`authorization.rs` and
`identifiers.rs`); the services that act on them live in the
`authorization` crate. Adapters for a real identity provider would sit
behind the `Credential` abstraction — this repository does not implement
one and does not pretend to.
