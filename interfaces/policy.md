# Policy wire contract — receiving side

`safeguard-policy` (DEFINE) exposes a policy contract that `safeguard-hooks`
(ENFORCE) calls on every gated operation. Audit does not call the policy
contract, but it consumes policy artifacts — decision documents and the
versioned policy schema — when reconstructing *derived* events and reports.
The canonical emitter-side references live in `safeguard-hooks/interfaces/`
and `safeguard-policy/docs/contract-interface.md`.

## The enforcement seam

```text
is_authorized(account: Address, token: Address) -> bool
```

The hooks layer screens each party of an operation with its own call; a
revert or non-boolean answer is reported as `policy_unavailable` and the
operation fails closed. Audit never re-evaluates policy — it records which
policy version produced a decision, by reference.

## Decision documents

Evaluations resolve to one of `APPROVE`, `BLOCK`, `FLAG` with supporting
metadata (policy id, policy version, rule reference, reason code, and an
off-chain timestamp). The machine-readable form is the
`policy-schema/decision.schema.json` of `safeguard-policy`, which this
repository's schemas mirror for its own decision records.

## What audit consumes

* **Policy identity and versions** — to attribute a derived decision to the
  policy version in force when the operation was screened.
* **Reason codes** — the stable, documented machine-readable causes that the
  hooks revert codes mirror (`safeguard-hooks/docs/errors.md`).
* **Nothing else** — no registry data, no private financial data, and no
  policy evaluation. The privacy boundary is load-bearing: audit persists
  evidence, not compliance secrets.