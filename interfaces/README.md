# Interfaces

Canonical protocol references between the Safeguard polyrepos, from the
perspective of this repository (VERIFY).

Safeguard is a three-polyrepo system with a strict separation of duties:

```text
safeguard-policy  (DEFINE)  ── versioned policy wire contract ──┐
                                                                 ▼
safeguard-hooks   (ENFORCE) ── state-transition compliance events ──┐
                                                                     ▼
safeguard-audit   (VERIFY)  ◄── observes and indexes both surfaces
```

This directory pins the *receiving* side of those contracts so the
normalizer, the Soroban adapter, and the reporting layer consume
documented shapes — never guesses about what the sibling repos emit.

## References

| File | Contract | Consumed by |
| ---- | -------- | ----------- |
| [`events.md`](events.md) | The hooks contract's state-transition events (freeze/unfreeze, bind/unbind, config changes, initialization) | `event-normalizer`, `soroban` adapter |
| [`policy.md`](policy.md) | The policy wire contract (`is_authorized`) and decision documents | derived-event reconstruction, reporting |

The canonical *emitting* side lives in the sibling polyrepos
(`safeguard-hooks/interfaces/`); when a reference here and the emitter
disagree, the emitter wins and this file is updated.