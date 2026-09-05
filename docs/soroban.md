# Soroban

The Soroban adapter is the door real on-chain data enters through:
it carries the *on-chain facts* of an operation — which contract
emitted which event, in which ledger and transaction, with which
topics — from a Soroban node into the ingestion pipeline. It speaks
the audit layer's normalized vocabulary on one side and a verified
Stellar RPC wire shape on the other.

`crates/soroban` (`safeguard-audit-soroban`) models the wire and the
ingestion door. `crates/rpc` (`safeguard-audit-rpc`, documented in
[rpc.md](rpc.md)) models the JSON-RPC protocol an operator's transport
implements and plugs into the door.

## What this layer is not

This adapter must never become the *meaning* layer:

- It does not decode ScVals. Topics and values stay opaque base64; their
  meaning belongs to the contract that emitted them.
- It does not decide what an event means for compliance. An event
  becomes an audit event only through the verified payload schemas of
  the contracts this deployment audits — never invented here.
- It is not an RPC client. Fetching is behind a narrow `SorobanEventFeed`
  trait; this crate depends on no network stack and no node.

The compliance meaning of an operation lives upstream, in
`safeguard-hooks`; this layer carries the on-chain envelope that the
audit trail correlates with it.

## The verified wire model

The `wire` module mirrors the Stellar RPC `getEvents` response shape as
the Stellar API reference defines it, and the shape is pinned verbatim
by tests against the documentation's own example:

| Wire field | Meaning here |
|---|---|
| `type` | `contract` or `system` emission |
| `ledger` | the ledger sequence the event was emitted in |
| `ledgerClosedAt` | ISO-8601 close time of that ledger |
| `contractId` | StrKey address of the emitting contract |
| `id` | the TOID-based dedup key: 19-character TOID + hyphen + 10-character zero-padded event index |
| `transactionIndex`, `operationIndex` | position within the ledger / transaction |
| `inSuccessfulContractCall` | deprecated by Stellar; retained for forward compatibility |
| `topic` | 1-4 base64 ScVal segments |
| `value` | the emitted data, a base64 ScVal |
| `txHash` | the 64-lowercase-hex transaction hash |

Parsing is deliberately tolerant forward (unknown wire fields are
ignored) and strict on coherence: `SorobanEvent::validate()` is the
single wire-level door both the source and the mapping run, enforcing
only the shape — a TOID id whose index fits the supported range, a
positive ledger, 1-4 topics, and the lowercase-hex transaction hash —
never meaning.

## The ingestion door

`SorobanEventSource` implements the core `EventSource` trait, so
Soroban pages feed the normalizer exactly like any other source:

- **Positions are event ids.** A raw item's position is the event's own
  TOID `id` — the same key the pipeline's dedup and the derived event
  identity use — never arrival time.
- **Resumption is sound.** The RPC page cursor equals the last event's
  id, so the source resumes after a consumed item by passing that id
  back to the feed. Even a misbehaving feed can never make it re-serve
  an event at or before the resume point, and out-of-order pages are
  rejected, never silently mis-ordered.
- **Admission is the operator registry's decision.** The source is
  built for one network and consults its `ContractRegistry` for every
  event. Recognized contracts' events become raw items stamped with the
  contract's operator-chosen label (the scheme a future parser registry
  binds); system events and events from unregistered contracts are
  skipped — never silently — with a cumulative count a caller reads
  between fetches. An empty registry, the default, admits nothing.
- **Identity is deterministic.** `event_id` derives from network + TOID
  id, so it is kind-independent (re-normalizing under a newer parser
  keeps the same id and dedup keeps working) and losslessly
  reproducible from the resume position alone (checkpoint and identity
  can never disagree).

## The metadata mapping

`to_normalized` converts a wire event into the provider-neutral pieces
the audit model speaks — `EventOrder` (ledger sequence, transaction and
operation position, event index from the TOID suffix), `LedgerReference`
(with close time), and an optional `TransactionReference` — every piece
validated through the `audit-core` constructors, so a malformed wire
value is an error, never a silently wrong reference.

The ledger close time arrives as an RFC 3339 UTC string. The parser is
strict and self-validating: it converts the text to Unix seconds and
asks `audit-core`'s own renderer to reproduce the input. A string that
does not round-trip exactly — an impossible date (`2026-02-30`), a
non-UTC offset, trailing garbage — is rejected rather than
approximated. No calendar logic is invented in this crate.

## Fixtures and vectors

- `fixtures/soroban/` — committed `getEvents` result pages: a
  hooks-transfer page and a mixed page interleaving a system event and
  an unregistered-contract event around a recognized one.
- `test-vectors/soroban/` — a committed wire corpus (valid and invalid
  events, one per rejection class) with an executable runner that walks
  every file through the same `validate` + `to_normalized` doors the
  pipeline uses.
- `crates/integration-tests` — end-to-end adapter tests (mock RPC →
  feed → registry-gated source over the fixtures) and cross-cutting
  invariants: served-set invariance under page size, safe advance
  through fully-skipped pages, and byte-deterministic drains.

## What waits on upstream verification

The adapter closes at the boundary of *meaning*. Converting a
recognized contract's wire event into an audit event kind (freeze,
bind, config-change, …) requires the actual `safeguard-hooks` payload
schemas, which live in the sibling repository. Until that mapping is
verified against the real hooks surface, events arrive as scheme-labeled
raw items — admitted, positioned, ordered, and identity-stamped — and
stop exactly where an invented payload mapping would begin.
