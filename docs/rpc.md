# RPC

The RPC crate (`crates/rpc`, `safeguard-audit-rpc`) is the Stellar
Soroban RPC *protocol* boundary: request and response envelopes for the
JSON-RPC `getEvents` method, verified against the current Stellar API
reference, plus the retry/timeout policy an ingestion loop runs under.
It sits above `safeguard-audit-soroban` (which models the event shape
and the ingestion door) and below the operator's transport, which this
repository does not ship.

## What this crate is not

- **No HTTP transport.** The crate defines the typed `EventsRpc` client
  contract and the envelope machinery, but performs no network I/O. A
  transport serializes the request body, POSTs it to a node, and hands
  the response body to the parser.
- **No invented semantics.** Protocol shapes are modeled as documented
  and pinned by tests against the documentation's own example request
  and response.

## The request shape (verified)

`getEvents` takes named parameters, exactly as the Stellar
documentation defines them:

| Parameter | Rule |
|---|---|
| `startLedger` | inclusive start; omitted when a `cursor` is carried |
| `endLedger` | exclusive end; omitted when a `cursor` is carried |
| `filters` | up to 5; each names an event `type` and/or up to 5 `contractIds` and/or up to 5 topic-matcher arrays of 1-4 segments |
| `pagination` | carries the opaque `cursor` and the `limit` |

The `limit` is bounded to 1-10,000 (the node's hardcoded range; it
defaults to 100 when absent). `GetEventsParams` validates the parameter
rules — a cursor request must not carry ledger bounds, a fresh request
needs a start ledger, filter cardinalities hold — before a request is
ever serialized, and `GetEventsRequest::body()` emits the JSON-RPC 2.0
envelope (`jsonrpc`, `id`, `method: "getEvents"`, `params`).

## The response shape (verified)

Responses are the JSON-RPC 2.0 envelope: a `result` member whose shape
is the `SorobanEventsResult` the soroban crate models (events plus the
retention window and the paging cursor), or an `error` member
(`code`/`message`/optional `data`). Parsing rules:

- the version must be `"2.0"`;
- a present `error` surfaces as a typed server error;
- a body with neither result nor error is malformed — never a silent
  empty page;
- unknown response fields are ignored, so a node that adds fields does
  not break ingestion.

## The client contract and retries

`EventsRpc` is the one typed call a transport implements:
`get_events(&GetEventsParams) -> Result<SorobanEventsResult, RpcError>`.
`EventsRpcFeed` adapts any such client to the `SorobanEventFeed` door
the ingestion source consumes, translating the source's resume position
into the RPC's cursor semantics exactly as documented: a fresh pass
sends the configured `startLedger`; a resumed pass sends only the
cursor.

`RpcError` is classified so retrying behaves sensibly:

| Class | Example | Retried? |
|---|---|---|
| `Transport` | connection dropped, node unreachable | yes |
| `Server` code in `-32099..=-32000` | the JSON-RPC reserved server-error range | yes |
| `Server` other / `Malformed` / `InvalidRequest` | rejected params, protocol violation | no |

`RetryPolicy` bounds attempts (default 5) with capped exponential
backoff, and `fetch_with_retry` applies it to a typed attempt closure —
permanent errors return immediately, transient ones recover within
budget, and the final error is returned as-is when the budget is
exhausted. `RpcPolicy` pairs the retry policy with a per-attempt
timeout that the transport applies.

## The mock

`MockEventsClient` implements `EventsRpc` over a recorded event list
with real paging semantics (cursor resumes, limits honored), plus an
optional transient-failure counter for exercising retry policies. It is
explicitly labeled for testing and development only: it performs no
network I/O, serves only what it was constructed with, and is not an
RPC node — it must never be treated as a security boundary.
