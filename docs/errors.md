# Error codes

Every error the audit domain can produce has a stable symbolic id and a
stable numeric code. **Codes are assign-only and are never reused**: a
variant that is removed keeps its number in the catalog's `retired`
list, so a code observed in a stored record, a log line or a downstream
integration never silently changes meaning.

The catalog is generated from the Rust sources and verified on every
run of CI, so this file cannot drift from the code:

```bash
python3 scripts/error_catalog.py --check   # gate
python3 scripts/error_catalog.py --write   # regenerate
```

## Code table

### `AuditError` — `crates/audit-core/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1001 | `SGA-AUDIT-ERROR-INVALID-IDENTIFIER` | `InvalidIdentifier` | An identifier failed structural validation (empty, wrong length, forbidden characters, or an out-of-range value). |
| 1002 | `SGA-AUDIT-ERROR-INVALID-TIMESTAMP` | `InvalidTimestamp` | A timestamp was outside the representable or acceptable range. |
| 1003 | `SGA-AUDIT-ERROR-INVALID-EVENT` | `InvalidEvent` | The event is structurally well-formed but semantically invalid. |
| 1004 | `SGA-AUDIT-ERROR-UNSUPPORTED-EVENT` | `UnsupportedEvent` | The event type is not in the supported registry. |
| 1005 | `SGA-AUDIT-ERROR-UNSUPPORTED-EVENT-VERSION` | `UnsupportedEventVersion` | The event version predates or postdates what this build understands. |
| 1006 | `SGA-AUDIT-ERROR-DUPLICATE-EVENT` | `DuplicateEvent` | An event that was already recorded was presented for insertion. |
| 1007 | `SGA-AUDIT-ERROR-AUTHORIZATION-FAILURE` | `AuthorizationFailure` | A caller attempted something they are not authorized to do. |
| 1008 | `SGA-AUDIT-ERROR-SCOPE-VIOLATION` | `ScopeViolation` | The caller is authorized but the request is outside their scope. |
| 1009 | `SGA-AUDIT-ERROR-STORAGE-FAILURE` | `StorageFailure` | The underlying storage layer failed. |
| 1010 | `SGA-AUDIT-ERROR-SOURCE-FAILURE` | `SourceFailure` | An upstream event source failed (network, timeout, malformed reply). |
| 1011 | `SGA-AUDIT-ERROR-INTEGRITY-FAILURE` | `IntegrityFailure` | An integrity check failed: digest mismatch, broken chain, tampering. |
| 1012 | `SGA-AUDIT-ERROR-MALFORMED-EVIDENCE` | `MalformedEvidence` | Evidence could not be parsed or did not match its manifest. |
| 1013 | `SGA-AUDIT-ERROR-REPORT-GENERATION-FAILURE` | `ReportGenerationFailure` | A report could not be generated. |
| 1014 | `SGA-AUDIT-ERROR-EXPORT-FAILURE` | `ExportFailure` | An export could not be produced. |
| 1015 | `SGA-AUDIT-ERROR-DECRYPTION-AUTHORIZATION-FAILURE` | `DecryptionAuthorizationFailure` | A decryption request was refused by the authorization boundary. |
| 1016 | `SGA-AUDIT-ERROR-UNSUPPORTED-SCHEMA` | `UnsupportedSchema` | The data carries a schema this build does not understand. |
| 1017 | `SGA-AUDIT-ERROR-VERSION-MISMATCH` | `VersionMismatch` | Two versions that must agree do not (policy, enforcement, parser...). |
| 1018 | `SGA-AUDIT-ERROR-REPLAY-CONFLICT` | `ReplayConflict` | Replay would conflict with existing production history. |
| 1019 | `SGA-AUDIT-ERROR-SERIALIZATION-FAILURE` | `SerializationFailure` | Canonical serialization failed (a value was not serializable). |
| 1020 | `SGA-AUDIT-ERROR-INVALID-QUERY` | `InvalidQuery` | A query was structurally invalid (contradictory filters, unknown fields, impossible ranges). |
| 1021 | `SGA-AUDIT-ERROR-VALIDATION-FAILURE` | `ValidationFailure` | A value failed validation that is not covered by a more specific variant (used by builders for compound invariants). |
| 1022 | `SGA-AUDIT-ERROR-INTERNAL` | `Internal` | An invariant violation or programmer error; never user-triggerable. |

### `AuthorizationError` — `crates/authorization/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1101 | `SGA-AUTHORIZATION-ERROR-UNKNOWN-AUDITOR` | `UnknownAuditor` | The auditor identity is not registered with any grants. |
| 1102 | `SGA-AUTHORIZATION-ERROR-INVALID-CREDENTIAL` | `InvalidCredential` | The presented credential is not registered or does not match the identity claiming it. |
| 1103 | `SGA-AUTHORIZATION-ERROR-CREDENTIAL-EXPIRED` | `CredentialExpired` | The credential has expired as of the decision time. |
| 1104 | `SGA-AUTHORIZATION-ERROR-EMPTY-GRANT` | `EmptyGrant` | A grant was defined without any scopes and without the `all` scope — it can never authorize anything, which is almost certainly a configuration error. |
| 1105 | `SGA-AUTHORIZATION-ERROR-INVALID-SCOPE` | `InvalidScope` | A scope could not be built from the supplied parts. |
| 1106 | `SGA-AUTHORIZATION-ERROR-UNLOGGABLE-SCOPE` | `UnloggableScope` | The requested scope is not representable as a stable label. |
| 1107 | `SGA-AUTHORIZATION-ERROR-ACCESS-LOG-FAILURE` | `AccessLogFailure` | The authorizer was asked to record an access entry it could not persist (e.g. the store rejected the audit-access record). |
| 1108 | `SGA-AUTHORIZATION-ERROR-INTERNAL` | `Internal` | An internal invariant was violated (e.g. a grant table with an inconsistent role). This is a bug, not a policy outcome. |

### `DecryptionError` — `crates/audit-core/src/decryption.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1201 | `SGA-DECRYPTION-ERROR-INVALID-REQUEST` | `InvalidRequest` | The request violated the boundary contract. |
| 1202 | `SGA-DECRYPTION-ERROR-NOT-AUTHORIZED` | `NotAuthorized` | The requester is not an authorized view-key holder. |
| 1203 | `SGA-DECRYPTION-ERROR-DENIED` | `Denied` | The request was authorized but the provider refused this access. |
| 1204 | `SGA-DECRYPTION-ERROR-FAILED` | `Failed` | The provider could not complete the request. |

### `EventError` — `crates/audit-events/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1301 | `SGA-EVENT-ERROR-UNSUPPORTED-EVENT-TYPE` | `UnsupportedEventType` | The event type is not in the supported registry. |
| 1302 | `SGA-EVENT-ERROR-UNSUPPORTED-EVENT-VERSION` | `UnsupportedEventVersion` | The event's version predates or postdates this build. |
| 1303 | `SGA-EVENT-ERROR-MALFORMED-PAYLOAD` | `MalformedPayload` | The event payload is structurally malformed. |
| 1304 | `SGA-EVENT-ERROR-MISSING-FIELD` | `MissingField` | A required field is absent. |
| 1305 | `SGA-EVENT-ERROR-INVALID-FIELD-VALUE` | `InvalidFieldValue` | A field has an invalid value. |
| 1306 | `SGA-EVENT-ERROR-AMBIGUOUS-ORDER` | `AmbiguousOrder` | Ordering metadata is ambiguous or contradictory. |
| 1307 | `SGA-EVENT-ERROR-NOT-DERIVABLE` | `NotDerivable` | The event cannot be derived from the given sources. |

### `EvidenceError` — `crates/evidence/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1401 | `SGA-EVIDENCE-ERROR-NOT-AUTHORIZED` | `NotAuthorized` | The acting auditor was not authorized to generate evidence. |
| 1402 | `SGA-EVIDENCE-ERROR-NO-SOURCE-RECORDS` | `NoSourceRecords` | Evidence requires at least one named source record. |
| 1403 | `SGA-EVIDENCE-ERROR-RECORD-MISSING` | `RecordMissing` | A named source record does not exist in the audit store. |
| 1404 | `SGA-EVIDENCE-ERROR-TAMPERED-SOURCE` | `TamperedSource` | A source record failed integrity verification; evidence is never built over altered records. |
| 1405 | `SGA-EVIDENCE-ERROR-INVALID-CONTENT` | `InvalidContent` | Invalid arguments or content (e.g. an unsupported kind). |
| 1406 | `SGA-EVIDENCE-ERROR-INTEGRITY` | `Integrity` | The integrity crate failed (hashing, manifest, or verification). |
| 1407 | `SGA-EVIDENCE-ERROR-EVENT-RECORD` | `EventRecord` | Recording the evidence-generated event into the audit store failed. |
| 1408 | `SGA-EVIDENCE-ERROR-INTERNAL` | `Internal` | Internal invariant broken (never expected at runtime). |

### `IndexerError` — `crates/event-indexer/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1501 | `SGA-INDEXER-ERROR-SOURCE` | `Source` | The event source failed to produce a page (retryable). The message carries the source's own error text. |
| 1502 | `SGA-INDEXER-ERROR-NORMALIZE` | `Normalize` | A raw item failed normalization (per-item, not retryable as-is). |
| 1503 | `SGA-INDEXER-ERROR-STORE` | `Store` | The store rejected a write (operator intervention). |
| 1504 | `SGA-INDEXER-ERROR-CHECKPOINT` | `Checkpoint` | The checkpoint could not be loaded, saved, or honored. |
| 1505 | `SGA-INDEXER-ERROR-ORDERING` | `Ordering` | Events within one page violated the deterministic ordering rules. |
| 1506 | `SGA-INDEXER-ERROR-POSITION` | `Position` | An item's recorded position is inconsistent with the source's contract (e.g. the source re-served an item at or before the checkpoint position). |
| 1507 | `SGA-INDEXER-ERROR-INTERNAL` | `Internal` | Invariant violation or programmer error; never user-triggerable. |

### `IntegrityError` — `crates/integrity/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1601 | `SGA-INTEGRITY-ERROR-INVALID-ARGUMENTS` | `InvalidArguments` | A manifest range or argument was incoherent. |
| 1602 | `SGA-INTEGRITY-ERROR-CANONICALIZATION` | `Canonicalization` | A record could not be canonicalized (should never happen for the domain types; surfaced rather than hidden). |

### `InvestigationError` — `crates/investigation/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1701 | `SGA-INVESTIGATION-ERROR-CASE-NOT-FOUND` | `CaseNotFound` | The case id does not exist in the case store. |
| 1702 | `SGA-INVESTIGATION-ERROR-CASE-ALREADY-EXISTS` | `CaseAlreadyExists` | A case with this id already exists (idempotent re-open is handled explicitly; an unexpected duplicate is a bug). |
| 1703 | `SGA-INVESTIGATION-ERROR-INVALID-TRANSITION` | `InvalidTransition` | The requested status transition is not allowed by the case model. |
| 1704 | `SGA-INVESTIGATION-ERROR-CLOSED-CASE` | `ClosedCase` | The operation requires the case to be open (findings, notes, linking, and transitions after closure are rejected). |
| 1705 | `SGA-INVESTIGATION-ERROR-NOT-AUTHORIZED` | `NotAuthorized` | The actor is not authorized for the operation on this case. |
| 1706 | `SGA-INVESTIGATION-ERROR-MISSING-RECORD` | `MissingRecord` | A referenced audit record does not exist in the store. |
| 1707 | `SGA-INVESTIGATION-ERROR-STORE` | `Store` | A case-store operation failed. |
| 1708 | `SGA-INVESTIGATION-ERROR-LIFECYCLE-RECORD` | `LifecycleRecord` | An audit-store (EventStore) operation failed while recording a lifecycle event. |
| 1709 | `SGA-INVESTIGATION-ERROR-INVALID-CONTENT` | `InvalidContent` | Validation of case content failed (title, summary bounds, etc.). |
| 1710 | `SGA-INVESTIGATION-ERROR-INTERNAL` | `Internal` | An internal invariant was violated. This is a bug, not a workflow outcome. |

### `NormalizerError` — `crates/event-normalizer/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1801 | `SGA-NORMALIZER-ERROR-UNSUPPORTED-SCHEME` | `UnsupportedScheme` | The item named a scheme this build does not implement. |
| 1802 | `SGA-NORMALIZER-ERROR-UNSUPPORTED-VERSION` | `UnsupportedVersion` | The scheme is known but the payload version is not supported. |
| 1803 | `SGA-NORMALIZER-ERROR-MALFORMED-PAYLOAD` | `MalformedPayload` | The payload was not decodable JSON or not the expected shape. |
| 1804 | `SGA-NORMALIZER-ERROR-VALIDATION-FAILED` | `ValidationFailed` | The payload decoded but violated semantic rules. |
| 1805 | `SGA-NORMALIZER-ERROR-CLASSIFICATION-FAILED` | `ClassificationFailed` | The payload was valid but could not be projected onto the envelope. |

### `PermissionReason` — `crates/authorization/src/permissions.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 1901 | `SGA-PERMISSION-REASON-GRANTED-BY-ROLE` | `GrantedByRole` | The role baseline grants the action. |
| 1902 | `SGA-PERMISSION-REASON-GRANTED-BY-OVERRIDE` | `GrantedByOverride` | An explicit per-identity override granted it. |
| 1903 | `SGA-PERMISSION-REASON-EXPLICITLY-DENIED` | `ExplicitlyDenied` | An explicit per-identity override revoked it. |
| 1904 | `SGA-PERMISSION-REASON-NOT-GRANTED` | `NotGranted` | Neither the role nor any override grants it. |

### `ReportingError` — `crates/reporting/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 2001 | `SGA-REPORTING-ERROR-NOT-AUTHORIZED` | `NotAuthorized` | The acting auditor was not authorized to generate reports. |
| 2002 | `SGA-REPORTING-ERROR-INVALID-REQUEST` | `InvalidRequest` | The request was malformed or incoherent. |
| 2003 | `SGA-REPORTING-ERROR-UNSUPPORTED-KIND` | `UnsupportedKind` | An unsupported report kind was requested. |
| 2004 | `SGA-REPORTING-ERROR-STORE` | `Store` | The store query/scan failed. |
| 2005 | `SGA-REPORTING-ERROR-INTEGRITY` | `Integrity` | Hashing or canonicalization failed. |
| 2006 | `SGA-REPORTING-ERROR-EVENT-RECORD` | `EventRecord` | Recording the report-generated event failed. |
| 2007 | `SGA-REPORTING-ERROR-INTERNAL` | `Internal` | Internal invariant broken (never expected at runtime). |

### `RpcError` — `crates/rpc/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 2101 | `SGA-RPC-ERROR-TRANSPORT` | `Transport` | The transport could not complete the exchange (connection failure, timeout, node unreachable). Potentially transient — the retry policy treats this class as retryable. |
| 2102 | `SGA-RPC-ERROR-SERVER` | `Server` | The node answered with a JSON-RPC error member. |
| 2103 | `SGA-RPC-ERROR-MALFORMED` | `Malformed` | The response violated the JSON-RPC or getEvents envelope contract (wrong protocol version, missing result and error, undecodable body). Retrying cannot fix a malformed response. |
| 2104 | `SGA-RPC-ERROR-INVALID-REQUEST` | `InvalidRequest` | The request itself was rejected by local validation (an incoherent combination of parameters, an out-of-range limit). |

### `SourceError` — `crates/audit-core/src/source.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 2201 | `SGA-SOURCE-ERROR-FETCH-FAILED` | `FetchFailed` | The source could not produce a page (network, decode, backend). |
| 2202 | `SGA-SOURCE-ERROR-INVALID-POSITION` | `InvalidPosition` | A resume position was unknown or invalid to this source. |
| 2203 | `SGA-SOURCE-ERROR-LIMIT-OUT-OF-RANGE` | `LimitOutOfRange` | A page limit was outside the source's supported range. |
| 2204 | `SGA-SOURCE-ERROR-INVALID-ITEM` | `InvalidItem` | An item violated the source item contract. |

### `StoreError` — `crates/storage/src/errors.rs`

| Code | Symbol | Variant | Meaning |
| ---: | ------ | ------- | ------- |
| 2301 | `SGA-STORE-ERROR-NOT-FOUND` | `NotFound` | The requested record does not exist. |
| 2302 | `SGA-STORE-ERROR-DUPLICATE` | `Duplicate` | An insert collided with an existing record/event. |
| 2303 | `SGA-STORE-ERROR-INVALID-CURSOR` | `InvalidCursor` | A cursor was malformed or out of range. |
| 2304 | `SGA-STORE-ERROR-INVALID-QUERY` | `InvalidQuery` | A query was structurally invalid (e.g. contradictory filters). |
| 2305 | `SGA-STORE-ERROR-BATCH-REJECTED` | `BatchRejected` | A batch was rejected as a whole (validation or write conflict). |
| 2306 | `SGA-STORE-ERROR-INTEGRITY-MISMATCH` | `IntegrityMismatch` | An integrity expectation of the store failed (tamper detection). |
| 2307 | `SGA-STORE-ERROR-UNSUPPORTED` | `Unsupported` | The requested operation is unsupported by this store. |
| 2308 | `SGA-STORE-ERROR-STORAGE-FAILURE` | `StorageFailure` | The underlying storage backend failed. |

## Coverage

100 codes across 14 enums. 100 carry a documented meaning.
