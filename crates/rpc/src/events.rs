//! The `getEvents` protocol shapes, verified against the Stellar API
//! reference.
//!
//! The request side mirrors the documented `params` object exactly:
//! `startLedger` (inclusive; must be omitted when a cursor is carried),
//! `endLedger` (exclusive), up to five `filters` — each naming an event
//! `type` and/or up to five `contractIds` and/or up to five topic
//! matchers — and `pagination` carrying the opaque `cursor` and the
//! 1-10,000 `limit`. Field ordering in the serialized JSON is canonical
//! and semantically irrelevant, and the example request from the
//! documentation is pinned by test.
//!
//! The response side is the JSON-RPC 2.0 envelope whose `result` is the
//! verified [`SorobanEventsResult`] shape and whose `error` member
//! surfaces as a typed [`RpcError`]. Unknown response fields are
//! ignored (forward tolerance), and a body that is neither a valid
//! envelope nor carries a result is a typed error, never a silent
//! empty page.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use safeguard_audit_soroban::SorobanEventsResult;

use crate::errors::{RpcError, RpcResult};

/// The hardcoded getEvents limit range, per the Stellar documentation.
pub const MIN_LIMIT: u32 = 1;
/// The hardcoded getEvents limit range, per the Stellar documentation.
pub const MAX_LIMIT: u32 = 10_000;
/// The maximum number of filters in one request, per the documentation.
pub const MAX_FILTERS: usize = 5;
/// The maximum number of contract ids in one filter, per the
/// documentation.
pub const MAX_CONTRACT_IDS_PER_FILTER: usize = 5;

/// Filter events by emission type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventTypeFilter {
    /// Contract-emitted events.
    Contract,
    /// Network-emitted (system) events.
    System,
}

/// One event filter: an emission type and/or contract ids and/or topic
/// matchers. An event matches if it matches any supplied filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFilter {
    /// Restrict to one emission type when set.
    pub filter_type: Option<EventTypeFilter>,
    /// Restrict to these contract ids (max 5). Empty means "all
    /// contracts", exactly like omitting the field.
    pub contract_ids: Vec<String>,
    /// Topic matchers: up to 5 arrays, each holding 1-4 segment
    /// matchers (a base64 ScVal, `*` for any single value, or `**` for
    /// zero or more). Empty means "all topics".
    pub topics: Vec<Vec<String>>,
}

impl EventFilter {
    /// A filter over one contract id.
    pub fn for_contract(contract_id: impl Into<String>) -> Self {
        Self {
            filter_type: Some(EventTypeFilter::Contract),
            contract_ids: vec![contract_id.into()],
            topics: Vec::new(),
        }
    }

    /// Validates the documented cardinality limits.
    pub fn validate(&self) -> RpcResult<()> {
        if self.contract_ids.len() > MAX_CONTRACT_IDS_PER_FILTER {
            return Err(RpcError::InvalidRequest(format!(
                "a filter may name at most {MAX_CONTRACT_IDS_PER_FILTER} contract ids, got {}",
                self.contract_ids.len()
            )));
        }
        if self.topics.len() > MAX_FILTERS {
            return Err(RpcError::InvalidRequest(format!(
                "a filter may carry at most {MAX_FILTERS} topic matchers, got {}",
                self.topics.len()
            )));
        }
        for (index, matchers) in self.topics.iter().enumerate() {
            if matchers.is_empty() || matchers.len() > 4 {
                return Err(RpcError::InvalidRequest(format!(
                    "topic matcher {index} must hold 1-4 segment matchers, got {}",
                    matchers.len()
                )));
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(filter_type) = self.filter_type {
            object.insert(
                "type".into(),
                Value::String(filter_type.as_str().to_owned()),
            );
        }
        if !self.contract_ids.is_empty() {
            object.insert(
                "contractIds".into(),
                Value::Array(
                    self.contract_ids
                        .iter()
                        .map(|id| Value::String(id.clone()))
                        .collect(),
                ),
            );
        }
        if !self.topics.is_empty() {
            object.insert(
                "topics".into(),
                Value::Array(
                    self.topics
                        .iter()
                        .map(|matchers| {
                            Value::Array(
                                matchers.iter().map(|m| Value::String(m.clone())).collect(),
                            )
                        })
                        .collect(),
                ),
            );
        }
        Value::Object(object)
    }
}

/// The named `getEvents` `params` object.
///
/// Field presence rules follow the documentation: a `cursor` must be
/// carried without `startLedger` or `endLedger` (the node resumes from
/// the cursor), while a fresh range request names a `startLedger` and
/// optionally an exclusive `endLedger`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEventsParams {
    start_ledger: Option<u32>,
    end_ledger: Option<u32>,
    filters: Vec<EventFilter>,
    cursor: Option<String>,
    limit: Option<u32>,
}

impl Default for GetEventsParams {
    fn default() -> Self {
        Self::new()
    }
}

impl GetEventsParams {
    /// An empty parameter set (no range, no filters).
    pub fn new() -> Self {
        Self {
            start_ledger: None,
            end_ledger: None,
            filters: Vec::new(),
            cursor: None,
            limit: None,
        }
    }

    /// Sets the inclusive start ledger (a fresh range request).
    pub fn start_ledger(mut self, ledger: u32) -> Self {
        self.start_ledger = Some(ledger);
        self
    }

    /// Sets the exclusive end ledger (a fresh range request).
    pub fn end_ledger(mut self, ledger: u32) -> Self {
        self.end_ledger = Some(ledger);
        self
    }

    /// Sets the opaque resume cursor (a continuation request).
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Sets the page limit (1-10,000; the node defaults to 100).
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Adds one event filter.
    pub fn add_filter(mut self, filter: EventFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Validates the documented parameter rules: limit within 1-10,000,
    /// no more than 5 filters, no filter over its own cardinality, a
    /// cursor that excludes both ledger bounds, and (when no cursor) a
    /// start ledger to begin from.
    pub fn validate(&self) -> RpcResult<()> {
        if let Some(limit) = self.limit {
            if !(MIN_LIMIT..=MAX_LIMIT).contains(&limit) {
                return Err(RpcError::InvalidRequest(format!(
                    "limit must be within {MIN_LIMIT}-{MAX_LIMIT}, got {limit}"
                )));
            }
        }
        if self.filters.len() > MAX_FILTERS {
            return Err(RpcError::InvalidRequest(format!(
                "at most {MAX_FILTERS} filters per request, got {}",
                self.filters.len()
            )));
        }
        for filter in &self.filters {
            filter.validate()?;
        }
        if self.cursor.is_some() {
            if self.start_ledger.is_some() || self.end_ledger.is_some() {
                return Err(RpcError::InvalidRequest(
                    "a cursor request must not carry startLedger or endLedger".into(),
                ));
            }
        } else if self.start_ledger.is_none() {
            return Err(RpcError::InvalidRequest(
                "a request needs either a cursor or a startLedger".into(),
            ));
        }
        Ok(())
    }

    /// The resume cursor, when set.
    pub fn cursor_value(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// The page limit, when set.
    pub fn limit_value(&self) -> Option<u32> {
        self.limit
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(ledger) = self.start_ledger {
            object.insert("startLedger".into(), json!(ledger));
        }
        if let Some(ledger) = self.end_ledger {
            object.insert("endLedger".into(), json!(ledger));
        }
        if !self.filters.is_empty() {
            object.insert(
                "filters".into(),
                Value::Array(self.filters.iter().map(EventFilter::to_value).collect()),
            );
        }
        // pagination is present only when it carries something.
        let mut pagination = Map::new();
        if let Some(cursor) = &self.cursor {
            pagination.insert("cursor".into(), json!(cursor));
        }
        if let Some(limit) = self.limit {
            pagination.insert("limit".into(), json!(limit));
        }
        if !pagination.is_empty() {
            object.insert("pagination".into(), Value::Object(pagination));
        }
        Value::Object(object)
    }
}

impl Serialize for GetEventsParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_value().serialize(serializer)
    }
}

impl EventTypeFilter {
    /// The wire label (`contract` or `system`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::System => "system",
        }
    }
}

/// A complete JSON-RPC `getEvents` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEventsRequest {
    /// The JSON-RPC request id (echoed by the node in its response).
    pub id: i64,
    /// The validated parameters.
    pub params: GetEventsParams,
}

impl GetEventsRequest {
    /// Builds a request.
    pub fn new(id: i64, params: GetEventsParams) -> Self {
        Self { id, params }
    }

    /// Serializes the request body (`jsonrpc` 2.0, method `getEvents`),
    /// validating the parameters first.
    pub fn body(&self) -> RpcResult<String> {
        self.params.validate()?;
        let object = json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": "getEvents",
            "params": self.params.to_value(),
        });
        serde_json::to_string(&object).map_err(|e| RpcError::Malformed(e.to_string()))
    }
}

/// The JSON-RPC error member a node returns.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcErrorBody {
    /// The JSON-RPC error code.
    pub code: i64,
    /// The node's message.
    pub message: String,
    /// Optional structured error data (absent fields stay `None`).
    pub data: Option<Value>,
}

impl From<RpcErrorBody> for RpcError {
    fn from(body: RpcErrorBody) -> Self {
        Self::Server {
            code: body.code,
            message: body.message,
        }
    }
}

/// The JSON-RPC 2.0 response envelope: exactly one of `result` or
/// `error`, plus the echoed `id` and the protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JsonRpcEnvelope<T> {
    /// The protocol version, `"2.0"` on every well-formed response.
    pub jsonrpc: String,
    /// The echoed request id, when the node returned one.
    pub id: Option<Value>,
    /// The method result, when the call succeeded (absent stays `None`).
    pub result: Option<T>,
    /// The error member, when the call failed (absent stays `None`).
    pub error: Option<RpcErrorBody>,
}

impl<T: DeserializeOwned> JsonRpcEnvelope<T> {
    /// Extracts the typed result, enforcing the envelope contract: a
    /// non-2.0 version, a present error member, or a missing result are
    /// all typed failures — never a silent empty value.
    pub fn into_result(self) -> RpcResult<T> {
        if self.jsonrpc != "2.0" {
            return Err(RpcError::Malformed(format!(
                "expected jsonrpc 2.0, got {:?}",
                self.jsonrpc
            )));
        }
        if let Some(error) = self.error {
            return Err(error.into());
        }
        self.result.ok_or_else(|| {
            RpcError::Malformed("response carried neither a result nor an error".into())
        })
    }
}

/// Parses a `getEvents` response body into its typed result.
///
/// Any HTTP transport can POST a [`GetEventsRequest`] body and hand the
/// response body to this function; nothing here performs network I/O.
pub fn parse_get_events_response(body: &str) -> RpcResult<SorobanEventsResult> {
    let envelope: JsonRpcEnvelope<SorobanEventsResult> =
        serde_json::from_str(body).map_err(|e| RpcError::Malformed(e.to_string()))?;
    envelope.into_result()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The params object from the Stellar documentation's own getEvents
    /// example request, verbatim.
    const DOC_PARAMS: &str = r#"{
        "startLedger": 199616,
        "filters": [
            {
                "type": "contract",
                "contractIds": [
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
                ],
                "topics": [
                    [
                        "AAAADwAAAAh0cmFuc2Zlcg==",
                        "*",
                        "*",
                        "**"
                    ]
                ]
            }
        ],
        "pagination": {
            "limit": 2
        }
    }"#;

    const DOC_EVENT: &str = r#"{
        "type": "contract",
        "ledger": 3727845,
        "ledgerClosedAt": "2026-07-21T18:01:10Z",
        "contractId": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        "id": "0016010972359577600-0000000001",
        "transactionIndex": 5,
        "operationIndex": 0,
        "inSuccessfulContractCall": true,
        "topic": [
            "AAAADwAAAAh0cmFuc2Zlcg==",
            "AAAAEgAAAAAAAAAAjnWZyariB+Ah9OPGy5WJe1t2Ks3gKsKGYsy7vmpJRIY=",
            "AAAAEgAAAAGu/2GlTlA4D83fxvERV0mWvvsyBPo+xfk3Guav6IgNZQ==",
            "AAAADgAAAAZuYXRpdmUAAA=="
        ],
        "value": "AAAACgAAAAAAAAAAAAAAALLQXgA=",
        "txHash": "a5c9247b77eb04c0d857934a2e988c408167976c8acbdf3d8acf64c44deb3beb"
    }"#;

    fn build_params_from_doc() -> GetEventsParams {
        GetEventsParams::new()
            .start_ledger(199_616)
            .add_filter(EventFilter {
                filter_type: Some(EventTypeFilter::Contract),
                contract_ids: vec![
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".into()
                ],
                topics: vec![vec![
                    "AAAADwAAAAh0cmFuc2Zlcg==".into(),
                    "*".into(),
                    "*".into(),
                    "**".into(),
                ]],
            })
            .limit(2)
    }

    #[test]
    fn the_documented_request_serializes_semantically_identical() {
        let params = build_params_from_doc();
        params.validate().unwrap();
        let ours = serde_json::to_value(&params).unwrap();
        let theirs: Value = serde_json::from_str(DOC_PARAMS).unwrap();
        assert_eq!(ours, theirs, "params must match the documentation example");
    }

    #[test]
    fn the_documented_request_body_is_well_formed_jsonrpc() {
        let request = GetEventsRequest::new(8_675_309, build_params_from_doc());
        let body = request.body().unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 8_675_309);
        assert_eq!(parsed["method"], "getEvents");
        assert!(parsed["params"].is_object());
    }

    #[test]
    fn cursor_and_ledger_bounds_are_mutually_exclusive() {
        let params = GetEventsParams::new()
            .start_ledger(100)
            .cursor("0016010972359577600-0000000008");
        assert!(params.validate().is_err());

        let continuation = GetEventsParams::new()
            .cursor("0016010972359577600-0000000008")
            .limit(100);
        continuation.validate().unwrap();

        let range = GetEventsParams::new().start_ledger(100).end_ledger(200);
        range.validate().unwrap();

        assert!(GetEventsParams::new().validate().is_err());
    }

    #[test]
    fn documented_response_envelope_parses_to_the_result() {
        let doc_response = format!(
            r#"{{
                "jsonrpc": "2.0",
                "id": 8675309,
                "result": {{
                    "events": [{DOC_EVENT}],
                    "latestLedger": 3730843,
                    "oldestLedger": 3609884,
                    "latestLedgerCloseTime": "1784671886",
                    "oldestLedgerCloseTime": "1784066056",
                    "cursor": "0016010972359577600-0000000008"
                }}
            }}"#
        );
        let result = parse_get_events_response(&doc_response).unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].id, "0016010972359577600-0000000001");
        assert_eq!(
            result.cursor.as_deref(),
            Some("0016010972359577600-0000000008")
        );
    }

    #[test]
    fn error_envelopes_surface_as_typed_server_errors() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "startLedger is before the oldest retained ledger"
            }
        }"#;
        match parse_get_events_response(body) {
            Err(RpcError::Server { code, message }) => {
                assert_eq!(code, -32000);
                assert!(message.contains("oldest retained ledger"));
            }
            other => panic!("expected a server error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_and_wrong_version_envelopes_are_typed_errors() {
        assert!(matches!(
            parse_get_events_response("{ nope"),
            Err(RpcError::Malformed(_))
        ));
        let wrong_version = r#"{"jsonrpc": "1.0", "id": 1, "result": {"events": []}}"#;
        assert!(matches!(
            parse_get_events_response(wrong_version),
            Err(RpcError::Malformed(_))
        ));
        let no_member = r#"{"jsonrpc": "2.0", "id": 1}"#;
        assert!(matches!(
            parse_get_events_response(no_member),
            Err(RpcError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_result_fields_are_tolerated() {
        // A node that adds result fields must not break parsing.
        let doc_response = format!(
            r#"{{
                "jsonrpc": "2.0",
                "id": 1,
                "result": {{
                    "events": [{DOC_EVENT}],
                    "someFutureField": "future"
                }}
            }}"#
        );
        let result = parse_get_events_response(&doc_response).unwrap();
        assert_eq!(result.events.len(), 1);
    }

    #[test]
    fn filter_cardinality_limits_are_enforced() {
        let mut filter = EventFilter::for_contract("C1");
        filter.contract_ids = (0..6).map(|i| format!("C{i}")).collect();
        assert!(filter.validate().is_err());

        let bad_topics = EventFilter {
            filter_type: None,
            contract_ids: vec![],
            topics: vec![vec!["*".into()]; 6],
        };
        assert!(bad_topics.validate().is_err());
    }
}
