//! The verified wire shape of Soroban RPC events.
//!
//! These types mirror the Stellar RPC `getEvents` response envelope as
//! defined by the current Stellar documentation (verified against the
//! API reference, July 2026): a result carries the events plus the
//! RPC's retention window and an opaque paging cursor, and each event
//! names its emission type, ledger, close time, emitting contract, a
//! TOID-based dedup id, transaction/operation position, topics, value,
//! and transaction hash.
//!
//! Serialization is deliberately tolerant in the *forward* direction:
//! unknown fields on the wire are ignored, so a node that adds fields
//! does not break ingestion. Fields this crate does not understand are
//! never silently *mis*understood — ScVal topics and values stay opaque
//! base64 strings, and their meaning is the contract's, not this
//! crate's.

use serde::{Deserialize, Serialize};

/// The `type` of an event emission as Stellar RPC reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SorobanEventType {
    /// Emitted by a contract during a successful call.
    Contract,
    /// Emitted by the network itself (system events).
    System,
}

impl SorobanEventType {
    /// The wire label (`contract` or `system`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::System => "system",
        }
    }
}

impl std::fmt::Display for SorobanEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One contract or system event as `getEvents` returns it.
///
/// Topics and the value are base64-encoded ScVals and are carried
/// verbatim: decoding and interpreting them belongs to the contract
/// surface this deployment verifies, never to the wire model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SorobanEvent {
    /// The wire `type` field: `contract` or `system`.
    #[serde(rename = "type")]
    pub event_type: SorobanEventType,
    /// Sequence number of the ledger the event was emitted in.
    pub ledger: i64,
    /// ISO-8601 close time of that ledger, when the node reports it.
    pub ledger_closed_at: Option<String>,
    /// StrKey contract address that emitted the event (system events may
    /// name no contract).
    pub contract_id: Option<String>,
    /// The event's unique id, in TOID form: a 19-character TOID and a
    /// 10-character zero-padded event index separated by a hyphen. This
    /// is the dedup key the ingestion layer uses — never arrival time.
    pub id: String,
    /// Index of the transaction within the ledger, when reported.
    pub transaction_index: Option<u32>,
    /// Index of the operation within the transaction, when reported.
    pub operation_index: Option<u32>,
    /// Whether the event was emitted during a successful contract call.
    /// Deprecated by Stellar; retained for forward compatibility.
    pub in_successful_contract_call: Option<bool>,
    /// The event's topic segments: 1-4 base64-encoded ScVals.
    pub topic: Vec<String>,
    /// The data the event emitted (a base64-encoded ScVal), when present.
    pub value: Option<String>,
    /// The 64-lowercase-hex transaction hash that triggered the event.
    pub tx_hash: Option<String>,
}

/// The full `getEvents` result: the events of one page plus the RPC's
/// reported retention window and the opaque cursor for the next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SorobanEventsResult {
    /// The events on this page.
    pub events: Vec<SorobanEvent>,
    /// Opaque paging token: include it in the next request to obtain the
    /// page occurring after this one.
    pub cursor: Option<String>,
    /// Latest ledger the RPC node knew about when it handled the request.
    pub latest_ledger: Option<i64>,
    /// Oldest ledger the RPC node still retains.
    pub oldest_ledger: Option<i64>,
    /// Close time (unix, as a string) of the latest retained ledger.
    pub latest_ledger_close_time: Option<String>,
    /// Close time (unix, as a string) of the oldest retained ledger.
    pub oldest_ledger_close_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One event from the Stellar documentation's own `getEvents`
    /// example, verbatim.
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

    #[test]
    fn the_documented_event_shape_deserializes_verbatim() {
        let event: SorobanEvent = serde_json::from_str(DOC_EVENT).unwrap();
        assert_eq!(event.event_type, SorobanEventType::Contract);
        assert_eq!(event.ledger, 3727845);
        assert_eq!(
            event.ledger_closed_at.as_deref(),
            Some("2026-07-21T18:01:10Z")
        );
        assert_eq!(
            event.contract_id.as_deref(),
            Some("CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC")
        );
        // The TOID-index id is the dedup key.
        assert_eq!(event.id, "0016010972359577600-0000000001");
        assert_eq!(event.transaction_index, Some(5));
        assert_eq!(event.operation_index, Some(0));
        assert_eq!(event.in_successful_contract_call, Some(true));
        // Topics are opaque base64 ScVals, carried verbatim.
        assert_eq!(event.topic.len(), 4);
        assert_eq!(event.topic[0], "AAAADwAAAAh0cmFuc2Zlcg==");
        assert_eq!(event.value.as_deref(), Some("AAAACgAAAAAAAAAAAAAAALLQXgA="));
        assert_eq!(
            event.tx_hash.as_deref(),
            Some("a5c9247b77eb04c0d857934a2e988c408167976c8acbdf3d8acf64c44deb3beb")
        );
    }

    #[test]
    fn serialization_round_trips_the_wire_labels() {
        let event: SorobanEvent = serde_json::from_str(DOC_EVENT).unwrap();
        let json = serde_json::to_string(&event).unwrap();
        let back: SorobanEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
        // Field names and labels stay in the shape the node expects.
        assert!(json.contains("\"type\":\"contract\""));
        assert!(json.contains("\"contractId\":"));
        assert!(json.contains("\"txHash\":"));
    }

    #[test]
    fn unknown_wire_fields_do_not_break_ingestion() {
        // A node that adds fields must not wedge the ingestion door;
        // unknown fields are ignored, known ones still parse.
        let extended = DOC_EVENT.replace(
            "\"txHash\":",
            "\"someFutureField\": \"future\", \"txHash\":",
        );
        let event: SorobanEvent = serde_json::from_str(&extended).unwrap();
        assert_eq!(event.id, "0016010972359577600-0000000001");
        assert_eq!(event.topic.len(), 4);
    }

    #[test]
    fn the_result_page_carries_events_and_the_paging_cursor() {
        let result: SorobanEventsResult = serde_json::from_str(
            r#"{
                "events": [
                    {
                        "type": "system",
                        "ledger": 3727845,
                        "id": "0016010972359577600-0000000000",
                        "topic": ["AAAADgAAAAhzb21ldGhpbmc="]
                    }
                ],
                "latestLedger": 3730843,
                "oldestLedger": 3609884,
                "latestLedgerCloseTime": "1784671886",
                "oldestLedgerCloseTime": "1784066056",
                "cursor": "0016010972359577600-0000000008"
            }"#,
        )
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_type, SorobanEventType::System);
        // System events may name no contract and carry no value.
        assert_eq!(result.events[0].contract_id, None);
        assert_eq!(result.events[0].value, None);
        assert_eq!(result.latest_ledger, Some(3730843));
        assert_eq!(result.oldest_ledger, Some(3609884));
        assert_eq!(
            result.cursor.as_deref(),
            Some("0016010972359577600-0000000008")
        );
    }

    #[test]
    fn event_type_labels_are_stable() {
        assert_eq!(SorobanEventType::Contract.as_str(), "contract");
        assert_eq!(SorobanEventType::System.as_str(), "system");
        assert_eq!(
            serde_json::to_string(&SorobanEventType::System).unwrap(),
            "\"system\""
        );
    }
}
