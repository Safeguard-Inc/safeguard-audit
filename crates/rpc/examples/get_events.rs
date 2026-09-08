//! Demonstrates the `getEvents` protocol surface without any network I/O.
//!
//! Run it in one of two modes:
//!
//! ```sh
//! # 1. Build a documented getEvents request and print its JSON-RPC body.
//! cargo run --example get_events -- build
//!
//! # 2. Parse a response body read from stdin and summarize the page.
//! echo '{...}' | cargo run --example get_events -- parse
//! ```
//!
//! A real ingestion loop pairs these two halves: serialize a request with
//! [`GetEventsRequest::body`], POST it to an RPC node over whatever HTTP
//! transport the deployment uses, and hand the response body to
//! [`parse_get_events_response`]. This crate performs no network I/O by
//! design; see `crates/rpc` and `docs/rpc.md`.

use safeguard_audit_rpc::{
    parse_get_events_response, EventFilter, EventTypeFilter, GetEventsParams,
};

/// The example request params from the Stellar getEvents documentation,
/// mirrored here so the demo needs no input to show request building.
fn documented_params() -> GetEventsParams {
    GetEventsParams::new()
        .start_ledger(199_616)
        .add_filter(EventFilter {
            filter_type: Some(EventTypeFilter::Contract),
            contract_ids: vec!["CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".into()],
            topics: vec![vec![
                "AAAADwAAAAh0cmFuc2Zlcg==".into(),
                "*".into(),
                "*".into(),
                "**".into(),
            ]],
        })
        .limit(2)
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => {
            let request =
                safeguard_audit_rpc::GetEventsRequest::new(8_675_309, documented_params());
            match request.body() {
                Ok(body) => println!("{body}"),
                Err(e) => {
                    eprintln!("request rejected: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("parse") => {
            use std::io::Read;
            let mut body = String::new();
            if std::io::stdin().read_to_string(&mut body).is_err() {
                eprintln!("could not read the response body from stdin");
                std::process::exit(1);
            }
            match parse_get_events_response(&body) {
                Ok(result) => {
                    println!("parsed {} event(s)", result.events.len());
                    for event in &result.events {
                        println!(
                            "  id={} ledger={} contract={}",
                            event.id,
                            event.ledger,
                            event.contract_id.as_deref().unwrap_or("-")
                        );
                    }
                    println!("cursor: {}", result.cursor.as_deref().unwrap_or("-"));
                    println!(
                        "ledger range: {}..{}",
                        result.oldest_ledger.unwrap_or(0),
                        result.latest_ledger.unwrap_or(0)
                    );
                }
                Err(e) => {
                    eprintln!("response rejected: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("usage: get_events <build|parse>  (got {other:?})");
            std::process::exit(2);
        }
    }
}
