//! The RPC error taxonomy.
//!
//! Errors are typed so an ingestion loop can react correctly: transport
//! failures (a connection dropped, a node unreachable) and generic
//! JSON-RPC server errors can clear on retry, while protocol violations,
//! malformed responses, and rejected requests are permanent and must
//! surface to the operator instead of being retried into the ground.

use thiserror::Error;

/// A failed RPC exchange or a rejected request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RpcError {
    /// The transport could not complete the exchange (connection
    /// failure, timeout, node unreachable). Potentially transient —
    /// the retry policy treats this class as retryable.
    #[error("transport failure: {0}")]
    Transport(String),

    /// The node answered with a JSON-RPC error member.
    #[error("rpc server error {code}: {message}")]
    Server {
        /// The JSON-RPC error code.
        code: i64,
        /// The node's error message.
        message: String,
    },

    /// The response violated the JSON-RPC or getEvents envelope contract
    /// (wrong protocol version, missing result and error, undecodable
    /// body). Retrying cannot fix a malformed response.
    #[error("malformed rpc response: {0}")]
    Malformed(String),

    /// The request itself was rejected by local validation (an
    /// incoherent combination of parameters, an out-of-range limit).
    #[error("invalid rpc request: {0}")]
    InvalidRequest(String),
}

/// Whether `error` is worth retrying.
///
/// Retryable classes are the ones that can plausibly clear on their own:
/// transport hiccups, and the JSON-RPC reserved server-error range
/// (`-32000..=-32099`), which Soroban RPC uses for node-side failures.
/// Protocol violations, malformed responses, and locally-rejected
/// requests are permanent and must not be retried.
pub fn is_retryable(error: &RpcError) -> bool {
    match error {
        RpcError::Transport(_) => true,
        RpcError::Server { code, .. } => (-32_099..=-32_000).contains(code),
        RpcError::Malformed(_) | RpcError::InvalidRequest(_) => false,
    }
}

/// A result alias for RPC operations.
pub type RpcResult<T> = Result<T, RpcError>;
