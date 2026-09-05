//! The retry and timeout policy ingestion loops run under.
//!
//! An RPC feed is a live dependency: nodes are occasionally unreachable
//! and occasionally answer with a server error that clears moments
//! later. Blindly failing the whole ingestion pass on the first hiccup
//! is wrong, and so is retrying forever with no bound. This module
//! provides the policy (how many attempts, how long to wait between
//! them, how long one attempt may take) and the executor shape that
//! applies it to a typed `get_events` attempt, so a caller's transport
//! stays pluggable while the retry behavior stays uniform.

use std::thread;
use std::time::Duration;

use safeguard_audit_soroban::SorobanEventsResult;

use crate::errors::{is_retryable, RpcError, RpcResult};

/// How many times to attempt a call and how to space the attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts (the first call plus retries). Must be >= 1.
    pub max_attempts: u32,
    /// Delay before the first retry; each further retry doubles it.
    pub base_delay: Duration,
    /// Upper bound on any single delay.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    /// Builds a policy, rejecting incoherent configurations.
    pub fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> RpcResult<Self> {
        if max_attempts == 0 {
            return Err(RpcError::InvalidRequest(
                "max_attempts must be at least 1".into(),
            ));
        }
        if max_delay < base_delay {
            return Err(RpcError::InvalidRequest(
                "max_delay must not be smaller than base_delay".into(),
            ));
        }
        Ok(Self {
            max_attempts,
            base_delay,
            max_delay,
        })
    }

    /// The delay to wait before retry `retry_number` (1 = the first
    /// retry): exponential backoff from `base_delay`, capped at
    /// `max_delay`.
    pub fn backoff(&self, retry_number: u32) -> Duration {
        let exponent = retry_number.saturating_sub(1).min(16);
        self.base_delay
            .saturating_mul(1u32 << exponent)
            .min(self.max_delay)
    }
}

/// The full call policy: how long one attempt may take plus how many
/// attempts to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcPolicy {
    /// Upper bound on one attempt, applied by the transport (per-attempt
    /// timeouts live with the code that actually waits on the node).
    pub attempt_timeout: Duration,
    /// The retry policy.
    pub retry: RetryPolicy,
}

impl Default for RpcPolicy {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(30),
            retry: RetryPolicy::default(),
        }
    }
}

/// Runs `attempt` under `policy`, retrying retryable failures with
/// capped exponential backoff up to `max_attempts` total calls.
///
/// Permanent failures (protocol violations, malformed responses,
/// rejected requests) return immediately without retrying. After the
/// final attempt, the last error is returned as-is.
pub fn fetch_with_retry<F>(policy: &RetryPolicy, mut attempt: F) -> RpcResult<SorobanEventsResult>
where
    F: FnMut() -> RpcResult<SorobanEventsResult>,
{
    for attempt_number in 1..=policy.max_attempts {
        match attempt() {
            Ok(page) => return Ok(page),
            Err(error) => {
                let retryable = is_retryable(&error);
                if retryable && attempt_number < policy.max_attempts {
                    thread::sleep(policy.backoff(attempt_number));
                    continue;
                }
                return Err(error);
            }
        }
    }
    Err(RpcError::Transport(
        "retry policy exhausted without an attempt".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soroban_result() -> SorobanEventsResult {
        SorobanEventsResult {
            events: Vec::new(),
            cursor: None,
            latest_ledger: None,
            oldest_ledger: None,
            latest_ledger_close_time: None,
            oldest_ledger_close_time: None,
        }
    }

    #[test]
    fn transient_failures_recover_within_budget() {
        // Fail twice with transport errors, succeed on the third try.
        let mut calls = 0;
        let policy = RetryPolicy::new(5, Duration::ZERO, Duration::ZERO).unwrap();
        let out = fetch_with_retry(&policy, || {
            calls += 1;
            if calls < 3 {
                Err(RpcError::Transport("node unreachable".into()))
            } else {
                Ok(soroban_result())
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(out.events.len(), 0);
    }

    #[test]
    fn permanent_errors_are_not_retried() {
        let mut calls = 0;
        let policy = RetryPolicy::new(5, Duration::ZERO, Duration::ZERO).unwrap();
        let err = fetch_with_retry(&policy, || {
            calls += 1;
            Err(RpcError::InvalidRequest("bad params".into()))
        })
        .unwrap_err();
        assert_eq!(calls, 1, "a rejected request must not be retried");
        assert!(matches!(err, RpcError::InvalidRequest(_)));
    }

    #[test]
    fn attempts_are_bounded_and_the_last_error_is_returned() {
        let mut calls = 0;
        let policy = RetryPolicy::new(3, Duration::ZERO, Duration::ZERO).unwrap();
        let err = fetch_with_retry(&policy, || {
            calls += 1;
            Err(RpcError::Server {
                code: -32000,
                message: "node hiccup".into(),
            })
        })
        .unwrap_err();
        assert_eq!(calls, 3);
        assert!(matches!(err, RpcError::Server { code: -32000, .. }));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy = RetryPolicy::new(10, Duration::from_secs(1), Duration::from_secs(8)).unwrap();
        assert_eq!(policy.backoff(1), Duration::from_secs(1));
        assert_eq!(policy.backoff(2), Duration::from_secs(2));
        assert_eq!(policy.backoff(3), Duration::from_secs(4));
        assert_eq!(policy.backoff(4), Duration::from_secs(8));
        assert_eq!(policy.backoff(9), Duration::from_secs(8), "capped");
    }

    #[test]
    fn incoherent_policies_are_rejected() {
        assert!(RetryPolicy::new(0, Duration::ZERO, Duration::ZERO).is_err());
        assert!(RetryPolicy::new(3, Duration::from_secs(5), Duration::from_secs(1)).is_err());
    }
}
