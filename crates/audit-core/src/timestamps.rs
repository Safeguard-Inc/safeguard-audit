//! Time model for the audit domain.
//!
//! All timestamps are **UTC Unix seconds** (`i64`), which is exactly the
//! shape Stellar/Soroban ledger metadata uses (`close_time` is Unix
//! seconds), so ledger timestamps never need conversion before they enter a
//! record. Human-readable RFC 3339 rendering is derived on demand.
//!
//! ## Determinism
//!
//! Wall-clock time must never enter the *identity* of a record — identities
//! derive from event content. Times that must be reproducible (report
//! generation, evidence generation) are stamped through a [`Clock`], so
//! tests and replay can substitute a [`FixedClock`] and reproduce byte
//! for byte the output a real run would produce.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::errors::{AuditError, AuditResult};

/// A UTC timestamp expressed as Unix seconds.
///
/// Construction is infallible for any `i64` (it is just seconds), matching
/// ledger metadata; range errors surface only when converting to a bounded
/// representation such as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Wraps raw Unix seconds.
    pub fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// The Unix seconds value.
    pub fn as_unix_seconds(&self) -> i64 {
        self.0
    }

    /// The current time according to `clock`.
    pub fn now(clock: &dyn Clock) -> Self {
        clock.now()
    }

    /// Renders this timestamp as an RFC 3339 UTC string (`...Z`), or an
    /// error when the value is outside the years 0000-9999 representable in
    /// that format.
    pub fn to_rfc3339(&self) -> AuditResult<String> {
        let (y, mo, d, h, mi, s) = unix_to_civil(self.0);
        if !(0..=9999).contains(&y) {
            return Err(AuditError::InvalidTimestamp(format!(
                "{} seconds is outside the RFC 3339 year range",
                self.0
            )));
        }
        Ok(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"))
    }

    /// Whether `self` is on or after `other`.
    pub fn is_at_or_after(&self, other: Timestamp) -> bool {
        self.0 >= other.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_rfc3339() {
            Ok(s) => f.write_str(&s),
            Err(_) => write!(f, "unix:{}", self.0),
        }
    }
}

/// Converts Unix seconds to civil (year, month, day, hour, minute, second)
/// in UTC using the days-from-civil algorithm (Howard Hinnant).
fn unix_to_civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let h = rem / 3_600;
    let mi = (rem % 3_600) / 60;
    let s = rem % 60;
    (y, mo, d, h as u32, mi as u32, s as u32)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Source of "now". Injection keeps generation reproducible.
pub trait Clock {
    /// The current time in UTC Unix seconds.
    fn now(&self) -> Timestamp;
}

/// The real wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Timestamp::from_unix_seconds(secs)
    }
}

/// A clock pinned to a fixed instant — for tests, replay, and determinism.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now: Timestamp,
}

impl FixedClock {
    /// A clock that always reports `now`.
    pub fn at(now: Timestamp) -> Self {
        Self { now }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.now
    }
}

/// A half-open-or-closed query range over [`Timestamp`]s.
///
/// Both bounds are inclusive and optional: a `None` bound is unbounded on
/// that side. Construction validates that `start <= end` when both exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    start: Option<Timestamp>,
    end: Option<Timestamp>,
}

impl TimeRange {
    /// The unbounded range.
    pub fn all() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    /// Builds a range, rejecting `start > end`.
    pub fn new(start: Option<Timestamp>, end: Option<Timestamp>) -> AuditResult<Self> {
        if let (Some(a), Some(b)) = (start, end) {
            if a > b {
                return Err(AuditError::InvalidTimestamp(format!(
                    "range start {} is after range end {}",
                    a.as_unix_seconds(),
                    b.as_unix_seconds()
                )));
            }
        }
        Ok(Self { start, end })
    }

    /// A single-instant range.
    pub fn at(instant: Timestamp) -> Self {
        Self {
            start: Some(instant),
            end: Some(instant),
        }
    }

    /// The inclusive start, if bounded.
    pub fn start(&self) -> Option<Timestamp> {
        self.start
    }

    /// The inclusive end, if bounded.
    pub fn end(&self) -> Option<Timestamp> {
        self.end
    }

    /// Whether `t` falls inside the range.
    pub fn contains(&self, t: Timestamp) -> bool {
        self.start.is_none_or(|s| t >= s) && self.end.is_none_or(|e| t <= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seconds between the Unix epoch and year 0, used to bound RFC 3339 output.
    const YEAR_ZERO_UNIX: i64 = -62_167_219_200;

    #[test]
    fn epoch_renders_as_rfc3339() {
        assert_eq!(
            Timestamp::from_unix_seconds(0).to_rfc3339().unwrap(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn leap_day_renders_correctly() {
        // 2000-02-29T00:00:00Z — exercises the 400-year leap rule.
        assert_eq!(
            Timestamp::from_unix_seconds(951_782_400)
                .to_rfc3339()
                .unwrap(),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn known_instants_round_trip() {
        let cases = [
            (1_609_459_200i64, "2021-01-01T00:00:00Z"),
            (1_704_067_200, "2024-01-01T00:00:00Z"),
            (1_752_825_600, "2025-07-18T08:00:00Z"),
            (1_234_567_890, "2009-02-13T23:31:30Z"),
            (1_700_000_000, "2023-11-14T22:13:20Z"),
        ];
        for (secs, expect) in cases {
            assert_eq!(
                Timestamp::from_unix_seconds(secs).to_rfc3339().unwrap(),
                expect
            );
        }
    }

    #[test]
    fn time_of_day_is_split_correctly() {
        let t = Timestamp::from_unix_seconds(1_700_000_123);
        // 2023-11-14T22:15:23Z
        assert_eq!(t.to_rfc3339().unwrap(), "2023-11-14T22:15:23Z");
    }

    #[test]
    fn rfc3339_year_range_is_enforced() {
        assert!(Timestamp::from_unix_seconds(YEAR_ZERO_UNIX - 1)
            .to_rfc3339()
            .is_err());
        assert!(Timestamp::from_unix_seconds(YEAR_ZERO_UNIX)
            .to_rfc3339()
            .is_ok());
        // Years far in the future also error.
        assert!(Timestamp::from_unix_seconds(100_000 * 365 * 86_400)
            .to_rfc3339()
            .is_err());
    }

    #[test]
    fn fixed_clock_reports_its_instant() {
        let at = Timestamp::from_unix_seconds(1_700_000_000);
        let clock = FixedClock::at(at);
        assert_eq!(Timestamp::now(&clock), at);
        let _ = SystemClock;
    }

    #[test]
    fn system_clock_is_sane() {
        let now = SystemClock.now().as_unix_seconds();
        // Must be after 2020-01-01 and before year 2100.
        assert!(now > 1_577_836_800 && now < 4_102_444_800);
    }

    #[test]
    fn ranges_validate_and_test_membership() {
        let t0 = Timestamp::from_unix_seconds(100);
        let t1 = Timestamp::from_unix_seconds(200);
        let t2 = Timestamp::from_unix_seconds(300);

        assert!(TimeRange::new(Some(t1), Some(t0)).is_err());

        let bounded = TimeRange::new(Some(t0), Some(t2)).unwrap();
        assert!(
            bounded.contains(t0)
                && bounded.contains(t2)
                && !bounded.contains(Timestamp::from_unix_seconds(301))
        );

        let open = TimeRange::new(Some(t1), None).unwrap();
        assert!(!open.contains(t0) && open.contains(t2));

        assert!(TimeRange::all().contains(t0));
        assert!(TimeRange::at(t1).contains(t1) && !TimeRange::at(t1).contains(t0));
    }

    #[test]
    fn ordering_helpers() {
        let a = Timestamp::from_unix_seconds(1);
        let b = Timestamp::from_unix_seconds(2);
        assert!(b.is_at_or_after(a));
        assert!(a.is_at_or_after(a));
        assert!(!a.is_at_or_after(b));
    }
}
