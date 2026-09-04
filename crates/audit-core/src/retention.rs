//! Retention models.
//!
//! Audit history is evidence; destroying it is destructive and must never
//! be the default. Retention policy therefore answers *eligibility*
//! questions — when a record may be archived, and (only when a policy
//! explicitly opts in) when it may be destroyed — while holds (legal,
//! investigation) always override elapsed-time eligibility.
//!
//! This module holds the model and the pure eligibility evaluation. It
//! performs no deletion and touches no storage; retention *enforcement* is
//! a store/operator concern built on top of these answers.

use serde::{Deserialize, Serialize};

use crate::identifiers::CaseId;
use crate::timestamps::Timestamp;

/// How long a record is retained before archival/destruction eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPeriod {
    /// Retain forever (the default for audit evidence).
    Indefinite,
    /// Retain for a fixed number of days from recording.
    Days(u64),
}

impl RetentionPeriod {
    /// The stable label for this period.
    pub fn as_str(&self) -> String {
        match self {
            Self::Indefinite => "indefinite".to_owned(),
            Self::Days(n) => format!("days:{n}"),
        }
    }

    /// Whether retention is unlimited.
    pub fn is_indefinite(&self) -> bool {
        matches!(self, Self::Indefinite)
    }
}

/// The retention configuration attached to a record, range, or store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// How long content is retained.
    retention: RetentionPeriod,
    /// Whether the content has been moved to archival storage.
    archived: bool,
    /// A legal hold forbids archival and deletion.
    legal_hold: bool,
    /// An open investigation forbids archival and deletion of its records.
    investigation_case: Option<CaseId>,
    /// Whether deletion is ever permitted. Defaults to `false`: audit
    /// evidence is not destroyed unless a policy explicitly says so.
    deletion_allowed: bool,
}

impl RetentionPolicy {
    /// The default: indefinite retention, no holds, deletion forbidden.
    pub fn default_evidence() -> Self {
        Self {
            retention: RetentionPeriod::Indefinite,
            archived: false,
            legal_hold: false,
            investigation_case: None,
            deletion_allowed: false,
        }
    }

    /// A fixed-duration policy with deletion still forbidden.
    pub fn for_days(days: u64) -> Self {
        Self {
            retention: RetentionPeriod::Days(days),
            ..Self::default_evidence()
        }
    }

    /// Places a legal hold.
    pub fn with_legal_hold(mut self) -> Self {
        self.legal_hold = true;
        self
    }

    /// Attaches an investigation hold.
    pub fn with_investigation(mut self, case: CaseId) -> Self {
        self.investigation_case = Some(case);
        self
    }

    /// Explicitly permits deletion once eligibility is reached. This is the
    /// only way `eligible_for_deletion` can ever become true.
    pub fn with_deletion_allowed(mut self) -> Self {
        self.deletion_allowed = true;
        self
    }

    /// The retention period.
    pub fn retention(&self) -> RetentionPeriod {
        self.retention
    }

    /// Whether a legal hold is in force.
    pub fn legal_hold(&self) -> bool {
        self.legal_hold
    }

    /// Whether deletion is permitted at all.
    pub fn deletion_allowed(&self) -> bool {
        self.deletion_allowed
    }
}

/// The eligibility state of a record under a policy at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionStatus {
    /// Whether the retention period has fully elapsed.
    period_elapsed: bool,
    /// Whether the content may move to archival storage now.
    eligible_for_archival: bool,
    /// Whether the content may be destroyed now. Only true when the policy
    /// explicitly allows deletion *and* no hold applies.
    eligible_for_deletion: bool,
    /// Human-readable reasons for any hold in force.
    holds: Vec<String>,
}

impl RetentionStatus {
    /// Evaluates `policy` for content recorded at `recorded_at`, as of
    /// `now`.
    ///
    /// Holds always win: a legal or investigation hold suppresses both
    /// archival and deletion eligibility regardless of elapsed time.
    pub fn evaluate(policy: &RetentionPolicy, recorded_at: Timestamp, now: Timestamp) -> Self {
        let period_elapsed = match policy.retention {
            RetentionPeriod::Indefinite => false,
            RetentionPeriod::Days(days) => {
                let elapsed = now
                    .as_unix_seconds()
                    .saturating_sub(recorded_at.as_unix_seconds());
                elapsed >= days as i64 * 86_400
            }
        };

        let mut holds = Vec::new();
        if policy.legal_hold {
            holds.push("legal-hold".to_owned());
        }
        if let Some(case) = &policy.investigation_case {
            holds.push(format!("investigation:{case}"));
        }
        let held = !holds.is_empty();

        let eligible_for_archival = period_elapsed && !held;
        let eligible_for_deletion = policy.deletion_allowed && period_elapsed && !held;

        Self {
            period_elapsed,
            eligible_for_archival,
            eligible_for_deletion,
            holds,
        }
    }

    /// Whether the retention period has elapsed.
    pub fn period_elapsed(&self) -> bool {
        self.period_elapsed
    }

    /// Whether archival is permitted now.
    pub fn eligible_for_archival(&self) -> bool {
        self.eligible_for_archival
    }

    /// Whether destruction is permitted now (rare by design).
    pub fn eligible_for_deletion(&self) -> bool {
        self.eligible_for_deletion
    }

    /// The holds currently in force.
    pub fn holds(&self) -> &[String] {
        &self.holds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(day_offset: i64) -> Timestamp {
        Timestamp::from_unix_seconds(1_700_000_000 + day_offset * 86_400)
    }

    #[test]
    fn indefinite_retention_never_elapses() {
        let policy = RetentionPolicy::default_evidence();
        let status = RetentionStatus::evaluate(&policy, ts(0), ts(1_000_000));
        assert!(!status.period_elapsed());
        assert!(!status.eligible_for_archival());
        assert!(!status.eligible_for_deletion());
        assert_eq!(policy.retention().as_str(), "indefinite");
    }

    #[test]
    fn day_policies_elapse_after_the_period() {
        let policy = RetentionPolicy::for_days(30);
        assert_eq!(policy.retention().as_str(), "days:30");
        assert!(!RetentionStatus::evaluate(&policy, ts(0), ts(29)).period_elapsed());
        assert!(RetentionStatus::evaluate(&policy, ts(0), ts(30)).period_elapsed());
        assert!(RetentionStatus::evaluate(&policy, ts(0), ts(30)).eligible_for_archival());
        // Deletion stays forbidden without the explicit opt-in.
        assert!(!RetentionStatus::evaluate(&policy, ts(0), ts(100)).eligible_for_deletion());
    }

    #[test]
    fn deletion_requires_the_explicit_opt_in() {
        let policy = RetentionPolicy::for_days(1).with_deletion_allowed();
        let status = RetentionStatus::evaluate(&policy, ts(0), ts(10));
        assert!(status.eligible_for_deletion());
        assert!(status.eligible_for_archival());
    }

    #[test]
    fn holds_always_win() {
        let mut policy = RetentionPolicy::for_days(1).with_deletion_allowed();
        policy = policy.with_legal_hold();
        let status = RetentionStatus::evaluate(&policy, ts(0), ts(100));
        assert!(status.period_elapsed());
        assert!(!status.eligible_for_archival());
        assert!(!status.eligible_for_deletion());
        assert!(status.holds().contains(&"legal-hold".to_owned()));

        let case = RetentionPolicy::for_days(1).with_investigation(CaseId::derive(&["c9"]));
        let held = RetentionStatus::evaluate(&case, ts(0), ts(100));
        assert!(!held.eligible_for_deletion());
        assert_eq!(held.holds().len(), 1);
    }

    #[test]
    fn period_labels_are_stable() {
        assert_eq!(RetentionPeriod::Indefinite.as_str(), "indefinite");
        assert_eq!(RetentionPeriod::Days(7).as_str(), "days:7");
        assert!(RetentionPeriod::Indefinite.is_indefinite());
        assert!(!RetentionPeriod::Days(7).is_indefinite());
    }
}
