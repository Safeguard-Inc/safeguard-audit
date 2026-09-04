//! Deterministic ordering rules for indexed events.
//!
//! Audit history must be reproducible in the same order no matter how the
//! indexer happened to fetch it. Ordering follows the on-chain hierarchy —
//! ledger sequence, then operation index, then event index — never local
//! arrival time. When a component of the hierarchy is unknown, that
//! position is treated as *later than any known position*: known-placement
//! events sort deterministically first, and events with unknown placement
//! sort after them in an explicitly labelled uncertainty band.
//!
//! The comparison is total over the ordering metadata the normalized
//! envelope carries, so a page can be checked for monotonicity before it
//! is committed, and replay reproduces the exact same sequence.

use std::cmp::Ordering;

use safeguard_audit_core::EventOrder;

/// A total, deterministic ordering over event placement metadata.
///
/// Comparison is lexicographic over `(ledger_sequence, operation_index,
/// event_index)`; a missing component is `None` and orders *after* any
/// present value. Two placements that compare equal are the same event
/// position (same ledger/op/event) and must not both appear in one
/// history unless they are the same event.
pub fn compare_order(a: &EventOrder, b: &EventOrder) -> Ordering {
    opt_cmp(a.ledger_sequence, b.ledger_sequence)
        .then_with(|| opt_cmp(a.operation_index, b.operation_index))
        .then_with(|| opt_cmp(a.event_index, b.event_index))
}

/// Compares `Option<Ord>` treating `None` as greater than any value.
fn opt_cmp<T: Ord>(a: Option<T>, b: Option<T>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Verifies that a slice of placement metadata is in non-decreasing
/// deterministic order (allowing equal adjacent positions only when the
/// caller has already deduplicated, so pages must actually be strictly
/// increasing).
///
/// The indexer calls this on the events of one page before committing so
/// a misbehaving source can never scramble history.
pub fn is_strictly_increasing(order: &[EventOrder]) -> bool {
    order
        .windows(2)
        .all(|pair| compare_order(&pair[0], &pair[1]) == Ordering::Less)
}

/// Explains where in the ordering hierarchy two placements diverge, for
/// operator diagnostics.
pub fn describe_difference(a: &EventOrder, b: &EventOrder) -> String {
    match compare_order(a, b) {
        Ordering::Equal => "same placement".to_owned(),
        Ordering::Less => {
            if a.ledger_sequence != b.ledger_sequence {
                format!(
                    "ledger {:?} precedes ledger {:?}",
                    a.ledger_sequence, b.ledger_sequence
                )
            } else if a.operation_index != b.operation_index {
                format!(
                    "operation {:?} precedes operation {:?}",
                    a.operation_index, b.operation_index
                )
            } else {
                format!(
                    "event {:?} precedes event {:?}",
                    a.event_index, b.event_index
                )
            }
        }
        Ordering::Greater => describe_difference(b, a).replace("precedes", "follows"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(ledger: Option<i64>, op: Option<u32>, ev: Option<u32>) -> EventOrder {
        EventOrder {
            ledger_sequence: ledger,
            transaction_position: None,
            operation_index: op,
            event_index: ev,
        }
    }

    #[test]
    fn ordering_is_lexicographic_by_ledger_then_op_then_event() {
        let a = order(Some(100), Some(0), Some(0));
        let b = order(Some(100), Some(0), Some(1));
        let c = order(Some(100), Some(1), Some(0));
        let d = order(Some(101), Some(0), Some(0));
        assert_eq!(compare_order(&a, &b), Ordering::Less);
        assert_eq!(compare_order(&b, &c), Ordering::Less);
        assert_eq!(compare_order(&c, &d), Ordering::Less);
        assert_eq!(compare_order(&a, &a), Ordering::Equal);
    }

    #[test]
    fn unknown_placement_sorts_after_known_placement() {
        let known = order(Some(100), Some(0), Some(0));
        let unknown = order(None, None, None);
        assert_eq!(compare_order(&known, &unknown), Ordering::Less);
        assert_eq!(compare_order(&unknown, &known), Ordering::Greater);
        // Unknown-vs-unknown is equal (an explicit uncertainty band).
        assert_eq!(compare_order(&unknown, &unknown), Ordering::Equal);
    }

    #[test]
    fn partially_unknown_placement_still_orders_deterministically() {
        // Same ledger and operation, but one placement names its event
        // index and the other does not: the unindexed event sorts after
        // (its position inside the operation is unknown).
        let op_known = order(Some(100), Some(2), None);
        let ev_known = order(Some(100), Some(2), Some(0));
        assert_eq!(compare_order(&ev_known, &op_known), Ordering::Less);
        assert_eq!(compare_order(&op_known, &ev_known), Ordering::Greater);
    }

    #[test]
    fn strictly_increasing_detects_out_of_order_pages() {
        let seq = vec![
            order(Some(1), Some(0), Some(0)),
            order(Some(1), Some(1), Some(0)),
            order(Some(2), Some(0), Some(0)),
        ];
        assert!(is_strictly_increasing(&seq));
        let scrambled = vec![
            order(Some(2), Some(0), Some(0)),
            order(Some(1), Some(0), Some(0)),
        ];
        assert!(!is_strictly_increasing(&scrambled));
        let duplicated = vec![
            order(Some(1), Some(0), Some(0)),
            order(Some(1), Some(0), Some(0)),
        ];
        assert!(!is_strictly_increasing(&duplicated));
    }

    #[test]
    fn difference_descriptions_name_the_divergence() {
        let a = order(Some(1), Some(0), Some(0));
        let b = order(Some(2), Some(0), Some(0));
        assert!(describe_difference(&a, &b).contains("ledger"));
    }
}
