//! Rekey policy. Sessions derive a fresh set of transport keys after a
//! fixed wall-clock interval so a compromised long-lived key cannot
//! decrypt traffic indefinitely.
//!
//! The policy is time-based for now. A packet-count trigger (e.g. after
//! 2^32 packets) may be added once the wire format settles.

/// Hard-coded rekey interval from `IMPLEMENTATION.md §2.3`: 120 seconds.
/// Sessions older than this must begin a rekey before emitting further
/// data packets.
pub const REKEY_INTERVAL_MS: u64 = 120_000;

/// Return `true` if a session established at `established_at_ms` is due
/// for a rekey at `now_ms`. Monotonic clock required; backwards jumps
/// are treated as "not due" (never rewind the trigger).
pub fn is_due(established_at_ms: u64, now_ms: u64) -> bool {
    now_ms.checked_sub(established_at_ms).map(|age| age >= REKEY_INTERVAL_MS).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_due_before_interval() {
        assert!(!is_due(0, 0));
        assert!(!is_due(0, 119_999));
    }

    #[test]
    fn due_at_and_after_interval() {
        assert!(is_due(0, REKEY_INTERVAL_MS));
        assert!(is_due(0, REKEY_INTERVAL_MS + 1));
        assert!(is_due(1_000, 1_000 + REKEY_INTERVAL_MS));
    }

    #[test]
    fn clock_going_backwards_is_not_due() {
        assert!(!is_due(10_000, 5_000));
    }
}
