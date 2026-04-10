//! Keepalive scheduling.
//!
//! Established sessions periodically send an empty `Keepalive` DWP packet
//! so NAT bindings on every upstream middlebox stay open and the peer
//! notices the link is alive even when no user traffic is flowing.
//!
//! The policy is deliberately tiny: a fixed interval, with a "last sent
//! at" watermark so the session manager can ask "is this one due?".

/// Keepalive interval: 15 seconds. Short enough to hold typical UDP NAT
/// entries (most home routers evict at 30 s, some as low as 20 s).
pub const KEEPALIVE_INTERVAL_MS: u64 = 15_000;

/// Return `true` if the session has not sent anything on this interface
/// for at least `KEEPALIVE_INTERVAL_MS`, so the pipeline should emit a
/// keepalive probe before the next regular poll.
pub fn is_due(last_sent_at_ms: u64, now_ms: u64) -> bool {
    now_ms.checked_sub(last_sent_at_ms).map(|gap| gap >= KEEPALIVE_INTERVAL_MS).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_due_before_interval() {
        assert!(!is_due(0, 0));
        assert!(!is_due(0, 14_999));
    }

    #[test]
    fn due_at_and_after_interval() {
        assert!(is_due(0, KEEPALIVE_INTERVAL_MS));
        assert!(is_due(0, KEEPALIVE_INTERVAL_MS * 3));
    }

    #[test]
    fn clock_regression_does_not_trigger() {
        assert!(!is_due(10_000, 5_000));
    }
}
