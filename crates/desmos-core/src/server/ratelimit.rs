//! Per-source IP token-bucket rate limiter.
//!
//! First gate of the server handshake accept path. Every inbound
//! msg1 runs through
//! [`RateLimiter::try_admit`] *before* any crypto work happens —
//! that way a UDP flood from one source cannot burn CPU on
//! Noise IK key decryption, and cannot get past the
//! [`super::clients::ClientRegistry`] `max_clients` cap either.
//!
//! # Shape
//!
//! The default policy from SPECIFICATION.md §6.4 is **5 tokens
//! max, refilled at 5 tokens / 10 s**, which is exactly
//! `0.5 tokens/sec` as a refill rate. The implementation stores
//! tokens in a fixed-point milli-token form (`u32` with 1 token
//! = 1000) so the refill arithmetic is integer-only and the
//! bucket is 4 bytes larger than the naive f32 version.
//!
//! # Eviction
//!
//! A malicious peer that sprays from millions of source IPs
//! would blow the `HashMap` up if we never evicted idle
//! entries. [`RateLimiter::evict_stale`] walks the map and
//! drops every bucket whose last activity is older than
//! `max_idle_ms`. The caller (the daemon runner) decides the
//! cadence — typical: every 60 s, bounded to at most a few
//! thousand entries.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// SPECIFICATION.md §6.4 default: 5-token burst, refilled at
/// 5 tokens per 10 seconds. Stored in fixed-point milli-tokens
/// so 1 token = 1000.
pub const DEFAULT_MAX_TOKENS: u32 = 5;
pub const DEFAULT_REFILL_MILLI_PER_SEC: u32 = 500;

/// Per-source IP bucket. Public only so the tests and the
/// admission-path instrumentation can read `tokens_milli` and
/// `last_refill_ms` without going through a getter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    tokens_milli: u32,
    last_refill_ms: u64,
}

/// Token-bucket rate limiter keyed by [`IpAddr`].
///
/// All operations are guarded by a single [`Mutex`] — the
/// accept path is single-threaded per listener, so contention
/// is expected to be near-zero. If profiling shows the mutex
/// is a bottleneck in a future multi-listener world, shard by
/// the low byte of the IP.
#[derive(Debug)]
pub struct RateLimiter {
    max_tokens_milli: u32,
    refill_milli_per_sec: u32,
    inner: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Build a rate limiter with the SPECIFICATION.md §6.4
    /// defaults.
    pub fn with_default_policy() -> Self {
        Self::new(DEFAULT_MAX_TOKENS, DEFAULT_REFILL_MILLI_PER_SEC)
    }

    /// Build a rate limiter with a caller-supplied policy.
    /// `max_tokens` is the burst size (each token = one admit
    /// call). `refill_milli_per_sec` is the refill rate in
    /// fixed-point milli-tokens per second, e.g. `500` for
    /// 0.5 tokens/sec. Panics on zero `max_tokens` (a dead
    /// policy that would reject every caller).
    pub fn new(max_tokens: u32, refill_milli_per_sec: u32) -> Self {
        assert!(max_tokens > 0, "RateLimiter: max_tokens must be > 0");
        Self {
            max_tokens_milli: max_tokens.saturating_mul(1000),
            refill_milli_per_sec,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Try to admit one request from `source` at `now_ms`.
    /// Returns `true` if the bucket had at least one token and
    /// the call should proceed, `false` if the caller should be
    /// dropped. First call from a source initialises the bucket
    /// at the full `max_tokens`.
    pub fn try_admit(&self, source: IpAddr, now_ms: u64) -> bool {
        let mut inner = self.inner.lock().expect("ratelimit mutex poisoned");
        let bucket = inner
            .entry(source)
            .or_insert(Bucket { tokens_milli: self.max_tokens_milli, last_refill_ms: now_ms });

        // Refill based on wall-clock delta.
        if now_ms > bucket.last_refill_ms {
            let dt_ms = now_ms - bucket.last_refill_ms;
            // milli-tokens added = refill_rate * dt / 1000.
            let added = (self.refill_milli_per_sec as u64).saturating_mul(dt_ms) / 1000;
            let new_tokens = (bucket.tokens_milli as u64).saturating_add(added);
            bucket.tokens_milli = new_tokens.min(self.max_tokens_milli as u64) as u32;
            bucket.last_refill_ms = now_ms;
        }

        if bucket.tokens_milli >= 1000 {
            bucket.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }

    /// Drop every bucket whose `last_refill_ms` is older than
    /// `now_ms - max_idle_ms`. Returns the number of entries
    /// removed. Callers invoke this periodically (typical:
    /// every 60 s) so an attacker spraying from many source
    /// IPs cannot grow the map without bound.
    pub fn evict_stale(&self, now_ms: u64, max_idle_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(max_idle_ms);
        let mut inner = self.inner.lock().expect("ratelimit mutex poisoned");
        let before = inner.len();
        inner.retain(|_, b| b.last_refill_ms >= cutoff);
        before - inner.len()
    }

    /// Current number of tracked source IPs. Intended for
    /// metrics and tests — the absolute value is noisy under
    /// load so do not page on it.
    pub fn tracked(&self) -> usize {
        self.inner.lock().expect("ratelimit mutex poisoned").len()
    }

    /// Reset the limiter to a clean state. Primarily useful for
    /// tests; the daemon never calls this at runtime because
    /// wiping buckets would also wipe pending throttles on
    /// attackers mid-burst.
    #[cfg(test)]
    pub fn reset(&self) {
        self.inner.lock().expect("ratelimit mutex poisoned").clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_default_policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn default_policy_accepts_first_five_and_rejects_sixth() {
        // SPECIFICATION.md §6.4 acceptance: 5 tokens, 5/10s refill.
        let rl = RateLimiter::with_default_policy();
        let src = ip(203, 0, 113, 7);
        for _ in 0..5 {
            assert!(rl.try_admit(src, 0));
        }
        assert!(!rl.try_admit(src, 0));
    }

    #[test]
    fn refill_grants_one_token_after_two_seconds() {
        let rl = RateLimiter::with_default_policy();
        let src = ip(198, 51, 100, 1);
        // Burn the whole bucket.
        for _ in 0..5 {
            assert!(rl.try_admit(src, 0));
        }
        assert!(!rl.try_admit(src, 0));
        // 2000 ms * 0.5 tok/sec = 1 token.
        assert!(rl.try_admit(src, 2_000));
        assert!(!rl.try_admit(src, 2_000));
    }

    #[test]
    fn refill_fully_recovers_after_ten_seconds() {
        let rl = RateLimiter::with_default_policy();
        let src = ip(192, 0, 2, 9);
        for _ in 0..5 {
            assert!(rl.try_admit(src, 0));
        }
        // 10 s later, bucket should be full again.
        for _ in 0..5 {
            assert!(rl.try_admit(src, 10_000));
        }
        assert!(!rl.try_admit(src, 10_000));
    }

    #[test]
    fn refill_caps_at_max_tokens() {
        let rl = RateLimiter::with_default_policy();
        let src = ip(10, 0, 0, 1);
        // Spend 1, then idle for an hour — bucket must not exceed 5.
        assert!(rl.try_admit(src, 0));
        // One hour of refill at 0.5 tok/sec = 1800 tokens worth,
        // far past the cap.
        for _ in 0..5 {
            assert!(rl.try_admit(src, 3_600_000));
        }
        assert!(!rl.try_admit(src, 3_600_000));
    }

    #[test]
    fn sources_are_accounted_independently() {
        let rl = RateLimiter::with_default_policy();
        let a = ip(172, 16, 0, 1);
        let b = ip(172, 16, 0, 2);
        for _ in 0..5 {
            assert!(rl.try_admit(a, 0));
        }
        assert!(!rl.try_admit(a, 0));
        // b still has a full bucket.
        for _ in 0..5 {
            assert!(rl.try_admit(b, 0));
        }
        assert!(!rl.try_admit(b, 0));
    }

    #[test]
    fn evict_stale_drops_idle_buckets() {
        let rl = RateLimiter::with_default_policy();
        let a = ip(10, 0, 1, 1);
        let b = ip(10, 0, 1, 2);
        assert!(rl.try_admit(a, 0));
        assert!(rl.try_admit(b, 5_000));
        assert_eq!(rl.tracked(), 2);

        // Evict anything idle for more than 2 s at t = 10 s.
        // a was last touched at 0 (idle 10s), b at 5000 (idle 5s).
        // Both should go.
        let dropped = rl.evict_stale(10_000, 2_000);
        assert_eq!(dropped, 2);
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn evict_keeps_fresh_buckets() {
        let rl = RateLimiter::with_default_policy();
        let fresh = ip(10, 0, 2, 1);
        let old = ip(10, 0, 2, 2);
        assert!(rl.try_admit(old, 0));
        assert!(rl.try_admit(fresh, 9_500));
        // At t = 10_000, cutoff = 10_000 - 2_000 = 8_000.
        // old.last_refill = 0 < 8000 → evicted.
        // fresh.last_refill = 9500 >= 8000 → kept.
        let dropped = rl.evict_stale(10_000, 2_000);
        assert_eq!(dropped, 1);
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn custom_policy_burst_of_one() {
        let rl = RateLimiter::new(1, 100); // 1-token burst, very slow refill.
        let src = ip(127, 0, 0, 1);
        assert!(rl.try_admit(src, 0));
        assert!(!rl.try_admit(src, 0));
        // 10 s * 0.1 tok/sec = 1 token.
        assert!(rl.try_admit(src, 10_000));
    }

    #[test]
    fn tracked_matches_distinct_sources() {
        let rl = RateLimiter::with_default_policy();
        assert_eq!(rl.tracked(), 0);
        rl.try_admit(ip(1, 1, 1, 1), 0);
        rl.try_admit(ip(2, 2, 2, 2), 0);
        rl.try_admit(ip(1, 1, 1, 1), 1);
        assert_eq!(rl.tracked(), 2);
    }

    #[test]
    fn reset_clears_all_buckets() {
        let rl = RateLimiter::with_default_policy();
        rl.try_admit(ip(4, 4, 4, 4), 0);
        assert_eq!(rl.tracked(), 1);
        rl.reset();
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn backward_clock_does_not_wipe_bucket() {
        // now_ms < last_refill_ms: refund branch is skipped,
        // we just attempt to spend the current tokens.
        let rl = RateLimiter::with_default_policy();
        let src = ip(9, 9, 9, 9);
        // Establish bucket at t = 10_000.
        assert!(rl.try_admit(src, 10_000));
        // Clock jumps backward — still has 4 tokens left.
        assert!(rl.try_admit(src, 5_000));
        assert!(rl.try_admit(src, 5_000));
        assert!(rl.try_admit(src, 5_000));
        assert!(rl.try_admit(src, 5_000));
        assert!(!rl.try_admit(src, 5_000));
    }

    #[test]
    #[should_panic(expected = "max_tokens")]
    fn zero_max_tokens_panics_at_construction() {
        let _ = RateLimiter::new(0, 100);
    }
}
