//! 128-bit sliding anti-replay window, shape modelled after RFC 6479 §3.
//!
//! The window tracks the highest packet sequence number seen on a
//! session plus a 128-bit bitmap where bit 0 represents `highest` and
//! bit `k` represents `highest - k`. A freshly received sequence number
//! is accepted exactly once:
//!
//! - `seq > highest`: window slides left by `seq - highest`, bit 0 is
//!   re-set to mark the new top, and we accept.
//! - `seq == highest` or the corresponding bit is already set: duplicate,
//!   reject silently (callers typically bump a metric and drop).
//! - `seq < highest` and still inside the 128-wide window: the matching
//!   bit is set and we accept the out-of-order packet.
//! - `seq < highest - 127`: too old, out of window, reject.
//!
//! The window is a single-writer structure — the inbound pipeline stage
//! that owns the session touches it and nobody else.

use core::fmt;

/// Width of the sliding window, in packets.
pub const WINDOW_SIZE: u64 = 128;

/// Reason a packet was rejected by the anti-replay window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The sequence number was already seen.
    Duplicate,
    /// The sequence number falls before the tail of the window.
    OutOfWindow,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => f.write_str("anti-replay: duplicate sequence"),
            Self::OutOfWindow => f.write_str("anti-replay: sequence out of window"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Single-session anti-replay state.
#[derive(Debug, Clone)]
pub struct AntiReplayWindow {
    /// Highest sequence number accepted so far. Only meaningful once
    /// `initialised` is true.
    highest: u64,
    /// 128-bit sliding bitmap. Bit 0 corresponds to `highest`, bit `k`
    /// corresponds to `highest - k`.
    bitmap: u128,
    /// Set after the first successful `check_and_update` so sequence
    /// number zero itself can still be accepted exactly once.
    initialised: bool,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    /// Build an empty window. Every sequence number is fresh until the
    /// first successful `check_and_update`.
    pub const fn new() -> Self {
        Self { highest: 0, bitmap: 0, initialised: false }
    }

    /// Highest sequence seen so far, or `None` if no packet has been
    /// accepted yet.
    pub fn highest(&self) -> Option<u64> {
        if self.initialised {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Check whether `seq` would be accepted without mutating the
    /// window. Useful for speculative work in the pipeline; the real
    /// call site should use `check_and_update`.
    pub fn would_accept(&self, seq: u64) -> bool {
        if !self.initialised {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        let offset = self.highest - seq;
        if offset >= WINDOW_SIZE {
            return false;
        }
        let mask = 1u128 << offset;
        self.bitmap & mask == 0
    }

    /// Validate `seq` and, if fresh, mark it as seen. Returns `Ok(())`
    /// when the packet should be processed and a typed error otherwise.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), ReplayError> {
        if !self.initialised {
            self.highest = seq;
            self.bitmap = 1;
            self.initialised = true;
            return Ok(());
        }

        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= WINDOW_SIZE { 1 } else { (self.bitmap << shift) | 1 };
            self.highest = seq;
            return Ok(());
        }

        let offset = self.highest - seq;
        if offset >= WINDOW_SIZE {
            return Err(ReplayError::OutOfWindow);
        }
        let mask = 1u128 << offset;
        if self.bitmap & mask != 0 {
            return Err(ReplayError::Duplicate);
        }
        self.bitmap |= mask;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_window_accepts_any_first_packet() {
        let mut w = AntiReplayWindow::new();
        assert!(w.highest().is_none());
        assert!(w.check_and_update(0).is_ok());
        assert_eq!(w.highest(), Some(0));

        let mut w2 = AntiReplayWindow::new();
        assert!(w2.check_and_update(1_000_000).is_ok());
        assert_eq!(w2.highest(), Some(1_000_000));
    }

    #[test]
    fn in_order_packets_all_accepted() {
        let mut w = AntiReplayWindow::new();
        for seq in 0..500u64 {
            assert!(w.check_and_update(seq).is_ok(), "seq {seq} rejected");
        }
        assert_eq!(w.highest(), Some(499));
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(10).is_ok());
        assert!(w.check_and_update(5).is_ok());
        assert!(w.check_and_update(7).is_ok());
        assert!(w.check_and_update(3).is_ok());
    }

    #[test]
    fn duplicate_of_highest_is_rejected() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(42).unwrap();
        assert_eq!(w.check_and_update(42).unwrap_err(), ReplayError::Duplicate);
    }

    #[test]
    fn duplicate_within_window_is_rejected() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(100).unwrap();
        w.check_and_update(95).unwrap();
        assert_eq!(w.check_and_update(95).unwrap_err(), ReplayError::Duplicate);
        assert_eq!(w.check_and_update(100).unwrap_err(), ReplayError::Duplicate);
    }

    #[test]
    fn old_packet_at_exactly_window_edge_is_accepted() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(127).unwrap();
        // seq 0 is at offset 127, still inside the 128-bit window.
        assert!(w.check_and_update(0).is_ok());
    }

    #[test]
    fn old_packet_one_past_window_edge_is_rejected() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(128).unwrap();
        // seq 0 is at offset 128, out of window.
        assert_eq!(w.check_and_update(0).unwrap_err(), ReplayError::OutOfWindow);
    }

    #[test]
    fn large_forward_jump_clears_window() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(5).unwrap();
        w.check_and_update(4).unwrap();
        w.check_and_update(1_000_000).unwrap();
        // Old packets (seq 5, 4) are now far outside the window.
        assert_eq!(w.check_and_update(5).unwrap_err(), ReplayError::OutOfWindow);
        assert_eq!(w.check_and_update(4).unwrap_err(), ReplayError::OutOfWindow);
        // But fresh ones near the new highest still go through.
        assert!(w.check_and_update(999_999).is_ok());
    }

    #[test]
    fn exactly_window_sized_forward_jump_uses_overflow_branch() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(0).unwrap();
        // shift == WINDOW_SIZE should take the overflow branch so the
        // old highest is evicted entirely.
        w.check_and_update(WINDOW_SIZE).unwrap();
        assert_eq!(w.highest(), Some(WINDOW_SIZE));
        // seq 0 is at offset 128, out of window.
        assert_eq!(w.check_and_update(0).unwrap_err(), ReplayError::OutOfWindow);
    }

    #[test]
    fn would_accept_matches_check_and_update() {
        let mut w = AntiReplayWindow::new();
        w.check_and_update(50).unwrap();
        assert!(w.would_accept(51));
        assert!(w.would_accept(49));
        assert!(!w.would_accept(50)); // duplicate
        w.check_and_update(49).unwrap();
        assert!(!w.would_accept(49));
        // Way-in-the-future sequences are always fresh.
        assert!(w.would_accept(u64::MAX - 1));
    }

    #[test]
    fn would_accept_on_fresh_window_is_true_for_any_seq() {
        let w = AntiReplayWindow::new();
        assert!(w.would_accept(0));
        assert!(w.would_accept(u64::MAX));
    }

    #[test]
    fn window_is_per_session_not_shared() {
        // Regression: two AntiReplayWindow instances must not share
        // state in any sneaky way. Clone derives independent copies.
        let mut a = AntiReplayWindow::new();
        let mut b = AntiReplayWindow::new();
        a.check_and_update(7).unwrap();
        assert!(b.check_and_update(7).is_ok());
        // Cloning mid-stream is fine too.
        let mut c = a.clone();
        assert_eq!(c.check_and_update(7).unwrap_err(), ReplayError::Duplicate);
    }
}
