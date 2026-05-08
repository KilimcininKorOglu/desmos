//! Probe scheduler.
//!
//! One `ProbeScheduler` runs per bonding link. It decides when to
//! emit the next probe, assigns monotonic probe sequence numbers,
//! tracks in-flight probes in a small map, and reports successful
//! RTT measurements plus timed-out probes back to the caller.
//!
//! The scheduler is pure logic: it holds no sockets and produces no
//! packets. The pipeline builds and dispatches the actual wire
//! packet (`PacketType::Probe` with the seq + send time in the
//! payload) based on what [`ProbeScheduler::issue`] returns, and
//! feeds the arriving probe echo back through [`ProbeScheduler::on_ack`].
//!
//! Time is passed in microseconds so the scheduler can compute RTTs
//! in the same unit that [`super::score::LinkStats::record_rtt`]
//! expects.

use std::collections::BTreeMap;

/// Default probe cadence: one probe every 500 ms, matching the
/// `probe_interval_ms` acceptance criterion.
pub const DEFAULT_INTERVAL_US: u64 = 500_000;

/// Default probe timeout: a probe that has not been acknowledged
/// within 2 seconds is declared lost. Generous so spikes on high-
/// latency mobile links do not look like loss.
pub const DEFAULT_TIMEOUT_US: u64 = 2_000_000;

/// Result of a successful `on_ack` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeAck {
    pub seq: u64,
    pub rtt_us: u32,
}

/// Per-link probe scheduler.
#[derive(Debug, Clone)]
pub struct ProbeScheduler {
    interval_us: u64,
    timeout_us: u64,
    /// When the last probe was issued, in microseconds. `None` before
    /// the very first call so the first probe fires immediately on
    /// `is_due`.
    last_send_us: Option<u64>,
    /// Next probe sequence number to hand out.
    next_seq: u64,
    /// Probes awaiting acknowledgement: seq → send time (µs).
    in_flight: BTreeMap<u64, u64>,
}

impl ProbeScheduler {
    pub fn new(interval_us: u64, timeout_us: u64) -> Self {
        assert!(interval_us > 0, "interval_us must be > 0");
        assert!(timeout_us > 0, "timeout_us must be > 0");
        Self {
            interval_us,
            timeout_us,
            last_send_us: None,
            next_seq: 0,
            in_flight: BTreeMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_INTERVAL_US, DEFAULT_TIMEOUT_US)
    }

    /// `true` if a new probe should be sent at `now_us`. The first
    /// call always returns `true` because no probe has been sent yet;
    /// subsequent calls only return `true` once `interval_us` has
    /// elapsed since the last issue.
    pub fn is_due(&self, now_us: u64) -> bool {
        match self.last_send_us {
            None => true,
            Some(last) => now_us.saturating_sub(last) >= self.interval_us,
        }
    }

    /// Issue the next probe: returns the sequence number the caller
    /// should put on the wire. Records the probe as in-flight.
    pub fn issue(&mut self, now_us: u64) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.in_flight.insert(seq, now_us);
        self.last_send_us = Some(now_us);
        seq
    }

    /// Handle an acknowledgement for a probe. Returns the RTT in
    /// microseconds if the seq was in-flight, or `None` if the probe
    /// was unknown (either already timed out or never issued).
    pub fn on_ack(&mut self, seq: u64, now_us: u64) -> Option<ProbeAck> {
        let send_us = self.in_flight.remove(&seq)?;
        let rtt_us = now_us.saturating_sub(send_us) as u32;
        Some(ProbeAck { seq, rtt_us })
    }

    /// Drain and return every in-flight probe that has been waiting
    /// longer than `timeout_us`. These are considered lost; the
    /// caller should feed each into `LinkStats::record_loss`.
    pub fn drain_timeouts(&mut self, now_us: u64) -> Vec<u64> {
        let mut out = Vec::new();
        // Collect expired seqs first so we do not mutate the map
        // while iterating. The number of in-flight probes is small
        // (at most ~4 between the 500 ms interval and 2 s timeout),
        // so allocation cost is negligible.
        let expired: Vec<u64> = self
            .in_flight
            .iter()
            .filter_map(|(&seq, &send)| {
                if now_us.saturating_sub(send) >= self.timeout_us {
                    Some(seq)
                } else {
                    None
                }
            })
            .collect();
        for seq in expired {
            self.in_flight.remove(&seq);
            out.push(seq);
        }
        out
    }

    /// Number of probes currently awaiting acknowledgement.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Next seq value that will be returned by `issue`. Exposed for
    /// tests and metrics.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Configured probe interval.
    pub fn interval_us(&self) -> u64 {
        self.interval_us
    }

    /// Configured probe timeout.
    pub fn timeout_us(&self) -> u64 {
        self.timeout_us
    }
}

impl Default for ProbeScheduler {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_to_is_due_returns_true() {
        let s = ProbeScheduler::with_defaults();
        assert!(s.is_due(0));
        assert!(s.is_due(10_000_000));
    }

    #[test]
    fn is_due_respects_interval() {
        let mut s = ProbeScheduler::new(500_000, 2_000_000);
        let _ = s.issue(1_000_000);
        assert!(!s.is_due(1_000_000));
        assert!(!s.is_due(1_499_999));
        assert!(s.is_due(1_500_000));
        assert!(s.is_due(1_500_001));
    }

    #[test]
    fn issue_assigns_monotonic_seqs() {
        let mut s = ProbeScheduler::with_defaults();
        assert_eq!(s.issue(1), 0);
        assert_eq!(s.issue(2), 1);
        assert_eq!(s.issue(3), 2);
        assert_eq!(s.next_seq(), 3);
    }

    #[test]
    fn issue_records_in_flight() {
        let mut s = ProbeScheduler::with_defaults();
        s.issue(1);
        s.issue(2);
        assert_eq!(s.in_flight_count(), 2);
    }

    #[test]
    fn on_ack_returns_rtt_and_clears_in_flight() {
        let mut s = ProbeScheduler::with_defaults();
        let seq = s.issue(1_000);
        let ack = s.on_ack(seq, 5_500).unwrap();
        assert_eq!(ack.seq, seq);
        assert_eq!(ack.rtt_us, 4_500);
        assert_eq!(s.in_flight_count(), 0);
    }

    #[test]
    fn on_ack_unknown_seq_returns_none() {
        let mut s = ProbeScheduler::with_defaults();
        assert!(s.on_ack(42, 1_000).is_none());
    }

    #[test]
    fn on_ack_already_acked_seq_returns_none() {
        let mut s = ProbeScheduler::with_defaults();
        let seq = s.issue(1_000);
        s.on_ack(seq, 2_000).unwrap();
        assert!(s.on_ack(seq, 3_000).is_none());
    }

    #[test]
    fn drain_timeouts_returns_only_expired_probes() {
        let mut s = ProbeScheduler::new(500_000, 2_000_000);
        let a = s.issue(0);
        let b = s.issue(1_000_000);
        let c = s.issue(2_500_000);

        // now = 2_500_000 → a is 2.5 s old, b is 1.5 s old, c is 0 s.
        let expired = s.drain_timeouts(2_500_000);
        assert_eq!(expired, vec![a]);
        assert_eq!(s.in_flight_count(), 2);
        // Further drain at 3.5 s expires b but not c.
        let expired = s.drain_timeouts(3_500_000);
        assert_eq!(expired, vec![b]);
        assert_eq!(s.in_flight_count(), 1);
        // c still in flight.
        let _ = c;
    }

    #[test]
    fn drain_timeouts_is_idempotent_when_nothing_expired() {
        let mut s = ProbeScheduler::with_defaults();
        s.issue(0);
        assert!(s.drain_timeouts(100_000).is_empty());
        assert_eq!(s.in_flight_count(), 1);
    }

    #[test]
    fn ack_then_timeout_does_not_double_count() {
        let mut s = ProbeScheduler::new(500_000, 2_000_000);
        let seq = s.issue(0);
        s.on_ack(seq, 100_000).unwrap();
        // Advance past the timeout; the probe is already gone from
        // in_flight so drain_timeouts sees nothing.
        assert!(s.drain_timeouts(3_000_000).is_empty());
    }

    #[test]
    #[should_panic(expected = "interval_us")]
    fn new_rejects_zero_interval() {
        let _ = ProbeScheduler::new(0, 1_000);
    }

    #[test]
    #[should_panic(expected = "timeout_us")]
    fn new_rejects_zero_timeout() {
        let _ = ProbeScheduler::new(1_000, 0);
    }
}
