//! Per-link quality statistics and composite score.
//!
//! `LinkStats` tracks three rolling metrics for a single bonding link:
//!
//! - **RTT EWMA** (Jacobson SRTT with α = 0.125) — the smoothed
//!   round-trip time in microseconds.
//! - **Loss rate** — fraction of the last N probes that were declared
//!   lost by the probe scheduler's timeout path.
//! - **Jitter** — standard deviation of the RTT samples held in the
//!   same rolling window.
//!
//! The stats feed a [`LinkScore`] composite value that the weighted
//! and latency-adaptive strategies multiply into their
//! scheduling decisions. Higher composite = better link.
//!
//! This module is pure logic: no I/O, no timers, no allocations on
//! the read side. Unit tests feed synthetic samples via `record_*`.

use std::collections::VecDeque;

/// Default window size for loss / jitter calculations. The TASKS.md
/// acceptance item calls out "rolling loss over last 100 probes", so
/// 100 is the standard setting.
pub const DEFAULT_WINDOW: usize = 100;

/// α for the Jacobson RTT EWMA (RFC 6298 §2 default). `smoothed =
/// (1 - α) · smoothed + α · sample`.
pub const RTT_EWMA_ALPHA: f64 = 0.125;

/// Snapshot of a link's current quality. Returned by
/// [`LinkStats::score`]; cheap to copy and drop.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LinkScore {
    /// Smoothed round-trip time in microseconds. `0` when no probes
    /// have been received yet.
    pub rtt_us: u32,
    /// Fraction of recent probes that were lost, in `[0.0, 1.0]`.
    pub loss_rate: f32,
    /// Jitter in microseconds (stdev of the RTT sample window).
    pub jitter_us: u32,
    /// Composite "higher is better" score. The weighted and adaptive
    /// strategies use this to pick links.
    pub composite: f32,
}

/// Rolling statistics for a single link.
#[derive(Debug, Clone)]
pub struct LinkStats {
    rtt_ewma_us: f64,
    rtt_seeded: bool,
    /// True = probe got a response, false = timed out.
    outcome_window: VecDeque<bool>,
    /// Raw RTT samples in microseconds, for jitter.
    rtt_samples: VecDeque<u32>,
    window_size: usize,
}

impl LinkStats {
    pub fn new(window_size: usize) -> Self {
        assert!(window_size > 0, "window_size must be > 0");
        Self {
            rtt_ewma_us: 0.0,
            rtt_seeded: false,
            outcome_window: VecDeque::with_capacity(window_size),
            rtt_samples: VecDeque::with_capacity(window_size),
            window_size,
        }
    }

    /// Record a successful probe with its measured RTT in microseconds.
    pub fn record_rtt(&mut self, rtt_us: u32) {
        if self.rtt_seeded {
            // Standard Jacobson SRTT update.
            let sample = rtt_us as f64;
            self.rtt_ewma_us = (1.0 - RTT_EWMA_ALPHA) * self.rtt_ewma_us + RTT_EWMA_ALPHA * sample;
        } else {
            self.rtt_ewma_us = rtt_us as f64;
            self.rtt_seeded = true;
        }

        self.push_sample(rtt_us);
        self.push_outcome(true);
    }

    /// Record a probe that never received a response (timed out).
    pub fn record_loss(&mut self) {
        self.push_outcome(false);
    }

    fn push_sample(&mut self, rtt_us: u32) {
        if self.rtt_samples.len() == self.window_size {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt_us);
    }

    fn push_outcome(&mut self, success: bool) {
        if self.outcome_window.len() == self.window_size {
            self.outcome_window.pop_front();
        }
        self.outcome_window.push_back(success);
    }

    /// Current smoothed RTT in microseconds, or `None` if no probe has
    /// been recorded yet.
    pub fn rtt_ewma_us(&self) -> Option<u32> {
        if self.rtt_seeded {
            Some(self.rtt_ewma_us.round() as u32)
        } else {
            None
        }
    }

    /// Fraction of probes in the rolling window that were lost. `0.0`
    /// when the window is empty so a brand-new link is considered
    /// perfectly healthy until the first probe lands.
    pub fn loss_rate(&self) -> f32 {
        if self.outcome_window.is_empty() {
            return 0.0;
        }
        let lost = self.outcome_window.iter().filter(|ok| !**ok).count();
        lost as f32 / self.outcome_window.len() as f32
    }

    /// Standard deviation of the RTT samples in the rolling window,
    /// rounded to whole microseconds. Returns `0` when fewer than two
    /// samples have been recorded (stdev is undefined).
    pub fn jitter_us(&self) -> u32 {
        let n = self.rtt_samples.len();
        if n < 2 {
            return 0;
        }
        let mean = self.rtt_samples.iter().map(|s| *s as f64).sum::<f64>() / n as f64;
        let variance = self
            .rtt_samples
            .iter()
            .map(|s| {
                let d = *s as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        variance.sqrt().round() as u32
    }

    /// Build a composite snapshot. The `composite` field folds RTT,
    /// loss, and jitter into a single "higher is better" value:
    ///
    /// ```text
    /// composite = (1 - loss_rate) · 10_000 / (1 + rtt_ms + jitter_ms · 2)
    /// ```
    ///
    /// The constants are tunable; the weighted strategy can read them
    /// from config later. A perfectly healthy 1 ms RTT
    /// link with zero loss scores ~5 000; a 100 ms RTT link with 10 %
    /// loss scores ~88.
    pub fn score(&self) -> LinkScore {
        let rtt_us = self.rtt_ewma_us().unwrap_or(0);
        let loss_rate = self.loss_rate();
        let jitter_us = self.jitter_us();

        let rtt_ms = rtt_us as f32 / 1_000.0;
        let jitter_ms = jitter_us as f32 / 1_000.0;
        let composite = (1.0 - loss_rate) * 10_000.0 / (1.0 + rtt_ms + jitter_ms * 2.0);

        LinkScore { rtt_us, loss_rate, jitter_us, composite }
    }

    /// Number of samples currently held. Useful for asserting warm-up.
    pub fn sample_count(&self) -> usize {
        self.rtt_samples.len()
    }

    /// Number of outcome entries (successes + losses) currently held.
    pub fn outcome_count(&self) -> usize {
        self.outcome_window.len()
    }
}

impl Default for LinkStats {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stats_report_nothing_until_first_sample() {
        let s = LinkStats::new(10);
        assert_eq!(s.rtt_ewma_us(), None);
        assert_eq!(s.loss_rate(), 0.0);
        assert_eq!(s.jitter_us(), 0);
        assert_eq!(s.sample_count(), 0);
    }

    #[test]
    fn first_sample_seeds_the_ewma_exactly() {
        let mut s = LinkStats::new(10);
        s.record_rtt(5_000);
        assert_eq!(s.rtt_ewma_us(), Some(5_000));
    }

    #[test]
    fn ewma_converges_toward_new_samples() {
        let mut s = LinkStats::new(100);
        s.record_rtt(10_000);
        // Same sample repeated → EWMA stays at 10_000.
        for _ in 0..20 {
            s.record_rtt(10_000);
        }
        assert_eq!(s.rtt_ewma_us(), Some(10_000));

        // Step change to 30_000 — EWMA should drift upward with α = 0.125.
        for _ in 0..50 {
            s.record_rtt(30_000);
        }
        let current = s.rtt_ewma_us().unwrap();
        assert!(
            current > 25_000 && current <= 30_000,
            "EWMA after 50 samples of 30k should be near 30k, got {current}"
        );
    }

    #[test]
    fn loss_rate_reflects_rolling_window() {
        let mut s = LinkStats::new(10);
        for _ in 0..5 {
            s.record_rtt(1_000);
        }
        for _ in 0..5 {
            s.record_loss();
        }
        assert_eq!(s.loss_rate(), 0.5);
    }

    #[test]
    fn loss_rate_evicts_oldest_entry_when_window_fills() {
        let mut s = LinkStats::new(4);
        s.record_loss();
        s.record_loss();
        s.record_rtt(1_000);
        s.record_rtt(1_000);
        assert_eq!(s.loss_rate(), 0.5);
        // One more success evicts the oldest loss.
        s.record_rtt(1_000);
        assert_eq!(s.loss_rate(), 0.25);
    }

    #[test]
    fn jitter_is_zero_for_constant_rtt() {
        let mut s = LinkStats::new(10);
        for _ in 0..10 {
            s.record_rtt(5_000);
        }
        assert_eq!(s.jitter_us(), 0);
    }

    #[test]
    fn jitter_matches_computed_stdev_for_known_samples() {
        let mut s = LinkStats::new(10);
        let samples: [u32; 5] = [1_000, 1_200, 900, 1_100, 1_300];
        for &x in &samples {
            s.record_rtt(x);
        }
        // Mean = 1100, variance = (100^2 + 100^2 + 200^2 + 0 + 200^2) / 5
        //                       = (10000 + 10000 + 40000 + 0 + 40000) / 5
        //                       = 100000 / 5 = 20000
        // stdev ≈ sqrt(20000) ≈ 141.42 → 141 after rounding.
        let j = s.jitter_us();
        assert!((140..=142).contains(&j), "expected jitter near 141, got {j}");
    }

    #[test]
    fn jitter_is_zero_with_single_sample() {
        let mut s = LinkStats::new(10);
        s.record_rtt(500);
        assert_eq!(s.jitter_us(), 0);
    }

    #[test]
    fn score_composite_higher_for_better_link() {
        let mut good = LinkStats::new(100);
        let mut bad = LinkStats::new(100);
        // Good: 1 ms RTT, no loss.
        for _ in 0..50 {
            good.record_rtt(1_000);
        }
        // Bad: 100 ms RTT, 20 % loss.
        for i in 0..50 {
            if i % 5 == 0 {
                bad.record_loss();
            } else {
                bad.record_rtt(100_000);
            }
        }
        let good_score = good.score();
        let bad_score = bad.score();
        assert!(
            good_score.composite > bad_score.composite,
            "good={good_score:?}, bad={bad_score:?}",
        );
    }

    #[test]
    fn score_is_zero_when_loss_is_100_percent() {
        let mut s = LinkStats::new(10);
        for _ in 0..10 {
            s.record_loss();
        }
        assert_eq!(s.score().composite, 0.0);
        assert_eq!(s.score().loss_rate, 1.0);
    }

    #[test]
    fn sample_window_caps_at_window_size() {
        let mut s = LinkStats::new(5);
        for i in 0..20 {
            s.record_rtt(1_000 + i);
        }
        assert_eq!(s.sample_count(), 5);
        assert_eq!(s.outcome_count(), 5);
    }

    #[test]
    #[should_panic(expected = "window_size")]
    fn new_rejects_zero_window() {
        let _ = LinkStats::new(0);
    }
}
