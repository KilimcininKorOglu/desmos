//! Integration test: drive a `ProbeScheduler` + `LinkStats` pair
//! through a simulated probe/response cycle with a fake clock and
//! assert that the reported RTT, loss, and jitter match the
//! synthetic workload exactly.
//!
//! This is the closest we get to "real network probing" without
//! touching a socket: the test controls both sides of the exchange
//! and compares the stats the bonding engine will eventually consume.

use desmos_core::bonding::probe::ProbeScheduler;
use desmos_core::bonding::score::LinkStats;
use desmos_core::bonding::score::DEFAULT_WINDOW;

/// Simulate a probe that arrives with a fixed RTT. Advances the
/// clock, issues a probe, advances the clock by `rtt_us`, and calls
/// `on_ack`. Returns the measured RTT.
fn probe_once(sched: &mut ProbeScheduler, stats: &mut LinkStats, now_us: &mut u64, rtt_us: u64) {
    let seq = sched.issue(*now_us);
    *now_us += rtt_us;
    let ack = sched.on_ack(seq, *now_us).unwrap();
    stats.record_rtt(ack.rtt_us);
}

/// Simulate a probe that never gets acknowledged. Advances the clock
/// past the scheduler timeout, drains, and records each timeout as a
/// loss in the stats.
fn probe_and_timeout(sched: &mut ProbeScheduler, stats: &mut LinkStats, now_us: &mut u64) {
    let _seq = sched.issue(*now_us);
    *now_us += sched.timeout_us() + 1;
    for _ in sched.drain_timeouts(*now_us) {
        stats.record_loss();
    }
}

#[test]
fn full_probe_cycle_reports_correct_rtt_and_no_loss() {
    let mut sched = ProbeScheduler::new(500_000, 2_000_000);
    let mut stats = LinkStats::new(DEFAULT_WINDOW);
    let mut clock = 0u64;

    for _ in 0..20 {
        probe_once(&mut sched, &mut stats, &mut clock, 10_000);
        clock += sched.interval_us();
    }

    assert_eq!(stats.rtt_ewma_us(), Some(10_000));
    assert_eq!(stats.loss_rate(), 0.0);
    assert_eq!(stats.jitter_us(), 0);
    assert_eq!(sched.in_flight_count(), 0);
    assert_eq!(sched.next_seq(), 20);
}

#[test]
fn timed_out_probes_become_loss_in_stats() {
    let mut sched = ProbeScheduler::new(500_000, 2_000_000);
    let mut stats = LinkStats::new(100);
    let mut clock = 0u64;

    // 8 successful probes, 2 timeouts.
    for _ in 0..8 {
        probe_once(&mut sched, &mut stats, &mut clock, 20_000);
        clock += sched.interval_us();
    }
    for _ in 0..2 {
        probe_and_timeout(&mut sched, &mut stats, &mut clock);
        clock += sched.interval_us();
    }

    assert_eq!(stats.outcome_count(), 10);
    assert_eq!(stats.loss_rate(), 0.2);
    assert_eq!(stats.rtt_ewma_us(), Some(20_000));
    assert_eq!(sched.in_flight_count(), 0);
}

#[test]
fn mixed_rtt_stream_shows_nonzero_jitter() {
    let mut sched = ProbeScheduler::new(500_000, 2_000_000);
    let mut stats = LinkStats::new(10);
    let mut clock = 0u64;

    let samples = [5_000u64, 7_000, 4_000, 9_000, 6_000, 5_500, 8_000];
    for &rtt in &samples {
        probe_once(&mut sched, &mut stats, &mut clock, rtt);
        clock += sched.interval_us();
    }

    let score = stats.score();
    assert!(score.rtt_us > 0);
    assert!(score.jitter_us > 0);
    assert_eq!(score.loss_rate, 0.0);
    assert!(score.composite > 0.0);
}

#[test]
fn rolling_window_evicts_old_outcomes() {
    // Window of 5: old losses drop off as new successes replace them.
    let mut sched = ProbeScheduler::new(500_000, 2_000_000);
    let mut stats = LinkStats::new(5);
    let mut clock = 0u64;

    // Start with 5 losses → 100% loss.
    for _ in 0..5 {
        probe_and_timeout(&mut sched, &mut stats, &mut clock);
        clock += sched.interval_us();
    }
    assert_eq!(stats.loss_rate(), 1.0);

    // 3 successes → 40% loss (2 losses remain in window).
    for _ in 0..3 {
        probe_once(&mut sched, &mut stats, &mut clock, 10_000);
        clock += sched.interval_us();
    }
    assert_eq!(stats.loss_rate(), 0.4);

    // 2 more successes → 0% loss.
    for _ in 0..2 {
        probe_once(&mut sched, &mut stats, &mut clock, 10_000);
        clock += sched.interval_us();
    }
    assert_eq!(stats.loss_rate(), 0.0);
}

#[test]
fn probe_cadence_matches_configured_interval() {
    let mut sched = ProbeScheduler::new(1_000_000, 2_000_000);
    let mut clock = 0u64;

    // First probe is always due.
    assert!(sched.is_due(clock));
    sched.issue(clock);
    // Not due until interval has fully elapsed.
    clock += 999_999;
    assert!(!sched.is_due(clock));
    clock += 1;
    assert!(sched.is_due(clock));
    sched.issue(clock);
    clock += sched.interval_us();
    assert!(sched.is_due(clock));
}
