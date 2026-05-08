//! Path MTU Discovery state machine.
//!
//! Each bonding link runs one `Pmtud` instance. It decides what
//! packet size to probe next, converges on a measured MTU once a
//! probe succeeds, and falls back to the RFC 8201 §4 minimum
//! (1280 bytes) after a configured number of consecutive failures.
//!
//! The module is pure logic: no timers, no sockets. The probe loop
//! in `crates/desmos-core/src/bonding/probe.rs` drives `Pmtud` by
//! calling `on_success` / `on_timeout` from its ack / timeout
//! handlers, with the size it probed — `Pmtud` never has to know
//! how much wall-clock time has elapsed.
//!
//! # Strategy
//!
//! We do a linear shrink: start at the configured initial MTU, and
//! on every timeout step down by `STEP` bytes (default 64). Stop
//! shrinking at `MIN_MTU = 1280`; one more failure at 1280 marks
//! the link as [`PmtudState::Failed`], and from that point the
//! link uses 1280 as its effective MTU. Any success at any point
//! converges the state machine immediately.
//!
//! For the common 1500 → 1280 case this converges in 1-5 probes,
//! which at a 500 ms probe cadence is ≤ 2.5 s — well under the
//! "converges within 3 s per link" acceptance bar. Jumbogram links
//! would need more probes; the comment
//! on `STEP` documents how to tune it.

/// RFC 8201 §4 minimum path MTU. Every IPv6 path is required to
/// accept packets at least this large; any link that fails below
/// this point is effectively broken and falls back to 1280.
pub const MIN_MTU: u16 = 1280;

/// Step size between consecutive probes during shrink. 64 bytes is
/// small enough to narrow in on the true MTU without leaving gaps
/// that matter (a 63-byte error budget on the actual path MTU is
/// invisible to application-layer performance), and large enough
/// to converge in a handful of probes on jumbogram links.
pub const STEP: u16 = 64;

/// Default upper bound on consecutive failed probes before the
/// state machine declares the link `Failed` and falls back to
/// `MIN_MTU`. 5 matches the other streak constants elsewhere in
/// the bonding layer so operators have one number to remember.
pub const DEFAULT_MAX_ATTEMPTS: u8 = 5;

/// High-level state of a single link's PMTUD state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtudState {
    /// Still narrowing in on the MTU; `current_probe_size` holds
    /// the next size to try.
    Probing,
    /// Converged on a working MTU. The field is the final usable
    /// size; the probe loop can stop probing for this link.
    Converged(u16),
    /// Too many consecutive failures. Report `MIN_MTU` as the
    /// effective MTU and rely on external tooling (operator, Web
    /// UI) to investigate.
    Failed,
}

/// Per-link PMTUD state machine.
#[derive(Debug, Clone)]
pub struct Pmtud {
    state: PmtudState,
    current_probe: u16,
    attempts: u8,
    max_attempts: u8,
}

impl Pmtud {
    /// Build a new state machine starting at `initial_mtu`. The
    /// first `current_probe_size` call returns this value.
    /// `initial_mtu` is clamped to at least `MIN_MTU` so callers
    /// cannot hand in a value that would immediately fail.
    pub fn new(initial_mtu: u16) -> Self {
        let start = initial_mtu.max(MIN_MTU);
        Self {
            state: PmtudState::Probing,
            current_probe: start,
            attempts: 0,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Build with an explicit `max_attempts` cap. Used by tests
    /// and, eventually, by the operator-tunable config.
    pub fn with_max_attempts(initial_mtu: u16, max_attempts: u8) -> Self {
        let start = initial_mtu.max(MIN_MTU);
        Self { state: PmtudState::Probing, current_probe: start, attempts: 0, max_attempts }
    }

    /// Current state.
    pub fn state(&self) -> PmtudState {
        self.state
    }

    /// The size the probe loop should put on the wire next.
    /// Returns the converged / fallback size once `state` is no
    /// longer `Probing` — the probe loop can keep calling this
    /// safely even after convergence to get a "current MTU"
    /// reading, though it should also check `is_done()` to know
    /// whether to keep probing.
    pub fn current_probe_size(&self) -> u16 {
        match self.state {
            PmtudState::Probing => self.current_probe,
            PmtudState::Converged(size) => size,
            PmtudState::Failed => MIN_MTU,
        }
    }

    /// Effective MTU to use for outbound packets right now.
    pub fn mtu(&self) -> u16 {
        match self.state {
            PmtudState::Probing => self.current_probe,
            PmtudState::Converged(size) => size,
            PmtudState::Failed => MIN_MTU,
        }
    }

    /// `true` once the state machine has stopped probing (either
    /// successfully converged or permanently failed).
    pub fn is_done(&self) -> bool {
        !matches!(self.state, PmtudState::Probing)
    }

    /// Number of consecutive probe failures since the last success
    /// or reset.
    pub fn failed_attempts(&self) -> u8 {
        self.attempts
    }

    /// Handle a successful probe of `probed_size` bytes. The link
    /// can carry at least `probed_size`; we converge immediately.
    /// A later, larger success would need a fresh state machine.
    pub fn on_success(&mut self, probed_size: u16) {
        if matches!(self.state, PmtudState::Failed) {
            // Already declared Failed; ignore late acks so a
            // transient recovery does not undo the operator's
            // fallback path.
            return;
        }
        self.state = PmtudState::Converged(probed_size);
        self.attempts = 0;
    }

    /// Handle a probe timeout. If we can still shrink, step
    /// `current_probe` down by `STEP` and stay in `Probing`. If
    /// we have already hit `MIN_MTU` and exhausted `max_attempts`,
    /// declare the link `Failed`.
    pub fn on_timeout(&mut self, probed_size: u16) {
        if self.is_done() {
            return;
        }
        if probed_size != self.current_probe {
            // Stale timeout for a size we already moved past. Drop
            // it silently — the real current probe is still
            // outstanding.
            return;
        }
        self.attempts = self.attempts.saturating_add(1);

        if self.current_probe <= MIN_MTU {
            if self.attempts >= self.max_attempts {
                self.state = PmtudState::Failed;
            }
            // Keep probing at MIN_MTU until max_attempts is hit;
            // do not step below the RFC 8201 floor.
            return;
        }
        let next = self.current_probe.saturating_sub(STEP);
        self.current_probe = next.max(MIN_MTU);
    }

    /// Reset back to `Probing` at `initial_mtu`. Used when the
    /// link recovers from `Dead` (see the failover
    /// controller) — the new epoch starts from scratch because
    /// the path might have changed while the link was down.
    pub fn reset(&mut self, initial_mtu: u16) {
        let start = initial_mtu.max(MIN_MTU);
        self.state = PmtudState::Probing;
        self.current_probe = start;
        self.attempts = 0;
    }
}

impl Default for Pmtud {
    /// Default to a 1500-byte start — the most common Ethernet MTU.
    fn default() -> Self {
        Self::new(1500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_in_probing_at_initial_mtu() {
        let p = Pmtud::new(1500);
        assert_eq!(p.state(), PmtudState::Probing);
        assert_eq!(p.current_probe_size(), 1500);
        assert_eq!(p.mtu(), 1500);
        assert!(!p.is_done());
    }

    #[test]
    fn new_clamps_to_min_mtu() {
        let p = Pmtud::new(500);
        assert_eq!(p.current_probe_size(), MIN_MTU);
        let p2 = Pmtud::new(MIN_MTU);
        assert_eq!(p2.current_probe_size(), MIN_MTU);
    }

    #[test]
    fn success_converges_immediately() {
        let mut p = Pmtud::new(1500);
        p.on_success(1500);
        assert_eq!(p.state(), PmtudState::Converged(1500));
        assert_eq!(p.mtu(), 1500);
        assert!(p.is_done());
    }

    #[test]
    fn timeout_steps_down_by_64_bytes() {
        let mut p = Pmtud::new(1500);
        p.on_timeout(1500);
        assert_eq!(p.current_probe_size(), 1500 - STEP);
        p.on_timeout(1500 - STEP);
        assert_eq!(p.current_probe_size(), 1500 - 2 * STEP);
    }

    #[test]
    fn timeout_clamps_at_min_mtu() {
        // Start just above MIN_MTU so the first timeout would
        // naturally step below it. The clamp must catch that and
        // pin to MIN_MTU instead of underflowing.
        let mut p = Pmtud::new(MIN_MTU + 40);
        assert_eq!(p.current_probe_size(), MIN_MTU + 40);
        p.on_timeout(MIN_MTU + 40);
        assert_eq!(p.current_probe_size(), MIN_MTU);
        // Further timeouts stay clamped.
        p.on_timeout(MIN_MTU);
        assert_eq!(p.current_probe_size(), MIN_MTU);
    }

    #[test]
    fn stale_timeout_for_older_probe_is_ignored() {
        let mut p = Pmtud::new(1500);
        p.on_timeout(1500);
        assert_eq!(p.current_probe_size(), 1500 - STEP);
        // Late timeout for the old probe should not double-step.
        p.on_timeout(1500);
        assert_eq!(p.current_probe_size(), 1500 - STEP);
    }

    #[test]
    fn five_failures_at_min_mtu_mark_failed() {
        let mut p = Pmtud::new(MIN_MTU);
        for _ in 0..DEFAULT_MAX_ATTEMPTS {
            p.on_timeout(MIN_MTU);
        }
        assert_eq!(p.state(), PmtudState::Failed);
        assert_eq!(p.mtu(), MIN_MTU);
        assert!(p.is_done());
    }

    #[test]
    fn success_after_partial_shrink_converges_mid_way() {
        let mut p = Pmtud::new(1500);
        p.on_timeout(1500); // → 1436
        p.on_timeout(1436); // → 1372
        p.on_success(1372);
        assert_eq!(p.state(), PmtudState::Converged(1372));
        assert_eq!(p.mtu(), 1372);
    }

    #[test]
    fn success_while_failed_is_ignored() {
        let mut p = Pmtud::with_max_attempts(MIN_MTU, 1);
        p.on_timeout(MIN_MTU);
        assert_eq!(p.state(), PmtudState::Failed);
        // A transient late ack should not revive the state machine.
        p.on_success(1500);
        assert_eq!(p.state(), PmtudState::Failed);
    }

    #[test]
    fn reset_returns_to_probing() {
        let mut p = Pmtud::new(1500);
        p.on_success(1400);
        assert!(matches!(p.state(), PmtudState::Converged(_)));
        p.reset(1500);
        assert_eq!(p.state(), PmtudState::Probing);
        assert_eq!(p.current_probe_size(), 1500);
        assert_eq!(p.failed_attempts(), 0);
    }

    #[test]
    fn typical_1500_to_1372_converges_in_three_probes() {
        // Acceptance: TASKS.md Task 28 requires PMTUD to converge
        // within 3 s per link. At 500 ms per probe that is ≤ 6
        // probes; a realistic 1500→1372 shrink takes 3.
        let mut p = Pmtud::new(1500);
        let mut probe_count = 0;
        for _ in 0..10 {
            probe_count += 1;
            let size = p.current_probe_size();
            // Simulate a link whose real MTU is 1372.
            if size <= 1372 {
                p.on_success(size);
                break;
            }
            p.on_timeout(size);
        }
        assert!(matches!(p.state(), PmtudState::Converged(_)));
        assert_eq!(p.mtu(), 1372);
        assert!(probe_count <= 3, "expected ≤ 3 probes, took {probe_count}");
    }

    #[test]
    fn timeout_bumps_attempt_counter_until_success() {
        let mut p = Pmtud::new(1500);
        p.on_timeout(1500);
        p.on_timeout(1436);
        assert_eq!(p.failed_attempts(), 2);
        p.on_success(1372);
        assert_eq!(p.failed_attempts(), 0);
    }

    #[test]
    fn is_done_reflects_state() {
        let mut p = Pmtud::new(1500);
        assert!(!p.is_done());
        p.on_success(1500);
        assert!(p.is_done());

        let mut p2 = Pmtud::with_max_attempts(MIN_MTU, 1);
        p2.on_timeout(MIN_MTU);
        assert!(p2.is_done());
    }

    #[test]
    fn current_probe_after_convergence_returns_converged_value() {
        let mut p = Pmtud::new(1500);
        p.on_success(1400);
        assert_eq!(p.current_probe_size(), 1400);
    }

    #[test]
    fn mtu_after_failed_is_min_mtu() {
        let mut p = Pmtud::with_max_attempts(MIN_MTU, 1);
        p.on_timeout(MIN_MTU);
        assert_eq!(p.mtu(), MIN_MTU);
    }
}
