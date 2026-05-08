//! Per-link health state machine.
//!
//! Replaces the coarse `Link::healthy: bool` flag with
//! the four-state model from `IMPLEMENTATION.md §2.4`:
//!
//! ```text
//!                      HighLoss×5
//!              ┌────────────────────────► Degraded
//!              │                              │
//!  Healthy ────┤                              │ Good×3
//!              │                              ▼
//!              │          NoResponse×3    Probation
//!              └────────────────────────► (until T)
//!              ▲                              │
//!              │                              │  now >= until
//!              └──────────────────────────────┘
//! ```
//!
//! `Good×3` from `Dead` also transitions to `Probation`, so a link
//! that goes completely silent and then recovers re-enters at
//! reduced weight for 10 seconds before it is trusted again.
//!
//! The machine is driven by [`ProbeSample`] events, which the
//! probe loop produces from every ack/timeout pair. Consecutive
//! non-matching samples reset the streak counters so one transient
//! spike does not flip the state.
//!
//! Time is passed in milliseconds so the machine stays pure logic —
//! no direct `std::time::Instant` dependency, no hidden global clock.
//! The caller (the bonding engine's periodic tick) owns the clock.

/// Duration a recovered link spends in `Probation` before it is
/// considered healthy again. Matches SPEC §3.2.4 (10 seconds).
pub const PROBATION_MS: u64 = 10_000;

/// Number of consecutive `HighLoss` probes required to demote a
/// `Healthy` link to `Degraded`.
pub const HIGH_LOSS_STREAK: u8 = 5;

/// Number of consecutive `NoResponse` probes required to mark a
/// `Healthy` or `Degraded` link as `Dead`.
pub const NO_RESPONSE_STREAK: u8 = 3;

/// Number of consecutive `Good` probes required to promote a
/// degraded or dead link into `Probation`.
pub const RECOVERY_STREAK: u8 = 3;

/// Per-probe outcome classification. The probe loop produces these
/// from the `LinkStats` after every measurement cycle: a
/// successful ack + low loss is `Good`, a high-loss probe stream is
/// `HighLoss`, a probe that never answered is `NoResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSample {
    Good,
    HighLoss,
    NoResponse,
}

/// Current link health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Healthy,
    /// A recovered link that is trusted at reduced weight until
    /// `until_ms` is reached on the monotonic clock.
    Probation {
        until_ms: u64,
    },
    /// Elevated loss rate but still reachable. Strategies should
    /// deprioritise degraded links but keep sending some traffic.
    Degraded,
    /// No response for long enough that we treat the link as dead.
    /// The outbound pipeline must skip it entirely; a `Good` probe
    /// burst moves it back to `Probation`.
    Dead,
}

impl LinkState {
    /// `true` when the link can still receive data-plane traffic.
    /// `Dead` is the only state that must be excluded from the
    /// outbound scheduler's healthy set.
    pub fn is_bondable(&self) -> bool {
        !matches!(self, LinkState::Dead)
    }
}

/// Transition report returned by [`LinkStateMachine::on_probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub from: LinkState,
    pub to: LinkState,
}

/// Hysteretic state machine. One instance per link.
#[derive(Debug, Clone)]
pub struct LinkStateMachine {
    state: LinkState,
    high_loss_streak: u8,
    no_response_streak: u8,
    recovery_streak: u8,
}

impl Default for LinkStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkStateMachine {
    pub const fn new() -> Self {
        Self {
            state: LinkState::Healthy,
            high_loss_streak: 0,
            no_response_streak: 0,
            recovery_streak: 0,
        }
    }

    pub fn state(&self) -> LinkState {
        self.state
    }

    pub fn is_bondable(&self) -> bool {
        self.state.is_bondable()
    }

    /// Feed a probe outcome. Returns `Some(Transition)` when the
    /// state changed, `None` when it stayed the same. Callers can
    /// ignore the `Option` — the new state is always readable via
    /// [`state`](Self::state).
    pub fn on_probe(&mut self, sample: ProbeSample, now_ms: u64) -> Option<Transition> {
        // Reset streaks that this sample does not extend. A single
        // `Good` clears both loss and no-response counters; a single
        // `HighLoss` clears recovery and no-response; a single
        // `NoResponse` clears recovery and loss.
        match sample {
            ProbeSample::Good => {
                self.high_loss_streak = 0;
                self.no_response_streak = 0;
                self.recovery_streak = self.recovery_streak.saturating_add(1);
            }
            ProbeSample::HighLoss => {
                self.recovery_streak = 0;
                self.no_response_streak = 0;
                self.high_loss_streak = self.high_loss_streak.saturating_add(1);
            }
            ProbeSample::NoResponse => {
                self.recovery_streak = 0;
                self.high_loss_streak = 0;
                self.no_response_streak = self.no_response_streak.saturating_add(1);
            }
        }

        let next = self.compute_next(now_ms);
        if next != self.state {
            let from = self.state;
            self.state = next;
            // Reset every streak on a transition so the new state
            // starts fresh; otherwise a Healthy→Dead drop would
            // count the same NoResponse streak twice on the way to
            // any further transition.
            self.high_loss_streak = 0;
            self.no_response_streak = 0;
            self.recovery_streak = 0;
            Some(Transition { from, to: next })
        } else {
            None
        }
    }

    /// Time-based tick. Called periodically by the bonding engine;
    /// returns `Some(Transition)` when a `Probation` link's window
    /// has elapsed and it can be promoted back to `Healthy`.
    pub fn tick(&mut self, now_ms: u64) -> Option<Transition> {
        if let LinkState::Probation { until_ms } = self.state {
            if now_ms >= until_ms {
                let from = self.state;
                self.state = LinkState::Healthy;
                self.recovery_streak = 0;
                return Some(Transition { from, to: LinkState::Healthy });
            }
        }
        None
    }

    fn compute_next(&self, now_ms: u64) -> LinkState {
        match self.state {
            LinkState::Healthy => {
                if self.no_response_streak >= NO_RESPONSE_STREAK {
                    LinkState::Dead
                } else if self.high_loss_streak >= HIGH_LOSS_STREAK {
                    LinkState::Degraded
                } else {
                    LinkState::Healthy
                }
            }
            LinkState::Degraded => {
                if self.no_response_streak >= NO_RESPONSE_STREAK {
                    LinkState::Dead
                } else if self.recovery_streak >= RECOVERY_STREAK {
                    LinkState::Probation { until_ms: now_ms + PROBATION_MS }
                } else {
                    LinkState::Degraded
                }
            }
            LinkState::Dead => {
                if self.recovery_streak >= RECOVERY_STREAK {
                    LinkState::Probation { until_ms: now_ms + PROBATION_MS }
                } else {
                    LinkState::Dead
                }
            }
            LinkState::Probation { until_ms } => {
                // A `HighLoss` / `NoResponse` during probation
                // pushes the link straight back to Degraded / Dead.
                if self.no_response_streak >= NO_RESPONSE_STREAK {
                    LinkState::Dead
                } else if self.high_loss_streak >= HIGH_LOSS_STREAK {
                    LinkState::Degraded
                } else if now_ms >= until_ms {
                    LinkState::Healthy
                } else {
                    LinkState::Probation { until_ms }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_machine_starts_healthy() {
        let m = LinkStateMachine::new();
        assert_eq!(m.state(), LinkState::Healthy);
        assert!(m.is_bondable());
    }

    #[test]
    fn good_probe_on_healthy_stays_healthy() {
        let mut m = LinkStateMachine::new();
        for _ in 0..10 {
            assert!(m.on_probe(ProbeSample::Good, 0).is_none());
        }
        assert_eq!(m.state(), LinkState::Healthy);
    }

    #[test]
    fn five_consecutive_high_loss_demotes_to_degraded() {
        let mut m = LinkStateMachine::new();
        for _ in 0..4 {
            assert!(m.on_probe(ProbeSample::HighLoss, 0).is_none());
        }
        let t = m.on_probe(ProbeSample::HighLoss, 0).unwrap();
        assert_eq!(t.from, LinkState::Healthy);
        assert_eq!(t.to, LinkState::Degraded);
    }

    #[test]
    fn three_consecutive_no_response_marks_dead() {
        let mut m = LinkStateMachine::new();
        assert!(m.on_probe(ProbeSample::NoResponse, 0).is_none());
        assert!(m.on_probe(ProbeSample::NoResponse, 0).is_none());
        let t = m.on_probe(ProbeSample::NoResponse, 0).unwrap();
        assert_eq!(t.to, LinkState::Dead);
        assert!(!m.is_bondable());
    }

    #[test]
    fn one_good_probe_breaks_high_loss_streak() {
        let mut m = LinkStateMachine::new();
        m.on_probe(ProbeSample::HighLoss, 0);
        m.on_probe(ProbeSample::HighLoss, 0);
        m.on_probe(ProbeSample::HighLoss, 0);
        m.on_probe(ProbeSample::HighLoss, 0);
        m.on_probe(ProbeSample::Good, 0);
        // Still healthy; the HighLoss streak was reset.
        assert_eq!(m.state(), LinkState::Healthy);
        // And four more HighLoss alone are not enough to demote.
        for _ in 0..4 {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        assert_eq!(m.state(), LinkState::Healthy);
    }

    #[test]
    fn three_good_probes_from_degraded_enter_probation() {
        let mut m = LinkStateMachine::new();
        // Drop to Degraded.
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        assert_eq!(m.state(), LinkState::Degraded);
        // Three good probes → Probation(until=1000 + 10_000).
        m.on_probe(ProbeSample::Good, 1_000);
        m.on_probe(ProbeSample::Good, 1_000);
        let t = m.on_probe(ProbeSample::Good, 1_000).unwrap();
        assert_eq!(t.from, LinkState::Degraded);
        match t.to {
            LinkState::Probation { until_ms } => assert_eq!(until_ms, 11_000),
            other => panic!("expected Probation, got {other:?}"),
        }
    }

    #[test]
    fn three_good_probes_from_dead_enter_probation() {
        let mut m = LinkStateMachine::new();
        for _ in 0..NO_RESPONSE_STREAK {
            m.on_probe(ProbeSample::NoResponse, 0);
        }
        assert_eq!(m.state(), LinkState::Dead);
        m.on_probe(ProbeSample::Good, 500);
        m.on_probe(ProbeSample::Good, 500);
        let t = m.on_probe(ProbeSample::Good, 500).unwrap();
        match t.to {
            LinkState::Probation { until_ms } => assert_eq!(until_ms, 10_500),
            other => panic!("expected Probation, got {other:?}"),
        }
    }

    #[test]
    fn probation_promotes_to_healthy_via_tick() {
        let mut m = LinkStateMachine::new();
        // Degrade then recover into Probation at t=0.
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        for _ in 0..RECOVERY_STREAK {
            m.on_probe(ProbeSample::Good, 0);
        }
        assert!(matches!(m.state(), LinkState::Probation { .. }));

        // Tick before the window: no transition.
        assert!(m.tick(5_000).is_none());
        assert!(matches!(m.state(), LinkState::Probation { .. }));

        // Tick at the expiry: promoted.
        let t = m.tick(PROBATION_MS).unwrap();
        assert_eq!(t.to, LinkState::Healthy);
        assert_eq!(m.state(), LinkState::Healthy);
    }

    #[test]
    fn probation_high_loss_falls_back_to_degraded() {
        let mut m = LinkStateMachine::new();
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        for _ in 0..RECOVERY_STREAK {
            m.on_probe(ProbeSample::Good, 0);
        }
        assert!(matches!(m.state(), LinkState::Probation { .. }));

        // 5 more HighLoss drop the link back to Degraded.
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 1_000);
        }
        assert_eq!(m.state(), LinkState::Degraded);
    }

    #[test]
    fn probation_no_response_falls_back_to_dead() {
        let mut m = LinkStateMachine::new();
        for _ in 0..NO_RESPONSE_STREAK {
            m.on_probe(ProbeSample::NoResponse, 0);
        }
        for _ in 0..RECOVERY_STREAK {
            m.on_probe(ProbeSample::Good, 0);
        }
        assert!(matches!(m.state(), LinkState::Probation { .. }));
        for _ in 0..NO_RESPONSE_STREAK {
            m.on_probe(ProbeSample::NoResponse, 1_000);
        }
        assert_eq!(m.state(), LinkState::Dead);
    }

    #[test]
    fn degraded_three_no_response_drops_to_dead() {
        let mut m = LinkStateMachine::new();
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        assert_eq!(m.state(), LinkState::Degraded);
        for _ in 0..NO_RESPONSE_STREAK {
            m.on_probe(ProbeSample::NoResponse, 0);
        }
        assert_eq!(m.state(), LinkState::Dead);
    }

    #[test]
    fn is_bondable_reflects_state() {
        let mut m = LinkStateMachine::new();
        assert!(m.is_bondable()); // Healthy
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        assert!(m.is_bondable()); // Degraded
        for _ in 0..NO_RESPONSE_STREAK {
            m.on_probe(ProbeSample::NoResponse, 0);
        }
        assert!(!m.is_bondable()); // Dead
    }

    #[test]
    fn tick_on_non_probation_is_noop() {
        let mut m = LinkStateMachine::new();
        assert!(m.tick(1_000_000).is_none());
        assert_eq!(m.state(), LinkState::Healthy);
    }

    #[test]
    fn transition_resets_streaks() {
        // Regression for a bug where a Healthy → Degraded drop would
        // leave `high_loss_streak` at 5, so the very next HighLoss
        // would still see a streak of 6 and could trigger premature
        // follow-on transitions.
        let mut m = LinkStateMachine::new();
        for _ in 0..HIGH_LOSS_STREAK {
            m.on_probe(ProbeSample::HighLoss, 0);
        }
        assert_eq!(m.state(), LinkState::Degraded);
        // Single HighLoss should not do anything further.
        m.on_probe(ProbeSample::HighLoss, 0);
        assert_eq!(m.state(), LinkState::Degraded);
    }
}
