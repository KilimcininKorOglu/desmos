//! Failover controller: glue between per-link state machines and
//! the `Engine::swap_links` hot-path.
//!
//! The controller owns one [`LinkStateMachine`] per link and maps
//! probe samples / clock ticks into transitions. When a transition
//! crosses the "bondable" boundary (`Dead` ↔ anything else) it
//! rebuilds the engine's current `LinkTable` with the affected link
//! marked dead or healthy and hands the fresh table to
//! `Engine::swap_links`. Strategies see the change on their very
//! next `schedule` call with zero synchronisation on the hot path.
//!
//! The controller is single-writer, owned by the bonding engine's
//! periodic tick task. `on_probe` and `tick` return the set of
//! transitions that just fired so the caller can log them, emit
//! metrics, or push them onto a Web UI event stream.

use std::collections::HashMap;

use super::link::Link;
use super::link::LinkId;
use super::link::LinkTable;
use super::link_state::LinkState;
use super::link_state::LinkStateMachine;
use super::link_state::ProbeSample;
use super::link_state::Transition;
use super::Engine;

/// Single emitted transition paired with the link it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTransition {
    pub link_id: LinkId,
    pub from: LinkState,
    pub to: LinkState,
}

impl LinkTransition {
    fn from_transition(link_id: LinkId, t: Transition) -> Self {
        Self { link_id, from: t.from, to: t.to }
    }

    /// `true` when the transition crossed the bondable boundary,
    /// i.e. the link became sendable when it was not before, or
    /// stopped being sendable when it was.
    pub fn crosses_bondable_boundary(&self) -> bool {
        self.from.is_bondable() != self.to.is_bondable()
    }
}

/// Failover controller.
#[derive(Debug, Default)]
pub struct FailoverController {
    machines: HashMap<LinkId, LinkStateMachine>,
}

impl FailoverController {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a link with the controller. Idempotent: re-registering
    /// an existing link is a no-op so the caller can safely call this
    /// from `Engine::swap_links` paths without checking.
    pub fn register(&mut self, link_id: LinkId) {
        self.machines.entry(link_id).or_default();
    }

    /// Drop all state for a removed link.
    pub fn deregister(&mut self, link_id: LinkId) {
        self.machines.remove(&link_id);
    }

    /// Number of links currently tracked.
    pub fn len(&self) -> usize {
        self.machines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Current state of one link. `None` when the link is not
    /// registered.
    pub fn state_of(&self, link_id: LinkId) -> Option<LinkState> {
        self.machines.get(&link_id).map(|m| m.state())
    }

    /// Snapshot of every tracked link's state. Handy for the status
    /// command and the Web UI.
    pub fn snapshot(&self) -> HashMap<LinkId, LinkState> {
        self.machines.iter().map(|(&k, v)| (k, v.state())).collect()
    }

    /// Feed a probe outcome for one link. Auto-registers the link if
    /// it has not been seen before.
    pub fn on_probe(
        &mut self,
        link_id: LinkId,
        sample: ProbeSample,
        now_ms: u64,
    ) -> Option<LinkTransition> {
        let machine = self.machines.entry(link_id).or_default();
        machine.on_probe(sample, now_ms).map(|t| LinkTransition::from_transition(link_id, t))
    }

    /// Periodic time tick. Returns every `Probation → Healthy`
    /// transition that fired now that enough time has elapsed.
    pub fn tick(&mut self, now_ms: u64) -> Vec<LinkTransition> {
        let mut out = Vec::new();
        for (&link_id, machine) in &mut self.machines {
            if let Some(t) = machine.tick(now_ms) {
                out.push(LinkTransition::from_transition(link_id, t));
            }
        }
        out
    }

    /// Rebuild the engine's current `LinkTable` so every link's
    /// `healthy` flag reflects the state machine's verdict, then
    /// atomically swap it in. Called after any call to `on_probe` /
    /// `tick` that produced transitions crossing the bondable
    /// boundary; cheap when nothing changed.
    pub fn apply_to_engine(&self, engine: &Engine) {
        let current = engine.links_snapshot();
        let mut dirty = false;
        let rebuilt: Vec<Link> = current
            .all()
            .iter()
            .map(|existing| {
                let state = self
                    .machines
                    .get(&existing.id)
                    .map(|m| m.state())
                    .unwrap_or(LinkState::Healthy);
                let should_be_healthy = state.is_bondable();
                if existing.healthy != should_be_healthy {
                    dirty = true;
                }
                Link {
                    id: existing.id,
                    name: existing.name.clone(),
                    peer: existing.peer,
                    weight: existing.weight,
                    healthy: should_be_healthy,
                }
            })
            .collect();
        if dirty {
            engine.swap_links(LinkTable::new(rebuilt));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bonding::link::Link;
    use crate::bonding::link::LinkTable;
    use crate::bonding::link_state::HIGH_LOSS_STREAK;
    use crate::bonding::link_state::NO_RESPONSE_STREAK;
    use crate::bonding::link_state::PROBATION_MS;
    use crate::bonding::link_state::RECOVERY_STREAK;
    use crate::bonding::Engine;

    fn sample_addr() -> std::net::SocketAddr {
        "127.0.0.1:51820".parse().unwrap()
    }

    fn three_link_engine() -> Engine {
        Engine::new_with_round_robin(LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
            Link::new(3, "c", sample_addr(), 10),
        ]))
    }

    fn two_link_engine() -> Engine {
        Engine::new_with_round_robin(LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
        ]))
    }

    #[test]
    fn register_is_idempotent() {
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(1);
        ctrl.register(2);
        assert_eq!(ctrl.len(), 2);
    }

    #[test]
    fn deregister_removes_state() {
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.deregister(1);
        assert!(ctrl.is_empty());
        assert!(ctrl.state_of(1).is_none());
    }

    #[test]
    fn on_probe_auto_registers_unknown_link() {
        let mut ctrl = FailoverController::new();
        ctrl.on_probe(7, ProbeSample::Good, 0);
        assert_eq!(ctrl.state_of(7), Some(LinkState::Healthy));
    }

    #[test]
    fn on_probe_returns_transition_only_when_state_changes() {
        let mut ctrl = FailoverController::new();
        // Good probes on a fresh Healthy link never transition.
        assert!(ctrl.on_probe(1, ProbeSample::Good, 0).is_none());
        // NoResponse streak × 3 → Dead.
        ctrl.on_probe(1, ProbeSample::NoResponse, 0);
        ctrl.on_probe(1, ProbeSample::NoResponse, 0);
        let t = ctrl.on_probe(1, ProbeSample::NoResponse, 0).unwrap();
        assert_eq!(t.link_id, 1);
        assert_eq!(t.to, LinkState::Dead);
        assert!(t.crosses_bondable_boundary());
    }

    #[test]
    fn dead_link_is_swapped_out_of_the_engine_link_table() {
        let engine = three_link_engine();
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);
        ctrl.register(3);

        // Link 2 goes dead.
        for _ in 0..NO_RESPONSE_STREAK {
            ctrl.on_probe(2, ProbeSample::NoResponse, 0);
        }
        ctrl.apply_to_engine(&engine);

        let snap = engine.links_snapshot();
        let healthy_ids: Vec<u32> = snap.healthy().iter().map(|l| l.id).collect();
        assert_eq!(healthy_ids, vec![1, 3]);
    }

    #[test]
    fn recovered_link_reappears_after_probation_window() {
        let engine = two_link_engine();
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);

        // Kill link 1.
        for _ in 0..NO_RESPONSE_STREAK {
            ctrl.on_probe(1, ProbeSample::NoResponse, 0);
        }
        ctrl.apply_to_engine(&engine);
        assert_eq!(engine.links_snapshot().healthy().len(), 1);

        // Three good probes put it in Probation (still bondable).
        for _ in 0..RECOVERY_STREAK {
            ctrl.on_probe(1, ProbeSample::Good, 100);
        }
        ctrl.apply_to_engine(&engine);
        assert_eq!(engine.links_snapshot().healthy().len(), 2);
        assert!(matches!(ctrl.state_of(1).unwrap(), LinkState::Probation { .. }));

        // Tick past the probation window → Healthy.
        let transitions = ctrl.tick(100 + PROBATION_MS);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].link_id, 1);
        assert_eq!(transitions[0].to, LinkState::Healthy);
        assert_eq!(ctrl.state_of(1), Some(LinkState::Healthy));
    }

    #[test]
    fn apply_to_engine_is_a_noop_when_nothing_changed() {
        let engine = three_link_engine();
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);
        ctrl.register(3);

        // Hand-rebuild current snapshot to capture the `Arc<LinkTable>`
        // pointer before the call.
        let before = engine.links_snapshot();
        ctrl.apply_to_engine(&engine);
        let after = engine.links_snapshot();

        // No transitions, no swap: the Arc we held should still be the
        // current one (same pointer).
        assert!(std::sync::Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn tick_on_healthy_links_returns_empty() {
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);
        assert!(ctrl.tick(1_000_000).is_empty());
    }

    #[test]
    fn five_high_loss_probes_do_not_cross_bondable_boundary() {
        // Degraded is still bondable, so `apply_to_engine` must not
        // evict the link. Verifies the boundary helper.
        let engine = two_link_engine();
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);

        for _ in 0..HIGH_LOSS_STREAK {
            ctrl.on_probe(1, ProbeSample::HighLoss, 0);
        }
        ctrl.apply_to_engine(&engine);
        // Still 2 healthy links.
        assert_eq!(engine.links_snapshot().healthy().len(), 2);
        assert_eq!(ctrl.state_of(1), Some(LinkState::Degraded));
    }

    #[test]
    fn snapshot_reports_every_registered_link() {
        let mut ctrl = FailoverController::new();
        ctrl.register(1);
        ctrl.register(2);
        ctrl.register(3);
        let snap = ctrl.snapshot();
        assert_eq!(snap.len(), 3);
        for id in [1, 2, 3] {
            assert_eq!(snap.get(&id), Some(&LinkState::Healthy));
        }
    }
}
