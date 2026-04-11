//! Integration test for Task 27: `LinkStateMachine` +
//! `FailoverController` driving a live bonding engine through a
//! failover / recovery cycle.
//!
//! The acceptance items from TASKS.md:
//!
//! 1. Transitions match PRD §4.4 exactly — covered by the
//!    `link_state.rs` unit tests.
//! 2. Failover redistribution within 1 s of dead detection — this
//!    test simulates a probe loop running every 200 ms, kills one
//!    of two links, and measures the number of ticks (= wall time)
//!    between the first `NoResponse` and the first `schedule` call
//!    that stops picking the dead link.
//! 3. Probation reintegrates after 10 s at reduced weight — this
//!    test reuses the same fake clock to confirm the probation
//!    window ticks back to Healthy after `PROBATION_MS` have
//!    elapsed.

use std::sync::Arc;

use desmos_core::bonding::link_state::PROBATION_MS;
use desmos_core::bonding::Engine;
use desmos_core::bonding::FailoverController;
use desmos_core::bonding::Link;
use desmos_core::bonding::LinkSelection;
use desmos_core::bonding::LinkState;
use desmos_core::bonding::LinkTable;
use desmos_core::bonding::ProbeSample;
use desmos_core::bonding::Redundant;
use desmos_proto::InterfaceId;
use desmos_proto::PacketMeta;
use desmos_proto::TimestampUs;

fn sample_packet() -> PacketMeta {
    PacketMeta::outbound(InterfaceId(0), TimestampUs(0))
}

fn sample_addr() -> std::net::SocketAddr {
    "127.0.0.1:51820".parse().unwrap()
}

fn two_link_rr_engine() -> Engine {
    Engine::new_with_round_robin(LinkTable::new(vec![
        Link::new(1, "primary", sample_addr(), 10),
        Link::new(2, "secondary", sample_addr(), 10),
    ]))
}

#[test]
fn failover_under_one_second_of_wall_time() {
    // Probe cadence in this test: one sample every 200 ms of
    // simulated time. The state machine needs 3 consecutive
    // NoResponse samples to mark a link Dead, so total wall time
    // = 3 × 200 ms = 600 ms, well under the 1 s acceptance bar.
    const PROBE_INTERVAL_MS: u64 = 200;

    let engine = two_link_rr_engine();
    let mut ctrl = FailoverController::new();
    ctrl.register(1);
    ctrl.register(2);

    // Warm up: confirm both links are selected by the scheduler.
    let p = sample_packet();
    let mut before_hit_2 = false;
    for _ in 0..4 {
        if let LinkSelection::One(link) = engine.schedule(&p) {
            if link.id == 2 {
                before_hit_2 = true;
            }
        }
    }
    assert!(before_hit_2, "warm-up should have picked link 2 at least once");

    // Link 1 starts dropping probes. The probe loop publishes
    // NoResponse every 200 ms of simulated time.
    let mut now_ms = 10_000u64;
    let mut dead_at_ms: Option<u64> = None;
    for _ in 0..10 {
        now_ms += PROBE_INTERVAL_MS;
        if let Some(t) = ctrl.on_probe(1, ProbeSample::NoResponse, now_ms) {
            if t.to == LinkState::Dead {
                dead_at_ms = Some(now_ms);
                break;
            }
        }
    }
    let dead_at = dead_at_ms.expect("link 1 should have reached Dead");
    let elapsed = dead_at - 10_000;
    assert!(elapsed <= 1_000, "failover detection took {elapsed} ms, expected ≤ 1000",);

    // Apply the transition to the engine and verify the scheduler
    // stops picking link 1 on every subsequent call.
    ctrl.apply_to_engine(&engine);
    for _ in 0..50 {
        match engine.schedule(&p) {
            LinkSelection::One(link) => assert_eq!(link.id, 2),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn probation_reintegrates_link_after_ten_seconds() {
    let engine = two_link_rr_engine();
    let mut ctrl = FailoverController::new();
    ctrl.register(1);
    ctrl.register(2);

    // Kill link 1 at t = 0.
    for _ in 0..3 {
        ctrl.on_probe(1, ProbeSample::NoResponse, 0);
    }
    ctrl.apply_to_engine(&engine);
    assert_eq!(engine.links_snapshot().healthy().len(), 1);

    // Between t = 0 and t = 1000 ms three good probes bring the
    // link into Probation. The link is bondable again, so the
    // engine sees two healthy links already.
    for _ in 0..3 {
        ctrl.on_probe(1, ProbeSample::Good, 500);
    }
    ctrl.apply_to_engine(&engine);
    assert_eq!(engine.links_snapshot().healthy().len(), 2);
    assert!(matches!(ctrl.state_of(1).unwrap(), LinkState::Probation { .. }));

    // Tick the failover loop: nothing fires until the probation
    // window expires.
    assert!(ctrl.tick(500 + PROBATION_MS - 1).is_empty());
    assert!(matches!(ctrl.state_of(1).unwrap(), LinkState::Probation { .. }));

    // Tick exactly at the expiry → Healthy.
    let transitions = ctrl.tick(500 + PROBATION_MS);
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].to, LinkState::Healthy);
}

#[test]
fn redundant_engine_sees_fan_out_shrink_on_failover() {
    let engine = Engine::new(
        Arc::new(Redundant::new()),
        LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
            Link::new(3, "c", sample_addr(), 10),
        ]),
    );
    let mut ctrl = FailoverController::new();
    for id in [1, 2, 3] {
        ctrl.register(id);
    }
    let p = sample_packet();

    // Before failover: all three links in the Many.
    match engine.schedule(&p) {
        LinkSelection::Many(links) => assert_eq!(links.len(), 3),
        other => panic!("unexpected {other:?}"),
    }

    // Kill link 2.
    for _ in 0..3 {
        ctrl.on_probe(2, ProbeSample::NoResponse, 0);
    }
    ctrl.apply_to_engine(&engine);

    match engine.schedule(&p) {
        LinkSelection::Many(links) => {
            let ids: Vec<u32> = links.iter().map(|l| l.id).collect();
            assert_eq!(ids, vec![1, 3]);
        }
        other => panic!("unexpected {other:?}"),
    }
}
