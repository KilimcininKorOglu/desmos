//! Integration test for Task 28: PMTUD state machine driving
//! fragment sizing + reassembly roundtrip for payloads up to 4×
//! the tunnel MTU.
//!
//! `fragment` and `Reassembler` live in `desmos-proto`, `Pmtud`
//! lives in `desmos-core::net`. This test wires them together on
//! a fake clock to show the whole path from "probe loop measures
//! a 1372-byte MTU" → "a 5 KiB application packet splits into 4
//! fragments" → "receiver reassembles the original bytes".
//!
//! The Task 28 acceptance items this test covers:
//!
//! - Fragment + reassemble roundtrip for payloads up to 4× tunnel
//!   MTU (covered by `four_times_mtu_roundtrip_via_pmtud`).
//! - PMTUD converges within 3 s per link (covered by
//!   `pmtud_converges_under_three_seconds_at_500ms_cadence`).
//! - Fallback MTU 1280 on discovery failure (covered by
//!   `pmtud_falls_back_to_1280_when_link_refuses_every_probe`).

use desmos_core::net::Pmtud;
use desmos_core::net::PmtudState;
use desmos_proto::fragment::fragment;
use desmos_proto::fragment::Reassembler;
use desmos_proto::fragment::FRAGMENT_HEADER_LEN;

/// DWP header + Poly1305 tag. This is the per-packet tax the
/// pipeline pays on every encrypted outbound frame, and is the
/// number the fragmenter needs to know so the post-framing wire
/// size stays under the tunnel MTU.
const WIRE_FRAMING_OVERHEAD: usize = desmos_proto::HEADER_LEN + desmos_proto::crypto::aead::TAG_LEN;

/// Simulate a probe loop running at a fixed cadence. The real path
/// MTU is `real_mtu`; any probe at that size or smaller succeeds,
/// any larger probe times out. Returns `(probe_count, elapsed_ms)`.
fn run_probe_loop_until_done(
    pmtud: &mut Pmtud,
    real_mtu: u16,
    probe_interval_ms: u64,
) -> (u32, u64) {
    let mut probe_count = 0u32;
    let mut elapsed_ms = 0u64;
    while !pmtud.is_done() {
        let size = pmtud.current_probe_size();
        probe_count += 1;
        elapsed_ms += probe_interval_ms;
        if size <= real_mtu {
            pmtud.on_success(size);
        } else {
            pmtud.on_timeout(size);
        }
        // Belt-and-braces guard against a divergent state machine.
        assert!(probe_count < 50, "probe loop did not terminate");
    }
    (probe_count, elapsed_ms)
}

#[test]
fn pmtud_converges_under_three_seconds_at_500ms_cadence() {
    // Real link MTU = 1372 (common cable-modem PPPoE path).
    let mut pmtud = Pmtud::new(1500);
    let (probes, elapsed) = run_probe_loop_until_done(&mut pmtud, 1372, 500);
    assert!(elapsed <= 3_000, "took {elapsed} ms to converge, expected ≤ 3000",);
    assert!(matches!(pmtud.state(), PmtudState::Converged(_)));
    assert_eq!(pmtud.mtu(), 1372);
    assert!(probes <= 6, "needed {probes} probes");
}

#[test]
fn pmtud_falls_back_to_1280_when_link_refuses_every_probe() {
    // Simulate a totally broken link. `real_mtu` = 0 means every
    // probe times out, including the one at MIN_MTU, so the state
    // machine exhausts its attempt budget and declares Failed.
    let mut pmtud = Pmtud::new(1500);
    let (_probes, _elapsed) = run_probe_loop_until_done(&mut pmtud, 0, 500);
    assert!(matches!(pmtud.state(), PmtudState::Failed));
    // Effective MTU is the RFC 8201 minimum.
    assert_eq!(pmtud.mtu(), 1280);
}

#[test]
fn four_times_mtu_roundtrip_via_pmtud() {
    // Measure the tunnel MTU via a fake probe loop, compute the
    // per-fragment budget from it, fragment a ~4× tunnel MTU
    // payload, and reassemble it on the receiver side. This is
    // the closest we can get to the real pipeline without
    // actually running encryption + UDP in a unit test.
    let mut pmtud = Pmtud::new(1500);
    run_probe_loop_until_done(&mut pmtud, 1372, 500);
    let tunnel_mtu = pmtud.mtu();
    // Per-fragment pre-seal budget = tunnel MTU - wire framing
    // overhead (DWP header + Poly1305 tag). The fragmenter
    // subtracts the 4-byte sub-header itself.
    let max_fragment_len = (tunnel_mtu as usize) - WIRE_FRAMING_OVERHEAD;
    let body_per_fragment = max_fragment_len - FRAGMENT_HEADER_LEN;

    // Build an application payload that is exactly 4× the
    // per-fragment body size, so the fragmenter produces exactly
    // four pieces — the acceptance-bar scenario.
    let payload_len = body_per_fragment * 4;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i & 0xff) as u8).collect();

    let fragments = fragment(&payload, max_fragment_len, 0xA5A5).unwrap();
    assert_eq!(fragments.len(), 4);
    for frag in &fragments {
        assert!(
            frag.len() <= max_fragment_len,
            "fragment of {} bytes exceeds max {max_fragment_len}",
            frag.len(),
        );
    }

    // Reassemble in reverse order to hit the slot-based path.
    let mut reasm = Reassembler::default();
    assert!(reasm.push(&fragments[3]).unwrap().is_none());
    assert!(reasm.push(&fragments[2]).unwrap().is_none());
    assert!(reasm.push(&fragments[1]).unwrap().is_none());
    let out = reasm.push(&fragments[0]).unwrap().unwrap();
    assert_eq!(out, payload);
}

#[test]
fn pmtud_reset_restarts_probing_after_convergence() {
    // Regression for the failover path: when a link goes Dead and
    // later recovers, the new epoch must restart PMTUD from
    // scratch because the path could have changed.
    let mut pmtud = Pmtud::new(1500);
    run_probe_loop_until_done(&mut pmtud, 1372, 500);
    assert!(matches!(pmtud.state(), PmtudState::Converged(_)));

    pmtud.reset(1500);
    assert!(matches!(pmtud.state(), PmtudState::Probing));
    assert_eq!(pmtud.current_probe_size(), 1500);

    // Second convergence after a path change. The linear-shrink
    // strategy lands on the largest STEP-aligned probe ≤ the
    // real MTU, so a 1308-byte real path converges to 1308, a
    // 1300-byte real path converges to the next step below
    // (1244 is below 1280 → clamped to MIN_MTU).
    run_probe_loop_until_done(&mut pmtud, 1308, 500);
    assert_eq!(pmtud.mtu(), 1308);
}
