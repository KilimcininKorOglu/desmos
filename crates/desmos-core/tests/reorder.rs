//! Reorder buffer integration tests and a 100 000-packet latency
//! bench. `criterion` is blocked by the MSRV 1.75 wall (see MEMORY
//! landmines), so instead of a real benchmark we run a deterministic
//! xorshift-driven workload and assert on the p99 per-push latency.
//!
//! Task 22 acceptance bar: p99 added latency < 1 ms. The bench runs
//! on any release or debug build and reports the measured p99 when
//! it fails.

use std::time::Instant;

use desmos_core::bonding::ReorderBuffer;

/// xorshift64 RNG — identical to the pattern used in the TOML,
/// antireplay, and session fuzzers elsewhere in the workspace.
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

/// Shuffle a contiguous seq range so nearby seqs arrive close in time
/// but not in strict order — closer to the real bonded-traffic shape.
fn shuffled_window(base: u64, len: usize, spread: u64, rng: &mut Xorshift64) -> Vec<u64> {
    // Produce a permutation by sliding a small random offset over a
    // contiguous range. `spread` controls how far a packet can drift
    // from its natural position.
    let mut out: Vec<u64> = (base..base + len as u64).collect();
    for i in 0..len {
        let jitter = (rng.next_u64() % (spread + 1)) as usize;
        let j = (i + jitter).min(len - 1);
        out.swap(i, j);
    }
    out
}

#[test]
fn in_order_100k_is_zero_buffered() {
    let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(256, 1_000);
    for seq in 0..100_000u64 {
        let out = buf.push(seq, seq as u32, 0);
        assert_eq!(out.len(), 1);
    }
    assert_eq!(buf.delivered_count(), 100_000);
    assert_eq!(buf.lost_count(), 0);
    assert_eq!(buf.duplicate_count(), 0);
    assert_eq!(buf.pending_count(), 0);
}

#[test]
fn shuffled_window_preserves_order_and_counters() {
    let mut rng = Xorshift64::new(0xDE5D_0022_0000_0001);
    let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(256, 1_000);
    let mut delivered: Vec<u32> = Vec::with_capacity(9_600);

    const CHUNK: u64 = 64;
    const CHUNKS: u64 = 150;
    for i in 0..CHUNKS {
        let base = i * CHUNK;
        // Chunk 0 is in-order so the buffer initialises at seq 0;
        // otherwise the first shuffled push would set next_expected
        // to a non-zero value and early seqs would be rejected as
        // late duplicates.
        let chunk: Vec<u64> = if i == 0 {
            (base..base + CHUNK).collect()
        } else {
            shuffled_window(base, CHUNK as usize, 8, &mut rng)
        };
        for &seq in &chunk {
            let out = buf.push(seq, seq as u32, 0);
            delivered.extend(out);
        }
    }
    // Any stragglers still in the buffer at the end will be released
    // by a late `poll_timeout` call; nudge it with a large now_ms so
    // the gap timeout fires. Loop until it stabilises because each
    // call only clears one head gap.
    loop {
        let out = buf.poll_timeout(u64::MAX);
        if out.is_empty() {
            break;
        }
        delivered.extend(out);
    }

    let total = (CHUNK * CHUNKS) as usize;
    assert_eq!(delivered.len(), total);
    for (i, v) in delivered.iter().enumerate() {
        assert_eq!(*v as u64, i as u64, "mismatch at position {i}");
    }
    // With a generous window (256) and a jitter spread of 8, nothing
    // should have been lost or duplicated.
    assert_eq!(buf.lost_count(), 0);
    assert_eq!(buf.duplicate_count(), 0);
}

#[test]
fn p99_push_latency_under_1ms_across_100k_packets() {
    let mut rng = Xorshift64::new(0xDE5D_0022_1111_2222);
    let mut buf: ReorderBuffer<u64> = ReorderBuffer::new(256, 1_000);
    let mut samples: Vec<u128> = Vec::with_capacity(100_000);

    // 100 000 packets with moderate jitter (spread 4) so some
    // buffering happens on every chunk and the latency measurement
    // reflects real reorder work, not just the in-order fast path.
    let mut base = 0u64;
    while base < 100_000 {
        let chunk = shuffled_window(base, 32, 4, &mut rng);
        for &seq in &chunk {
            let start = Instant::now();
            let _ = buf.push(seq, seq, 0);
            samples.push(start.elapsed().as_nanos());
        }
        base += 32;
    }

    samples.sort_unstable();
    let idx = (samples.len() as f64 * 0.99) as usize;
    let p99_ns = samples[idx];
    let p99_ms = p99_ns as f64 / 1_000_000.0;
    // Generous bound because `cargo test` defaults to debug builds
    // and the BTreeMap insert path is not optimised. The acceptance
    // bar in TASKS.md is "< 1 ms"; we assert 5 ms in debug and 1 ms
    // in release to catch runaway regressions either way.
    let bound_ms = if cfg!(debug_assertions) { 5.0 } else { 1.0 };
    assert!(p99_ms < bound_ms, "p99 per-push latency {p99_ms:.3} ms exceeds {bound_ms} ms bound",);
    assert_eq!(buf.lost_count(), 0);
}

#[test]
fn random_stream_with_occasional_drops_reports_correct_lost_count() {
    // Deterministic workload that drops every 17th packet after the
    // initial one (seq 0 is always sent so the buffer initialises
    // cleanly from the start of the stream). The buffer window is
    // large enough that no force-skip fires; all gaps are resolved
    // by the poll_timeout flush at the end.
    let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(1_000_000, 10);
    let total: u64 = 5_000;
    let mut delivered: Vec<u32> = Vec::with_capacity(total as usize);
    let mut actually_sent = 0u64;

    for seq in 0..total {
        if seq > 0 && seq % 17 == 0 {
            // Drop this one.
            continue;
        }
        actually_sent += 1;
        delivered.extend(buf.push(seq, seq as u32, 0));
    }
    // Loop the timeout flush until every head gap is cleared.
    loop {
        let out = buf.poll_timeout(1_000_000);
        if out.is_empty() {
            break;
        }
        delivered.extend(out);
    }

    assert_eq!(buf.delivered_count(), actually_sent, "delivered count should match packets sent");
    let expected_lost = total - actually_sent;
    assert_eq!(buf.lost_count(), expected_lost, "lost count should match skipped seqs",);
    assert_eq!(buf.duplicate_count(), 0);
    assert_eq!(buf.pending_count(), 0);
}
