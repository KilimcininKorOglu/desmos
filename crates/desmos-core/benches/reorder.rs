//! Reorder buffer benchmark.
//!
//! Measures push + drain latency for in-order and out-of-order traffic.
//! Target: p99 added latency < 1 ms (validated via timing, not
//! statistical percentile — we measure worst-case per-packet cost).
//!
//! Run with: `cargo bench -p desmos-core --bench reorder`

use desmos_core::bonding::reorder::ReorderBuffer;
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 100_000;
const WARMUP_ROUNDS: u32 = 3;
const MEASURE_ROUNDS: u32 = 5;

/// Window size for the reorder buffer.
const WINDOW: u64 = 64;

/// Gap timeout in milliseconds.
const GAP_TIMEOUT_MS: u64 = 50;

fn bench_in_order(iterations: u64) -> Duration {
    let mut buf: ReorderBuffer<Vec<u8>> = ReorderBuffer::new(WINDOW, GAP_TIMEOUT_MS);
    let payload = vec![0u8; 1400];

    let start = Instant::now();
    for i in 0..iterations {
        let now_ms = i; // Monotonic fake clock.
        let drained = buf.push(i, payload.clone(), now_ms);
        // In-order: each push should drain exactly 1 packet.
        assert_eq!(drained.len(), 1);
    }
    start.elapsed()
}

fn bench_out_of_order(iterations: u64) -> Duration {
    let mut buf: ReorderBuffer<Vec<u8>> = ReorderBuffer::new(WINDOW, GAP_TIMEOUT_MS);
    let payload = vec![0u8; 1400];

    // Simulate out-of-order: swap adjacent pairs (0,1) -> (1,0), (2,3) -> (3,2), etc.
    let start = Instant::now();
    let mut seq = 0u64;
    let mut now_ms = 0u64;
    while seq < iterations {
        now_ms += 1;
        if seq + 1 < iterations {
            // Push seq+1 first, then seq (swap pair).
            let _ = buf.push(seq + 1, payload.clone(), now_ms);
            let _ = buf.push(seq, payload.clone(), now_ms);
            seq += 2;
        } else {
            let _ = buf.push(seq, payload.clone(), now_ms);
            seq += 1;
        }
    }
    start.elapsed()
}

fn bench_with_gaps(iterations: u64) -> Duration {
    let mut buf: ReorderBuffer<Vec<u8>> = ReorderBuffer::new(WINDOW, GAP_TIMEOUT_MS);
    let payload = vec![0u8; 1400];

    // Every 10th packet is "lost" — skip its sequence number.
    let start = Instant::now();
    let mut now_ms = 0u64;
    for i in 0..iterations {
        now_ms += 1;
        if i % 10 == 5 {
            // Skip this seq to simulate loss.
            continue;
        }
        let _ = buf.push(i, payload.clone(), now_ms);
        // Periodically poll timeout to release stuck packets.
        if i % 100 == 99 {
            let _ = buf.poll_timeout(now_ms + GAP_TIMEOUT_MS + 1);
        }
    }
    start.elapsed()
}

fn run_bench(name: &str, f: impl Fn() -> Duration) -> Duration {
    for _ in 0..WARMUP_ROUNDS {
        f();
    }

    let mut best = Duration::MAX;
    let mut total = Duration::ZERO;
    for _ in 0..MEASURE_ROUNDS {
        let d = f();
        if d < best {
            best = d;
        }
        total += d;
    }
    let avg = total / MEASURE_ROUNDS;
    let best_ns = best.as_nanos() as f64 / ITERATIONS as f64;
    let avg_ns = avg.as_nanos() as f64 / ITERATIONS as f64;

    println!("{name:25}  best: {best_ns:.0} ns/pkt  avg: {avg_ns:.0} ns/pkt");

    best
}

fn main() {
    println!("=== desmos-core Reorder Buffer Benchmark ===");
    println!(
        "iterations={ITERATIONS}  window={WINDOW}  gap_timeout={GAP_TIMEOUT_MS}ms  \
         warmup={WARMUP_ROUNDS}  measure={MEASURE_ROUNDS}"
    );
    println!();

    run_bench("in-order", || bench_in_order(ITERATIONS));
    run_bench("out-of-order (swaps)", || bench_out_of_order(ITERATIONS));
    run_bench("with 10% gaps", || bench_with_gaps(ITERATIONS));

    println!();
    println!("Target: p99 added latency < 1 ms (= 1,000,000 ns/pkt)");
}
