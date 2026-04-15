//! DWP header encode/decode benchmark.
//!
//! Measures header codec throughput — should be negligible compared to
//! AEAD but validates that the wire format is not a bottleneck.
//!
//! Run with: `cargo bench -p desmos-proto --bench wire`

use desmos_proto::wire::{Header, PacketType, HEADER_LEN};
use desmos_proto::{Seq, SessionId};
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 1_000_000;
const WARMUP_ROUNDS: u32 = 3;
const MEASURE_ROUNDS: u32 = 5;

fn sample_header() -> Header {
    let mut h = Header::new(PacketType::Data, SessionId(42));
    h.sequence = Seq(1_000_000);
    h.payload_len = 1400;
    h
}

fn bench_encode(header: &Header, iterations: u64) -> Duration {
    let mut buf = [0u8; HEADER_LEN];
    let start = Instant::now();
    for _ in 0..iterations {
        header.encode(&mut buf).unwrap();
    }
    start.elapsed()
}

fn bench_decode(encoded: &[u8], iterations: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Header::decode(encoded).unwrap();
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

    println!(
        "{name:20}  best: {best_ns:.1} ns/op  avg: {avg_ns:.1} ns/op  ({ITERATIONS} iterations)",
    );

    best
}

fn main() {
    println!("=== desmos-proto Wire Codec Benchmark ===");
    println!("iterations={ITERATIONS}  warmup={WARMUP_ROUNDS}  measure={MEASURE_ROUNDS}");
    println!();

    let header = sample_header();
    let mut encoded = [0u8; HEADER_LEN];
    header.encode(&mut encoded).unwrap();

    let encode_best = run_bench("encode", || bench_encode(&header, ITERATIONS));
    let decode_best = run_bench("decode", || bench_decode(&encoded, ITERATIONS));

    println!();

    let encode_ns = encode_best.as_nanos() as f64 / ITERATIONS as f64;
    let decode_ns = decode_best.as_nanos() as f64 / ITERATIONS as f64;

    // Header codec should be sub-100ns.
    let target_ns = 100.0;
    println!(
        "encode: {encode_ns:.1} ns/op {}",
        if encode_ns <= target_ns { "PASS" } else { "SLOW" }
    );
    println!(
        "decode: {decode_ns:.1} ns/op {}",
        if decode_ns <= target_ns { "PASS" } else { "SLOW" }
    );
}
