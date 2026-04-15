//! AEAD throughput benchmark.
//!
//! Measures ChaCha20-Poly1305 seal + open throughput in GB/s.
//! Target: >= 2 Gbps (250 MB/s) per core on x86_64.
//!
//! Run with: `cargo bench -p desmos-proto --bench crypto`

use desmos_proto::crypto::aead::{AeadKey, KEY_LEN, NONCE_LEN, TAG_LEN};
use std::time::{Duration, Instant};

/// Number of iterations per measurement round.
const ITERATIONS: u64 = 10_000;

/// Payload size for throughput measurement (1400 = typical tunnel MTU).
const PAYLOAD_SIZE: usize = 1400;

/// Number of warmup rounds before measurement.
const WARMUP_ROUNDS: u32 = 3;

/// Number of measurement rounds.
const MEASURE_ROUNDS: u32 = 5;

fn make_key() -> AeadKey {
    let mut key = [0u8; KEY_LEN];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    AeadKey::new(&key).unwrap()
}

fn make_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..12].copy_from_slice(&seq.to_le_bytes());
    nonce
}

fn bench_seal(key: &AeadKey, payload: &[u8], iterations: u64) -> Duration {
    let aad = [0u8; 16]; // Simulated header AAD.
    let start = Instant::now();
    for i in 0..iterations {
        let mut buf = payload.to_vec();
        let nonce = make_nonce(i);
        key.seal_in_place(&nonce, &aad, &mut buf).unwrap();
    }
    start.elapsed()
}

fn bench_open(key: &AeadKey, payload: &[u8], iterations: u64) -> Duration {
    let aad = [0u8; 16];
    // Pre-encrypt all packets.
    let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(iterations as usize);
    for i in 0..iterations {
        let mut buf = payload.to_vec();
        let nonce = make_nonce(i);
        key.seal_in_place(&nonce, &aad, &mut buf).unwrap();
        ciphertexts.push(buf);
    }

    let start = Instant::now();
    for (i, ct) in ciphertexts.iter_mut().enumerate() {
        let nonce = make_nonce(i as u64);
        key.open_in_place(&nonce, &aad, ct).unwrap();
    }
    start.elapsed()
}

fn throughput_gbps(bytes: u64, elapsed: Duration) -> f64 {
    let bits = bytes as f64 * 8.0;
    bits / elapsed.as_secs_f64() / 1_000_000_000.0
}

fn run_bench(name: &str, f: impl Fn() -> Duration) -> Duration {
    // Warmup.
    for _ in 0..WARMUP_ROUNDS {
        f();
    }

    // Measure.
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
    let total_bytes = ITERATIONS * PAYLOAD_SIZE as u64;

    println!(
        "{name:20}  best: {:.2} Gbps  avg: {:.2} Gbps  ({} x {} B, {} rounds)",
        throughput_gbps(total_bytes, best),
        throughput_gbps(total_bytes, avg),
        ITERATIONS,
        PAYLOAD_SIZE,
        MEASURE_ROUNDS,
    );

    best
}

fn main() {
    println!("=== desmos-proto AEAD Benchmark ===");
    println!(
        "payload={} B  iterations={}  warmup={} measure={}",
        PAYLOAD_SIZE, ITERATIONS, WARMUP_ROUNDS, MEASURE_ROUNDS,
    );
    println!();

    let key = make_key();
    let payload = vec![0xABu8; PAYLOAD_SIZE];

    let seal_best = run_bench("seal (encrypt)", || bench_seal(&key, &payload, ITERATIONS));
    let open_best = run_bench("open (decrypt)", || bench_open(&key, &payload, ITERATIONS));

    println!();

    // Verify targets.
    let total_bytes = ITERATIONS * PAYLOAD_SIZE as u64;
    let seal_gbps = throughput_gbps(total_bytes, seal_best);
    let open_gbps = throughput_gbps(total_bytes, open_best);

    let target = 2.0; // Gbps
    println!(
        "seal: {:.2} Gbps {}",
        seal_gbps,
        if seal_gbps >= target { "PASS" } else { "BELOW TARGET" }
    );
    println!(
        "open: {:.2} Gbps {}",
        open_gbps,
        if open_gbps >= target { "PASS" } else { "BELOW TARGET" }
    );

    // Report per-packet cost.
    let seal_ns = seal_best.as_nanos() as f64 / ITERATIONS as f64;
    let open_ns = open_best.as_nanos() as f64 / ITERATIONS as f64;
    println!();
    println!("seal: {seal_ns:.0} ns/packet  ({} B + {} B tag)", PAYLOAD_SIZE, TAG_LEN);
    println!("open: {open_ns:.0} ns/packet  ({} B ciphertext)", PAYLOAD_SIZE + TAG_LEN);
}
