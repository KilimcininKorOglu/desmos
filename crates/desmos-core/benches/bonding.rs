//! Bonding engine scheduler dispatch benchmark.
//!
//! Measures per-packet scheduling latency for each bonding strategy.
//! Target: < 200 ns/packet.
//!
//! Run with: `cargo bench -p desmos-core --bench bonding`

use desmos_core::bonding::link::{Link, LinkTable};
use desmos_core::bonding::strategy::{LatencyAdaptive, Redundant, RoundRobin, Weighted};
use desmos_core::bonding::Engine;
use desmos_proto::packet::PacketMeta;
use desmos_proto::types::{InterfaceId, TimestampUs};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 500_000;
const WARMUP_ROUNDS: u32 = 3;
const MEASURE_ROUNDS: u32 = 5;

fn make_link_table(n: u32) -> LinkTable {
    let addr: SocketAddr = "127.0.0.1:4789".parse().unwrap();
    let links: Vec<Link> = (0..n).map(|i| Link::new(i, format!("eth{i}"), addr, 100)).collect();
    LinkTable::new(links)
}

fn sample_packet() -> PacketMeta {
    PacketMeta::inbound(InterfaceId(0), TimestampUs(0))
}

fn bench_strategy(engine: &Engine, iterations: u64) -> Duration {
    let pkt = sample_packet();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.schedule(&pkt);
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
    println!("=== desmos-core Bonding Scheduler Benchmark ===");
    println!("iterations={ITERATIONS}  links=4  warmup={WARMUP_ROUNDS}  measure={MEASURE_ROUNDS}");
    println!();

    let links = make_link_table(4);
    let target_ns = 200.0;

    let strategies: Vec<(&str, Arc<dyn desmos_core::bonding::BondingStrategy>)> = vec![
        ("round-robin", Arc::new(RoundRobin::new())),
        ("weighted", Arc::new(Weighted::new())),
        ("latency-adaptive", Arc::new(LatencyAdaptive::new())),
        ("redundant", Arc::new(Redundant::new())),
    ];

    for (name, strategy) in &strategies {
        let engine = Engine::new(strategy.clone(), links.clone());
        let best = run_bench(name, || bench_strategy(&engine, ITERATIONS));
        let best_ns = best.as_nanos() as f64 / ITERATIONS as f64;
        println!(
            "  -> {best_ns:.0} ns/pkt {}",
            if best_ns <= target_ns { "PASS" } else { "ABOVE TARGET" }
        );
        println!();
    }
}
