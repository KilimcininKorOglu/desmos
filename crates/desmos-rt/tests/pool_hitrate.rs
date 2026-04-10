//! Acceptance benchmark for Task 8: pool hit rate must exceed 99% in a
//! 10 000-iteration acquire/release loop on a cold pool (no prefill).
//!
//! The first acquire necessarily allocates (miss), every subsequent
//! acquire pops the just-released buffer (hit), so the theoretical rate
//! is `9999 / 10000 = 0.9999`.

use desmos_rt::PacketPool;

#[test]
fn pool_hit_rate_exceeds_99_percent_in_10k_loop() {
    let pool = PacketPool::new(1400, 0);
    for _ in 0..10_000 {
        let buf = pool.acquire();
        pool.release(buf);
    }
    let stats = pool.stats();
    assert_eq!(stats.acquires, 10_000);
    assert_eq!(stats.releases, 10_000);
    // First acquire missed, the next 9999 hit the free list.
    assert_eq!(stats.hits, 9_999);
    assert_eq!(stats.allocations, 1);
    assert!(stats.hit_rate() > 0.99, "hit rate {} did not exceed 0.99", stats.hit_rate());
}

#[test]
fn pool_prefill_keeps_hit_rate_at_100_percent() {
    let pool = PacketPool::new(1280, 16);
    for _ in 0..10_000 {
        let buf = pool.acquire();
        pool.release(buf);
    }
    let stats = pool.stats();
    assert_eq!(stats.allocations, 16);
    assert_eq!(stats.hits, 10_000);
    assert!((stats.hit_rate() - 1.0).abs() < 1e-12);
}
