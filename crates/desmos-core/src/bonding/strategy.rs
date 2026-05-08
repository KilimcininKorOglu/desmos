//! Bonding strategies.
//!
//! Four implementations share one narrow trait so the engine can
//! hot-swap between them at runtime:
//!
//! - [`RoundRobin`] — atomic cursor, strict N-way rotation.
//! - [`Weighted`] — stochastic sampling proportional to each link's
//!   static `weight`, using a per-strategy xorshift RNG.
//! - [`LatencyAdaptive`] — stochastic sampling with dynamic weights
//!   derived from `LinkScore::composite` per link,
//!   recomputed by the caller via [`LatencyAdaptive::update_score`]
//!   whenever the probe loop publishes fresh numbers.
//! - [`Replicate`] — returns `LinkSelection::Many`.
//!
//! Every strategy is `Send + Sync` and holds its own small amount of
//! interior state so the engine can share a single `Arc<dyn
//! BondingStrategy>` across pipeline threads without extra locks on
//! the hot path.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;

use desmos_proto::PacketMeta;

use super::link::Link;
use super::link::LinkId;
use super::link::LinkTable;
use super::score::LinkScore;

/// Per-packet scheduling decision. The round-robin, weighted, and
/// adaptive strategies return `One`; the redundant strategy
/// returns `Many`; an empty link set maps to `None`.
#[derive(Debug, Clone)]
pub enum LinkSelection {
    /// Send the packet over exactly one link.
    One(Arc<Link>),
    /// Replicate the packet on every link in the vector.
    Many(Vec<Arc<Link>>),
    /// No healthy links — the pipeline must drop the packet and bump
    /// a metric.
    None,
}

impl LinkSelection {
    /// Count of links chosen. `None` → 0, `One` → 1, `Many` → the vector length.
    pub fn count(&self) -> usize {
        match self {
            Self::None => 0,
            Self::One(_) => 1,
            Self::Many(v) => v.len(),
        }
    }
}

/// Common trait every bonding strategy implements. `Send + Sync`
/// because the engine holds a `dyn BondingStrategy` behind an
/// `RwLock<Arc<_>>` shared across pipeline threads.
pub trait BondingStrategy: Send + Sync {
    /// Short name reported by `desmos status` and `GET /api/v1/bonding`.
    fn name(&self) -> &'static str;

    /// Pick one or more links for the given packet. Strategies are
    /// expected to run in constant time against the healthy link
    /// slice; no allocations on the happy path beyond the
    /// `LinkSelection` variant itself.
    fn schedule(&self, packet: &PacketMeta, links: &LinkTable) -> LinkSelection;
}

// ---------------------------------------------------------------------------
// RoundRobin
// ---------------------------------------------------------------------------

/// Plain round-robin. Each call increments an atomic cursor and
/// chooses `healthy[cursor % n]`, so N packets sweep cleanly across
/// N links with no coordination between threads.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current cursor value. Exposed for tests and metrics; not part
    /// of the scheduling semantics.
    pub fn cursor(&self) -> usize {
        self.next.load(Ordering::Relaxed)
    }
}

impl BondingStrategy for RoundRobin {
    fn name(&self) -> &'static str {
        "round-robin"
    }

    fn schedule(&self, _packet: &PacketMeta, links: &LinkTable) -> LinkSelection {
        let healthy = links.healthy();
        if healthy.is_empty() {
            return LinkSelection::None;
        }
        // Relaxed ordering is enough here: the cursor is a pure
        // counter; no reordering of other memory operations relative
        // to it matters. Wrap-around at usize::MAX is fine thanks to
        // the modulo.
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % healthy.len();
        LinkSelection::One(Arc::clone(&healthy[idx]))
    }
}

// ---------------------------------------------------------------------------
// Shared xorshift64 RNG (atomic)
// ---------------------------------------------------------------------------

/// Draw the next xorshift64 sample from an `AtomicU64` state cell.
/// Uses `compare_exchange_weak` so multiple threads scheduling
/// concurrently see distinct samples without a mutex. The output is
/// never zero — xorshift has no fixed points, so once seeded the
/// sequence stays non-zero forever.
fn next_xorshift64(state: &AtomicU64) -> u64 {
    let mut x = state.load(Ordering::Relaxed);
    loop {
        let mut y = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        y ^= y << 13;
        y ^= y >> 7;
        y ^= y << 17;
        match state.compare_exchange_weak(x, y, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return y,
            Err(actual) => x = actual,
        }
    }
}

// ---------------------------------------------------------------------------
// Weighted
// ---------------------------------------------------------------------------

/// Static weighted sampler. Each call draws a random number in
/// `0..sum(healthy.weight)` and walks the cumulative-weight array to
/// pick the matching link. No locks on the hot path — only an atomic
/// compare-and-swap on the xorshift state. Over many samples the
/// empirical distribution converges to the configured weights.
#[derive(Debug)]
pub struct Weighted {
    rng_state: AtomicU64,
}

impl Weighted {
    pub fn new() -> Self {
        // Seed with a fixed constant so two `Weighted::new()` calls in
        // the same process start at the same state — tests can count on
        // that; production callers can `seed` directly if they need
        // stream separation.
        Self { rng_state: AtomicU64::new(0x9E37_79B9_7F4A_7C15) }
    }

    /// Construct with an explicit RNG seed. Useful for deterministic
    /// tests across multiple strategy instances.
    pub fn seeded(seed: u64) -> Self {
        let state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
        Self { rng_state: AtomicU64::new(state) }
    }
}

impl Default for Weighted {
    fn default() -> Self {
        Self::new()
    }
}

impl BondingStrategy for Weighted {
    fn name(&self) -> &'static str {
        "weighted"
    }

    fn schedule(&self, _packet: &PacketMeta, links: &LinkTable) -> LinkSelection {
        let healthy = links.healthy();
        if healthy.is_empty() {
            return LinkSelection::None;
        }
        let total_weight: u64 = healthy.iter().map(|l| l.weight as u64).sum();
        if total_weight == 0 {
            // Every healthy link has zero weight — fall back to a
            // uniform pick so the tunnel keeps moving. Otherwise a
            // typo in the config would blackhole traffic entirely.
            let idx = (next_xorshift64(&self.rng_state) as usize) % healthy.len();
            return LinkSelection::One(healthy[idx].clone());
        }
        let pick = next_xorshift64(&self.rng_state) % total_weight;
        let mut cumulative = 0u64;
        for link in &healthy {
            cumulative += link.weight as u64;
            if pick < cumulative {
                return LinkSelection::One(link.clone());
            }
        }
        // Cumulative walk must cover the full range; if we somehow
        // fall through, take the last link.
        LinkSelection::One(healthy.last().unwrap().clone())
    }
}

// ---------------------------------------------------------------------------
// LatencyAdaptive
// ---------------------------------------------------------------------------

/// Dynamic weighted sampler where the per-link weight is the
/// composite score from [`super::score::LinkScore`]. The probe loop
/// publishes fresh scores via [`LatencyAdaptive::update_score`] on
/// every measurement cycle; `schedule` reads the current snapshot
/// under a short read lock and samples proportionally to each link's
/// score.
///
/// Links that have not yet reported a score are treated as
/// "default-weight" so brand-new paths still receive probe traffic
/// even before the first measurement lands.
pub struct LatencyAdaptive {
    scores: RwLock<HashMap<LinkId, LinkScore>>,
    rng_state: AtomicU64,
    default_weight: f32,
}

impl LatencyAdaptive {
    /// Construct with the default unknown-link weight of 1 000 —
    /// slightly below a "good" link's 5 000 score so well-measured
    /// links still see most of the traffic but every new link gets
    /// enough volume to accumulate probe samples.
    pub fn new() -> Self {
        Self::with_default_weight(1_000.0)
    }

    pub fn with_default_weight(default_weight: f32) -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
            rng_state: AtomicU64::new(0x9E37_79B9_7F4A_7C15),
            default_weight,
        }
    }

    /// Publish a fresh per-link score. Called by the probe loop after
    /// every measurement cycle.
    pub fn update_score(&self, link_id: LinkId, score: LinkScore) {
        self.scores.write().unwrap().insert(link_id, score);
    }

    /// Drop a link's published score. Used when a link is removed
    /// from the table so future snapshots do not carry stale data.
    pub fn forget(&self, link_id: LinkId) {
        self.scores.write().unwrap().remove(&link_id);
    }

    /// Peek the current weight a given link would receive. Returns
    /// the default when no score has been published yet.
    pub fn current_weight(&self, link_id: LinkId) -> f32 {
        self.scores
            .read()
            .unwrap()
            .get(&link_id)
            .map(|s| s.composite)
            .unwrap_or(self.default_weight)
    }
}

impl Default for LatencyAdaptive {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for LatencyAdaptive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LatencyAdaptive")
            .field("known_links", &self.scores.read().unwrap().len())
            .field("default_weight", &self.default_weight)
            .finish()
    }
}

impl BondingStrategy for LatencyAdaptive {
    fn name(&self) -> &'static str {
        "latency-adaptive"
    }

    fn schedule(&self, _packet: &PacketMeta, links: &LinkTable) -> LinkSelection {
        let healthy = links.healthy();
        if healthy.is_empty() {
            return LinkSelection::None;
        }
        let scores = self.scores.read().unwrap();
        let mut weights: Vec<f32> = Vec::with_capacity(healthy.len());
        let mut total: f32 = 0.0;
        for link in &healthy {
            let w =
                scores.get(&link.id).map(|s| s.composite).unwrap_or(self.default_weight).max(0.0);
            weights.push(w);
            total += w;
        }
        drop(scores);

        if total <= 0.0 {
            // Every known link has collapsed to zero (100 % loss).
            // Still pick uniformly so the tunnel keeps trying — the
            // probe loop will update scores on the next cycle.
            let idx = (next_xorshift64(&self.rng_state) as usize) % healthy.len();
            return LinkSelection::One(healthy[idx].clone());
        }

        // Draw a uniform double in [0, total) and walk the cumulative
        // weights. f64 throughout for float precision, then cast back
        // to f32 for comparison.
        let rand = next_xorshift64(&self.rng_state) as f64 / u64::MAX as f64;
        let pick = (rand * total as f64) as f32;
        let mut cumulative: f32 = 0.0;
        for (i, w) in weights.iter().enumerate() {
            cumulative += *w;
            if pick < cumulative {
                return LinkSelection::One(healthy[i].clone());
            }
        }
        LinkSelection::One(healthy.last().unwrap().clone())
    }
}

// ---------------------------------------------------------------------------
// Redundant
// ---------------------------------------------------------------------------

/// Send every packet on every healthy link. The outbound pipeline
/// stage fans the sealed datagram out to each socket; the peer's
/// anti-replay window drops the second (and every subsequent) copy
/// as a duplicate, so the application sees the packet exactly once
/// and the effective per-packet latency is the fastest link's
/// arrival time. Total throughput is bounded by the slowest link
/// because the pipeline blocks on whichever link is full. Good fit
/// for real-time audio / gaming where reliability beats bandwidth.
#[derive(Debug, Default)]
pub struct Redundant;

impl Redundant {
    pub fn new() -> Self {
        Self
    }
}

impl BondingStrategy for Redundant {
    fn name(&self) -> &'static str {
        "redundant"
    }

    fn schedule(&self, _packet: &PacketMeta, links: &LinkTable) -> LinkSelection {
        let healthy = links.healthy();
        if healthy.is_empty() {
            LinkSelection::None
        } else {
            LinkSelection::Many(healthy)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_proto::InterfaceId;
    use desmos_proto::TimestampUs;

    fn sample_packet() -> PacketMeta {
        PacketMeta::outbound(InterfaceId(0), TimestampUs(0))
    }

    fn sample_addr() -> std::net::SocketAddr {
        "127.0.0.1:51820".parse().unwrap()
    }

    fn three_links() -> LinkTable {
        LinkTable::new(vec![
            Link::new(1, "eth0", sample_addr(), 10),
            Link::new(2, "eth1", sample_addr(), 10),
            Link::new(3, "wlan0", sample_addr(), 10),
        ])
    }

    fn selected_id(selection: &LinkSelection) -> u32 {
        match selection {
            LinkSelection::One(link) => link.id,
            _ => panic!("expected LinkSelection::One, got {selection:?}"),
        }
    }

    #[test]
    fn round_robin_rotates_through_links_in_order() {
        let rr = RoundRobin::new();
        let table = three_links();
        let p = sample_packet();

        let ids: Vec<u32> = (0..6).map(|_| selected_id(&rr.schedule(&p, &table))).collect();
        assert_eq!(ids, vec![1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn round_robin_skips_unhealthy_links() {
        let mut links = vec![
            Link::new(1, "eth0", sample_addr(), 10),
            Link::new(2, "eth1", sample_addr(), 10),
            Link::new(3, "wlan0", sample_addr(), 10),
        ];
        links[1].mark_dead();
        let table = LinkTable::new(links);
        let rr = RoundRobin::new();
        let p = sample_packet();

        let ids: Vec<u32> = (0..4).map(|_| selected_id(&rr.schedule(&p, &table))).collect();
        // Only links 1 and 3 are healthy; round-robin alternates
        // between them.
        assert_eq!(ids, vec![1, 3, 1, 3]);
    }

    #[test]
    fn round_robin_with_zero_healthy_links_returns_none() {
        let mut links =
            vec![Link::new(1, "eth0", sample_addr(), 10), Link::new(2, "eth1", sample_addr(), 10)];
        links[0].mark_dead();
        links[1].mark_dead();
        let table = LinkTable::new(links);
        let rr = RoundRobin::new();
        let p = sample_packet();
        assert!(matches!(rr.schedule(&p, &table), LinkSelection::None));
    }

    #[test]
    fn round_robin_with_empty_table_returns_none() {
        let table = LinkTable::new(Vec::new());
        let rr = RoundRobin::new();
        let p = sample_packet();
        assert!(matches!(rr.schedule(&p, &table), LinkSelection::None));
    }

    #[test]
    fn round_robin_cursor_increments_monotonically_even_with_dead_links() {
        // Regression for the "skip unhealthy" implementation: the
        // cursor must still increment so we never loop on the same
        // live link just because others are dead.
        let table = three_links();
        let rr = RoundRobin::new();
        let p = sample_packet();
        let _ = rr.schedule(&p, &table);
        let _ = rr.schedule(&p, &table);
        assert_eq!(rr.cursor(), 2);
    }

    #[test]
    fn round_robin_is_thread_safe_under_concurrent_schedules() {
        use std::sync::Arc as StdArc;
        use std::thread;

        let table = StdArc::new(three_links());
        let rr = StdArc::new(RoundRobin::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let rr = rr.clone();
            let table = table.clone();
            handles.push(thread::spawn(move || {
                let p = sample_packet();
                for _ in 0..1000 {
                    let _ = rr.schedule(&p, &table);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 8 threads × 1000 iterations = 8000 total schedules.
        assert_eq!(rr.cursor(), 8000);
    }

    #[test]
    fn name_identifies_strategy() {
        let rr = RoundRobin::new();
        assert_eq!(rr.name(), "round-robin");
    }

    #[test]
    fn link_selection_count_is_accurate() {
        assert_eq!(LinkSelection::None.count(), 0);
        let link = Arc::new(Link::new(1, "x", sample_addr(), 1));
        assert_eq!(LinkSelection::One(link.clone()).count(), 1);
        assert_eq!(LinkSelection::Many(vec![link.clone(), link]).count(), 2);
    }

    // -----------------------------------------------------------------
    // Weighted
    // -----------------------------------------------------------------

    fn three_weighted_links() -> LinkTable {
        LinkTable::new(vec![
            Link::new(1, "eth0", sample_addr(), 5),
            Link::new(2, "eth1", sample_addr(), 3),
            Link::new(3, "wlan0", sample_addr(), 2),
        ])
    }

    #[test]
    fn weighted_name_is_weighted() {
        assert_eq!(Weighted::new().name(), "weighted");
    }

    #[test]
    fn weighted_distribution_converges_to_configured_weights() {
        // 10 000 samples across weights 5 / 3 / 2. Expected hit counts:
        // link 1 = 5000, link 2 = 3000, link 3 = 2000. We assert each
        // empirical hit count is within 5 % of its expected value —
        // looser than a formal χ² test but enough to catch a bug in
        // the cumulative walk.
        let w = Weighted::seeded(0xCAFE_BABE_DEAD_BEEF);
        let table = three_weighted_links();
        let p = sample_packet();
        let mut counts = [0u64; 3];
        for _ in 0..10_000 {
            match w.schedule(&p, &table) {
                LinkSelection::One(link) => counts[(link.id - 1) as usize] += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        let expected = [5000.0f64, 3000.0, 2000.0];
        for (i, &c) in counts.iter().enumerate() {
            let diff = (c as f64 - expected[i]).abs();
            let tol = expected[i] * 0.05;
            assert!(
                diff < tol,
                "link {} count {c} outside 5 % of {expected}, diff={diff}",
                i + 1,
                expected = expected[i],
            );
        }
    }

    #[test]
    fn weighted_skips_unhealthy_links() {
        let mut links = vec![
            Link::new(1, "eth0", sample_addr(), 5),
            Link::new(2, "eth1", sample_addr(), 3),
            Link::new(3, "wlan0", sample_addr(), 2),
        ];
        links[0].mark_dead();
        let table = LinkTable::new(links);
        let w = Weighted::seeded(0xABCD_EF01_2345_6789);
        let p = sample_packet();
        let mut counts = [0u64; 3];
        for _ in 0..5_000 {
            if let LinkSelection::One(link) = w.schedule(&p, &table) {
                counts[(link.id - 1) as usize] += 1;
            }
        }
        // Link 1 is dead and must never be selected; links 2 and 3
        // split all traffic proportional to 3 / 2.
        assert_eq!(counts[0], 0);
        let ratio = counts[1] as f64 / counts[2] as f64;
        assert!((1.2..=1.8).contains(&ratio), "expected ratio ~1.5, got {ratio}",);
    }

    #[test]
    fn weighted_with_zero_weights_falls_back_to_uniform() {
        let table = LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 0),
            Link::new(2, "b", sample_addr(), 0),
        ]);
        let w = Weighted::seeded(42);
        let p = sample_packet();
        // Must not return None and must pick each link at least once
        // across a reasonable number of samples.
        let mut counts = [0u64; 2];
        for _ in 0..1_000 {
            if let LinkSelection::One(link) = w.schedule(&p, &table) {
                counts[(link.id - 1) as usize] += 1;
            } else {
                panic!("should not return None when healthy links exist");
            }
        }
        assert!(counts[0] > 0);
        assert!(counts[1] > 0);
    }

    #[test]
    fn weighted_with_single_link_always_picks_it() {
        let table = LinkTable::new(vec![Link::new(99, "solo", sample_addr(), 10)]);
        let w = Weighted::new();
        let p = sample_packet();
        for _ in 0..100 {
            match w.schedule(&p, &table) {
                LinkSelection::One(link) => assert_eq!(link.id, 99),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn weighted_with_empty_table_returns_none() {
        let table = LinkTable::new(Vec::new());
        let w = Weighted::new();
        let p = sample_packet();
        assert!(matches!(w.schedule(&p, &table), LinkSelection::None));
    }

    // -----------------------------------------------------------------
    // LatencyAdaptive
    // -----------------------------------------------------------------

    fn sample_score(composite: f32) -> LinkScore {
        LinkScore { rtt_us: 1_000, loss_rate: 0.0, jitter_us: 0, composite }
    }

    #[test]
    fn latency_adaptive_name_is_latency_adaptive() {
        assert_eq!(LatencyAdaptive::new().name(), "latency-adaptive");
    }

    #[test]
    fn latency_adaptive_with_no_scores_distributes_uniformly() {
        let la = LatencyAdaptive::new();
        let table = LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
            Link::new(3, "c", sample_addr(), 10),
        ]);
        let p = sample_packet();
        let mut counts = [0u64; 3];
        for _ in 0..3_000 {
            if let LinkSelection::One(link) = la.schedule(&p, &table) {
                counts[(link.id - 1) as usize] += 1;
            }
        }
        // Each link should get ~1000 ± 15 %.
        for c in counts {
            assert!((850..=1150).contains(&c), "expected ~1000 per link, got {c}");
        }
    }

    #[test]
    fn latency_adaptive_favours_the_best_link() {
        let la = LatencyAdaptive::new();
        la.update_score(1, sample_score(5_000.0));
        la.update_score(2, sample_score(1_000.0));
        la.update_score(3, sample_score(500.0));

        let table = LinkTable::new(vec![
            Link::new(1, "fast", sample_addr(), 10),
            Link::new(2, "ok", sample_addr(), 10),
            Link::new(3, "slow", sample_addr(), 10),
        ]);
        let p = sample_packet();
        let mut counts = [0u64; 3];
        for _ in 0..10_000 {
            if let LinkSelection::One(link) = la.schedule(&p, &table) {
                counts[(link.id - 1) as usize] += 1;
            }
        }
        // Expected proportions: 5000 / 1000 / 500 out of 6500 total.
        // → fast ≈ 7692, ok ≈ 1538, slow ≈ 769.
        assert!(counts[0] > counts[1]);
        assert!(counts[1] > counts[2]);
        assert!(counts[0] > 6_500, "fast should dominate, got {}", counts[0]);
        assert!(counts[2] < 1_500, "slow should trickle, got {}", counts[2]);
    }

    #[test]
    fn latency_adaptive_update_score_changes_distribution() {
        let la = LatencyAdaptive::new();
        let table = LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
        ]);
        let p = sample_packet();

        // Phase 1: both links at default → roughly 50/50.
        let mut phase1 = [0u64; 2];
        for _ in 0..2_000 {
            if let LinkSelection::One(link) = la.schedule(&p, &table) {
                phase1[(link.id - 1) as usize] += 1;
            }
        }
        assert!(phase1[0].abs_diff(phase1[1]) < 500);

        // Phase 2: publish a huge score for link 2 → heavily favoured.
        la.update_score(2, sample_score(50_000.0));
        let mut phase2 = [0u64; 2];
        for _ in 0..2_000 {
            if let LinkSelection::One(link) = la.schedule(&p, &table) {
                phase2[(link.id - 1) as usize] += 1;
            }
        }
        assert!(phase2[1] > phase2[0] * 10, "phase2={phase2:?}");
    }

    #[test]
    fn latency_adaptive_zero_total_weight_falls_back_to_uniform() {
        let la = LatencyAdaptive::with_default_weight(0.0);
        la.update_score(1, sample_score(0.0));
        la.update_score(2, sample_score(0.0));
        let table = LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
        ]);
        let p = sample_packet();
        // Must not return None; must pick each link at least once.
        let mut hits = [0u64; 2];
        for _ in 0..200 {
            if let LinkSelection::One(link) = la.schedule(&p, &table) {
                hits[(link.id - 1) as usize] += 1;
            } else {
                panic!("expected fallback pick");
            }
        }
        assert!(hits[0] > 0 && hits[1] > 0);
    }

    #[test]
    fn latency_adaptive_current_weight_reports_known_and_default() {
        let la = LatencyAdaptive::with_default_weight(123.0);
        la.update_score(1, sample_score(5_000.0));
        assert_eq!(la.current_weight(1), 5_000.0);
        assert_eq!(la.current_weight(2), 123.0);
        la.forget(1);
        assert_eq!(la.current_weight(1), 123.0);
    }

    #[test]
    fn latency_adaptive_skips_unhealthy_links() {
        let la = LatencyAdaptive::new();
        la.update_score(1, sample_score(5_000.0));
        la.update_score(2, sample_score(5_000.0));
        let mut links =
            vec![Link::new(1, "a", sample_addr(), 10), Link::new(2, "b", sample_addr(), 10)];
        links[0].mark_dead();
        let table = LinkTable::new(links);
        let p = sample_packet();
        for _ in 0..100 {
            match la.schedule(&p, &table) {
                LinkSelection::One(link) => assert_eq!(link.id, 2),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------
    // Redundant
    // -----------------------------------------------------------------

    #[test]
    fn redundant_name_is_redundant() {
        assert_eq!(Redundant::new().name(), "redundant");
    }

    #[test]
    fn redundant_returns_every_healthy_link() {
        let r = Redundant::new();
        let table = LinkTable::new(vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
            Link::new(3, "c", sample_addr(), 10),
        ]);
        let p = sample_packet();
        match r.schedule(&p, &table) {
            LinkSelection::Many(links) => {
                let ids: Vec<u32> = links.iter().map(|l| l.id).collect();
                assert_eq!(ids, vec![1, 2, 3]);
            }
            other => panic!("expected Many, got {other:?}"),
        }
    }

    #[test]
    fn redundant_skips_unhealthy_links() {
        let r = Redundant::new();
        let mut links = vec![
            Link::new(1, "a", sample_addr(), 10),
            Link::new(2, "b", sample_addr(), 10),
            Link::new(3, "c", sample_addr(), 10),
        ];
        links[1].mark_dead();
        let table = LinkTable::new(links);
        let p = sample_packet();
        match r.schedule(&p, &table) {
            LinkSelection::Many(links) => {
                let ids: Vec<u32> = links.iter().map(|l| l.id).collect();
                assert_eq!(ids, vec![1, 3]);
            }
            other => panic!("expected Many, got {other:?}"),
        }
    }

    #[test]
    fn redundant_with_zero_healthy_returns_none() {
        let r = Redundant::new();
        let mut links =
            vec![Link::new(1, "a", sample_addr(), 10), Link::new(2, "b", sample_addr(), 10)];
        links[0].mark_dead();
        links[1].mark_dead();
        let table = LinkTable::new(links);
        let p = sample_packet();
        assert!(matches!(r.schedule(&p, &table), LinkSelection::None));
    }

    #[test]
    fn redundant_with_single_healthy_still_returns_many() {
        let r = Redundant::new();
        let table = LinkTable::new(vec![Link::new(7, "solo", sample_addr(), 10)]);
        let p = sample_packet();
        match r.schedule(&p, &table) {
            LinkSelection::Many(links) => {
                assert_eq!(links.len(), 1);
                assert_eq!(links[0].id, 7);
            }
            other => panic!("expected Many, got {other:?}"),
        }
    }
}
