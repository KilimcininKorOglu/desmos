//! Bonding strategy trait + round-robin implementation.
//!
//! Strategies are plain `dyn Trait`s so the engine can hot-swap them at
//! runtime. The trait is deliberately narrow — `name()` for metrics
//! and logging, `schedule()` for per-packet link selection — so every
//! strategy implementation stays lock-free and allocation-free on the
//! hot path.
//!
//! Tasks 22-24 add `Weighted`, `Replicate`, and `LatencyAdaptive`
//! implementations on top of this scaffold.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use desmos_proto::PacketMeta;

use super::link::Link;
use super::link::LinkTable;

/// Per-packet scheduling decision. The round-robin, weighted, and
/// adaptive strategies return `One`; the redundant strategy (Task 23)
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
}
