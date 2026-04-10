//! Bonding engine: the policy layer that decides which link each
//! outbound packet rides on.
//!
//! The engine holds two runtime-swappable handles:
//!
//! - `strategy: RwLock<Arc<dyn BondingStrategy>>` — the current
//!   scheduling policy. Swappable at runtime (the Web UI "switch
//!   bonding mode" button goes through [`Engine::swap_strategy`]).
//! - `links: RwLock<Arc<LinkTable>>` — the current link set. Swapped
//!   wholesale whenever interfaces are added, removed, or their
//!   health flag flips, so pipeline threads holding an `Arc<LinkTable>`
//!   snapshot never see a torn view.
//!
//! Both locks are read-heavy: every outbound packet grabs a read
//! lock, clones the `Arc`, and drops the lock before calling
//! `schedule`. Writers (strategy hot-swap, link table updates) are
//! orders of magnitude rarer so `RwLock` rather than a lock-free
//! `ArcSwap` is fine for Task 21; Task 61 benchmarks can revisit if
//! the read path ever becomes contended.

pub mod link;
pub mod reorder;
pub mod strategy;

pub use link::Link;
pub use link::LinkId;
pub use link::LinkTable;
pub use reorder::ReorderBuffer;
pub use strategy::BondingStrategy;
pub use strategy::LinkSelection;
pub use strategy::RoundRobin;

use std::sync::Arc;
use std::sync::RwLock;

use desmos_proto::PacketMeta;

/// Bonding engine. One per tunnel.
pub struct Engine {
    strategy: RwLock<Arc<dyn BondingStrategy>>,
    links: RwLock<Arc<LinkTable>>,
}

impl Engine {
    /// Construct a new engine with the given initial strategy and
    /// link set. `new_with_round_robin` is the convenience constructor
    /// for the common case.
    pub fn new(strategy: Arc<dyn BondingStrategy>, links: LinkTable) -> Self {
        Self { strategy: RwLock::new(strategy), links: RwLock::new(Arc::new(links)) }
    }

    /// Convenience: build an engine with the default round-robin
    /// strategy and the given link set.
    pub fn new_with_round_robin(links: LinkTable) -> Self {
        Self::new(Arc::new(RoundRobin::new()), links)
    }

    /// Schedule one packet. Returns the `LinkSelection` the current
    /// strategy picked, already holding `Arc<Link>`s so the caller can
    /// drop the engine's internal locks and still keep a handle to
    /// the chosen link(s).
    pub fn schedule(&self, packet: &PacketMeta) -> LinkSelection {
        let strategy = self.strategy.read().unwrap().clone();
        let links = self.links.read().unwrap().clone();
        strategy.schedule(packet, &links)
    }

    /// Atomically replace the active strategy. The next `schedule`
    /// call sees the new policy; in-flight `schedule`s on other
    /// threads finish against the old policy and return normally.
    pub fn swap_strategy(&self, new_strategy: Arc<dyn BondingStrategy>) {
        *self.strategy.write().unwrap() = new_strategy;
    }

    /// Atomically replace the link table. The next `schedule` call
    /// sees the new link set.
    pub fn swap_links(&self, new_links: LinkTable) {
        *self.links.write().unwrap() = Arc::new(new_links);
    }

    /// Name of the active strategy. `name()` returns `&'static str`
    /// so the guard lifetime does not leak out.
    pub fn current_strategy_name(&self) -> &'static str {
        self.strategy.read().unwrap().name()
    }

    /// Snapshot of the current link table. Cheap: just an `Arc` clone
    /// under a read lock.
    pub fn links_snapshot(&self) -> Arc<LinkTable> {
        self.links.read().unwrap().clone()
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("strategy", &self.current_strategy_name())
            .field("links", &self.links_snapshot().len())
            .finish()
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

    fn two_link_table() -> LinkTable {
        LinkTable::new(vec![
            Link::new(1, "eth0", sample_addr(), 10),
            Link::new(2, "eth1", sample_addr(), 10),
        ])
    }

    #[test]
    fn engine_reports_current_strategy_name() {
        let engine = Engine::new_with_round_robin(two_link_table());
        assert_eq!(engine.current_strategy_name(), "round-robin");
    }

    #[test]
    fn engine_schedule_rotates_with_round_robin() {
        let engine = Engine::new_with_round_robin(two_link_table());
        let p = sample_packet();
        let ids: Vec<u32> = (0..4)
            .map(|_| match engine.schedule(&p) {
                LinkSelection::One(link) => link.id,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(ids, vec![1, 2, 1, 2]);
    }

    /// A test-only strategy that always picks the first link, so the
    /// hot-swap test can distinguish "old strategy ran" from "new
    /// strategy ran" by the id returned.
    struct AlwaysFirst;
    impl BondingStrategy for AlwaysFirst {
        fn name(&self) -> &'static str {
            "always-first"
        }
        fn schedule(&self, _p: &PacketMeta, links: &LinkTable) -> LinkSelection {
            let healthy = links.healthy();
            if healthy.is_empty() {
                LinkSelection::None
            } else {
                LinkSelection::One(healthy[0].clone())
            }
        }
    }

    #[test]
    fn swap_strategy_takes_effect_on_next_schedule() {
        let engine = Engine::new_with_round_robin(two_link_table());
        let p = sample_packet();
        assert!(matches!(engine.schedule(&p), LinkSelection::One(_)));

        engine.swap_strategy(Arc::new(AlwaysFirst));
        assert_eq!(engine.current_strategy_name(), "always-first");

        // All subsequent schedules pick link id 1.
        for _ in 0..5 {
            match engine.schedule(&p) {
                LinkSelection::One(link) => assert_eq!(link.id, 1),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn swap_links_takes_effect_on_next_schedule() {
        let engine = Engine::new_with_round_robin(two_link_table());
        let p = sample_packet();
        // Rotate once.
        let _ = engine.schedule(&p);
        // Replace the table with a single-link one.
        engine.swap_links(LinkTable::new(vec![Link::new(99, "new0", sample_addr(), 1)]));
        for _ in 0..3 {
            match engine.schedule(&p) {
                LinkSelection::One(link) => assert_eq!(link.id, 99),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn engine_hot_swap_is_safe_under_concurrent_schedules() {
        // Writer flips strategy between two implementations while
        // readers keep scheduling. No torn state, no panics, and
        // every schedule returns a valid LinkSelection::One.
        use std::sync::Arc as StdArc;
        use std::thread;

        let engine = StdArc::new(Engine::new_with_round_robin(two_link_table()));
        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));

        let mut readers = Vec::new();
        for _ in 0..4 {
            let engine = engine.clone();
            let stop = stop.clone();
            readers.push(thread::spawn(move || {
                let p = sample_packet();
                let mut count = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    match engine.schedule(&p) {
                        LinkSelection::One(_) => count += 1,
                        other => panic!("unexpected {other:?}"),
                    }
                }
                count
            }));
        }

        let writer_engine = engine.clone();
        let writer = thread::spawn(move || {
            for i in 0..1000 {
                if i % 2 == 0 {
                    writer_engine.swap_strategy(Arc::new(RoundRobin::new()));
                } else {
                    writer_engine.swap_strategy(Arc::new(AlwaysFirst));
                }
            }
        });

        writer.join().unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let total: u64 = readers.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total > 0, "readers should have scheduled at least one packet");
    }

    #[test]
    fn engine_links_snapshot_returns_current_table() {
        let engine = Engine::new_with_round_robin(two_link_table());
        assert_eq!(engine.links_snapshot().len(), 2);
        engine.swap_links(LinkTable::new(Vec::new()));
        assert_eq!(engine.links_snapshot().len(), 0);
    }
}
