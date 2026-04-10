//! Link types for the bonding engine.
//!
//! A [`Link`] is one physical path to the peer: an interface name, a
//! `(peer_addr)` tuple, a static weight, and a health flag. Task 25
//! replaces the coarse `healthy: bool` with the full link-state
//! machine (`Healthy / Probation / Degraded / Dead`) from
//! IMPLEMENTATION.md §2.4; Task 21 keeps the shape simple so the
//! round-robin strategy has something to schedule against.
//!
//! [`LinkTable`] is the read-only snapshot the engine passes to every
//! strategy invocation. It holds `Arc<Link>` so callers can cheaply
//! keep a reference to the chosen link past the schedule call — the
//! pipeline stage uses that to stamp `interface_id` into the DWP
//! header and to emit per-link metrics.

use std::net::SocketAddr;
use std::sync::Arc;

/// Stable identifier for one bonding link. Allocated by the engine at
/// registration time; the value maps 1-to-1 to the DWP header's
/// `InterfaceId` for outbound packets.
pub type LinkId = u32;

/// A single bonding link.
#[derive(Debug, Clone)]
pub struct Link {
    pub id: LinkId,
    /// Kernel interface name used to bind the socket (`SO_BINDTODEVICE`
    /// on Linux). Matches one of the names returned by
    /// `desmos-core::net::list()`.
    pub name: String,
    /// Peer address to send to on this link.
    pub peer: SocketAddr,
    /// Static weight. Ignored by round-robin; read by weighted /
    /// adaptive strategies in later tasks.
    pub weight: u32,
    /// Coarse health flag. Replaced by the full state machine in Task 25.
    pub healthy: bool,
}

impl Link {
    /// Build a healthy link with the given parameters.
    pub fn new(id: LinkId, name: impl Into<String>, peer: SocketAddr, weight: u32) -> Self {
        Self { id, name: name.into(), peer, weight, healthy: true }
    }

    /// Mark this link healthy.
    pub fn mark_healthy(&mut self) {
        self.healthy = true;
    }

    /// Mark this link dead so the next `LinkTable::healthy()` skips it.
    pub fn mark_dead(&mut self) {
        self.healthy = false;
    }
}

/// Immutable view of the engine's current link set. The engine keeps
/// an `Arc<LinkTable>` inside a lock and swaps it wholesale whenever
/// links are added, removed, or their health state changes.
#[derive(Debug, Default, Clone)]
pub struct LinkTable {
    links: Vec<Arc<Link>>,
}

impl LinkTable {
    pub fn new(links: Vec<Link>) -> Self {
        Self { links: links.into_iter().map(Arc::new).collect() }
    }

    /// All links, healthy or not. Strategies should prefer
    /// [`healthy`](Self::healthy) so dead paths are skipped without
    /// every strategy having to repeat the filter.
    pub fn all(&self) -> &[Arc<Link>] {
        &self.links
    }

    /// Every `Arc<Link>` whose `healthy` flag is `true`.
    pub fn healthy(&self) -> Vec<Arc<Link>> {
        self.links.iter().filter(|l| l.healthy).cloned().collect()
    }

    /// Number of links in the table regardless of health state.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Look up a link by id. Returns `None` if the id is not in the
    /// table. Used by the pipeline to resolve the `InterfaceId` back
    /// to a `(name, peer)` tuple after a strategy chooses a link.
    pub fn get(&self, id: LinkId) -> Option<Arc<Link>> {
        self.links.iter().find(|l| l.id == id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addr() -> SocketAddr {
        "127.0.0.1:51820".parse().unwrap()
    }

    #[test]
    fn new_link_is_healthy_by_default() {
        let l = Link::new(1, "eth0", sample_addr(), 10);
        assert!(l.healthy);
        assert_eq!(l.id, 1);
        assert_eq!(l.name, "eth0");
        assert_eq!(l.weight, 10);
    }

    #[test]
    fn mark_dead_flips_flag() {
        let mut l = Link::new(1, "eth0", sample_addr(), 10);
        l.mark_dead();
        assert!(!l.healthy);
        l.mark_healthy();
        assert!(l.healthy);
    }

    #[test]
    fn healthy_filters_dead_links() {
        let mut a = Link::new(1, "eth0", sample_addr(), 10);
        let b = Link::new(2, "eth1", sample_addr(), 10);
        a.mark_dead();
        let table = LinkTable::new(vec![a, b]);
        let healthy = table.healthy();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].id, 2);
    }

    #[test]
    fn empty_table_reports_zero_len() {
        let t = LinkTable::new(Vec::new());
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert!(t.healthy().is_empty());
    }

    #[test]
    fn get_by_id_returns_the_matching_link() {
        let t = LinkTable::new(vec![
            Link::new(1, "eth0", sample_addr(), 10),
            Link::new(2, "eth1", sample_addr(), 20),
            Link::new(3, "wlan0", sample_addr(), 5),
        ]);
        assert_eq!(t.get(2).unwrap().name, "eth1");
        assert!(t.get(99).is_none());
    }
}
