//! Thread-safe packet buffer pool.
//!
//! Implementation note: Task 8 uses a simple `Mutex<Vec<PacketBuf>>` free
//! list because every task in Phase 1 is single-threaded and the mutex is
//! uncontended. Later phases will swap this for an SPSC ring per pipeline
//! stage (Task 9) once the packet pipeline lands.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use desmos_proto::PacketBuf;

/// Pool statistics observable via [`PacketPool::stats`]. Counters use
/// `AtomicU64` with `Relaxed` ordering since they only feed the metrics
/// endpoint and never gate correctness decisions.
#[derive(Debug, Default)]
pub struct PoolStatsInner {
    acquires: AtomicU64,
    hits: AtomicU64,
    releases: AtomicU64,
    allocations: AtomicU64,
}

/// Snapshot of the counters taken at a single point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    pub acquires: u64,
    pub hits: u64,
    pub releases: u64,
    pub allocations: u64,
}

impl PoolStats {
    /// Fraction of acquires that were served from the free list. Returns
    /// `1.0` if no acquire has happened yet so an empty pool does not look
    /// artificially bad.
    pub fn hit_rate(self) -> f64 {
        if self.acquires == 0 {
            1.0
        } else {
            self.hits as f64 / self.acquires as f64
        }
    }
}

pub struct PacketPool {
    mtu: usize,
    free: Mutex<Vec<PacketBuf>>,
    stats: PoolStatsInner,
}

impl PacketPool {
    /// Create a pool for buffers sized for `mtu` bytes of payload. `prefill`
    /// buffers are allocated up front so the first `prefill` acquires never
    /// hit the allocator.
    pub fn new(mtu: usize, prefill: usize) -> Self {
        let mut free = Vec::with_capacity(prefill);
        let stats = PoolStatsInner::default();
        for _ in 0..prefill {
            free.push(PacketBuf::new(mtu));
            stats.allocations.fetch_add(1, Ordering::Relaxed);
        }
        Self { mtu, free: Mutex::new(free), stats }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Take a buffer from the free list, or allocate a fresh one if the list
    /// is empty. The returned buffer has `len == 0`.
    pub fn acquire(&self) -> PacketBuf {
        self.stats.acquires.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.free.lock().expect("pool mutex poisoned");
        if let Some(mut buf) = guard.pop() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            drop(guard);
            buf.reset();
            buf
        } else {
            drop(guard);
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            PacketBuf::new(self.mtu)
        }
    }

    /// Return a buffer to the free list for reuse.
    pub fn release(&self, mut buf: PacketBuf) {
        buf.reset();
        self.stats.releases.fetch_add(1, Ordering::Relaxed);
        self.free.lock().expect("pool mutex poisoned").push(buf);
    }

    /// Number of buffers currently sitting idle in the free list.
    pub fn idle(&self) -> usize {
        self.free.lock().expect("pool mutex poisoned").len()
    }

    /// Capture a consistent-enough snapshot of the pool counters.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            acquires: self.stats.acquires.load(Ordering::Relaxed),
            hits: self.stats.hits.load(Ordering::Relaxed),
            releases: self.stats.releases.load(Ordering::Relaxed),
            allocations: self.stats.allocations.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_prefill_populates_free_list() {
        let p = PacketPool::new(1400, 4);
        assert_eq!(p.idle(), 4);
        assert_eq!(p.stats().allocations, 4);
        assert_eq!(p.stats().acquires, 0);
    }

    #[test]
    fn acquire_pops_from_free_list() {
        let p = PacketPool::new(1400, 2);
        let buf = p.acquire();
        assert_eq!(buf.capacity(), 1400 + desmos_proto::PACKET_OVERHEAD);
        assert_eq!(p.idle(), 1);
        let stats = p.stats();
        assert_eq!(stats.acquires, 1);
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn acquire_allocates_when_empty() {
        let p = PacketPool::new(64, 0);
        let _ = p.acquire();
        let stats = p.stats();
        assert_eq!(stats.acquires, 1);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.allocations, 1);
    }

    #[test]
    fn release_returns_buffer_to_free_list() {
        let p = PacketPool::new(64, 0);
        let buf = p.acquire();
        p.release(buf);
        assert_eq!(p.idle(), 1);
        assert_eq!(p.stats().releases, 1);
    }

    #[test]
    fn release_resets_len() {
        let p = PacketPool::new(64, 0);
        let mut buf = p.acquire();
        buf.as_mut_capacity()[..3].copy_from_slice(b"xyz");
        buf.set_len(3);
        p.release(buf);
        let reused = p.acquire();
        assert_eq!(reused.len(), 0);
    }

    #[test]
    fn hit_rate_reports_fraction() {
        let p = PacketPool::new(64, 0);
        // First acquire misses (empty pool), rest hit after release.
        let b = p.acquire();
        p.release(b);
        for _ in 0..99 {
            let b = p.acquire();
            p.release(b);
        }
        let stats = p.stats();
        assert_eq!(stats.acquires, 100);
        assert_eq!(stats.hits, 99);
        assert!((stats.hit_rate() - 0.99).abs() < 1e-9);
    }
}
