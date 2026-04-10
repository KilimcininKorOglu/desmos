//! Atomic per-pipeline counters.
//!
//! The inbound and outbound encrypted pipeline stages bump these
//! counters on every packet so the CLI status command, Web UI, and
//! tests can read them without holding any locks. Everything is
//! `Relaxed` — we only need visibility-across-threads, not ordering
//! between counters.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Per-pipeline metric block. A single `PipelineMetrics` covers one
/// tunnel direction pair (outbound + inbound stages share it so
/// dashboards show a unified view).
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    /// DWP header decode failed or declared a bad length.
    pub bad_header: AtomicU64,
    /// AEAD `open_in_place` rejected the packet (tag mismatch, tampered
    /// ciphertext, or wrong session id / sequence pair).
    pub decrypt_failures: AtomicU64,
    /// Anti-replay window rejected the packet as a duplicate or as
    /// out-of-window.
    pub replay_drops: AtomicU64,
}

impl PipelineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_bad_header(&self) {
        self.bad_header.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_decrypt_failure(&self) {
        self.decrypt_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_replay_drop(&self) {
        self.replay_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the counters into a plain struct. Useful for CLI
    /// rendering or comparing two points in time.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bad_header: self.bad_header.load(Ordering::Relaxed),
            decrypt_failures: self.decrypt_failures.load(Ordering::Relaxed),
            replay_drops: self.replay_drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bad_header: u64,
    pub decrypt_failures: u64,
    pub replay_drops: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_are_all_zero() {
        let m = PipelineMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap, MetricsSnapshot::default());
    }

    #[test]
    fn record_sent_updates_packets_and_bytes() {
        let m = PipelineMetrics::new();
        m.record_sent(100);
        m.record_sent(250);
        let snap = m.snapshot();
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.bytes_sent, 350);
    }

    #[test]
    fn record_received_updates_packets_and_bytes() {
        let m = PipelineMetrics::new();
        m.record_received(42);
        let snap = m.snapshot();
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.bytes_received, 42);
    }

    #[test]
    fn error_counters_are_independent() {
        let m = PipelineMetrics::new();
        m.record_bad_header();
        m.record_decrypt_failure();
        m.record_decrypt_failure();
        m.record_replay_drop();
        let snap = m.snapshot();
        assert_eq!(snap.bad_header, 1);
        assert_eq!(snap.decrypt_failures, 2);
        assert_eq!(snap.replay_drops, 1);
    }
}
