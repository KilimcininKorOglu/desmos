//! Out-of-order reorder buffer with gap timeout.
//!
//! Bonded traffic arrives on multiple links whose one-way latencies
//! differ, so the decrypted inbound stream is almost guaranteed to be
//! slightly out of order. The reorder buffer holds packets keyed by
//! their sequence number until every earlier packet has either
//! arrived or timed out, then emits them in strict sequence.
//!
//! The buffer is single-writer — one per session, owned by the
//! inbound pipeline stage. It allocates nothing on the fast path for
//! in-order traffic; only out-of-order arrivals hit the `BTreeMap`.
//!
//! # Gap handling
//!
//! Two mechanisms declare a missing packet lost:
//!
//! 1. **Window pressure.** If a new seq arrives that is `window` or
//!    more ahead of `next_expected`, the gap is considered permanent
//!    — later-than-window packets would force unbounded buffering —
//!    and we skip to the new high-water mark.
//! 2. **Gap timeout.** A polling call checks the oldest pending
//!    packet's receive timestamp; if it has been waiting longer than
//!    `gap_timeout_ms` for an earlier packet that never came, we skip
//!    past the missing seqs and release everything that is now
//!    contiguous.
//!
//! Both paths bump the `lost` counter by the exact number of seqs
//! that were skipped so upper-layer metrics stay accurate.

use std::collections::BTreeMap;

/// Buffered packet awaiting in-order release.
struct Pending<T> {
    payload: T,
    received_at_ms: u64,
}

/// Single-session reorder buffer.
pub struct ReorderBuffer<T> {
    /// Next sequence number expected to be delivered. Starts at the
    /// seq of the first packet pushed; see `initialised`.
    next_expected: u64,
    /// Out-of-order packets waiting for earlier seqs.
    pending: BTreeMap<u64, Pending<T>>,
    /// Maximum tolerated gap (in seq units) between `next_expected`
    /// and the newest incoming packet before we force-skip.
    window: u64,
    /// Gap timeout in milliseconds. If the head packet has been
    /// waiting longer than this for its predecessor, we declare the
    /// predecessor lost.
    gap_timeout_ms: u64,
    /// Set by the first successful `push` so we can learn the stream's
    /// starting seq without hard-coding zero (the real DWP counter
    /// starts at 0 but the session rekey resets it; starting from the
    /// first observed seq is friendlier to both cases).
    initialised: bool,
    delivered: u64,
    lost: u64,
    duplicates: u64,
}

impl<T> ReorderBuffer<T> {
    /// Build a new reorder buffer. `window` is the max seq distance
    /// tolerated between `next_expected` and an incoming seq before a
    /// force-skip fires; `gap_timeout_ms` is the wall-clock wait
    /// before a head gap is declared lost.
    pub fn new(window: u64, gap_timeout_ms: u64) -> Self {
        Self {
            next_expected: 0,
            pending: BTreeMap::new(),
            window,
            gap_timeout_ms,
            initialised: false,
            delivered: 0,
            lost: 0,
            duplicates: 0,
        }
    }

    pub fn delivered_count(&self) -> u64 {
        self.delivered
    }

    pub fn lost_count(&self) -> u64 {
        self.lost
    }

    pub fn duplicate_count(&self) -> u64 {
        self.duplicates
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Return the next expected sequence number. Only meaningful once
    /// at least one packet has been successfully pushed.
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Feed one packet into the buffer. Returns the zero or more
    /// payloads that are now ready for delivery, in strict sequence
    /// order. An empty vector means the packet is waiting for an
    /// earlier arrival.
    pub fn push(&mut self, seq: u64, payload: T, now_ms: u64) -> Vec<T> {
        if !self.initialised {
            self.initialised = true;
            self.next_expected = seq + 1;
            self.delivered += 1;
            return vec![payload];
        }

        // Late or duplicate arrival.
        if seq < self.next_expected {
            self.duplicates += 1;
            return Vec::new();
        }
        // Duplicate of something already buffered.
        if self.pending.contains_key(&seq) {
            self.duplicates += 1;
            return Vec::new();
        }

        // Window pressure: the seq is far enough ahead that buffering
        // further would risk unbounded growth. Force-skip the
        // missing seqs and deliver from the new high-water mark.
        if seq >= self.next_expected + self.window {
            let skipped = seq - self.next_expected;
            self.lost += skipped;
            self.next_expected = seq + 1;
            self.delivered += 1;
            // Drop any pending entries that are now below the new
            // high-water mark — they are too stale to be useful.
            self.pending.retain(|&k, _| k > seq);
            let mut out = vec![payload];
            self.drain_contiguous(&mut out);
            return out;
        }

        if seq == self.next_expected {
            self.next_expected += 1;
            self.delivered += 1;
            let mut out = vec![payload];
            self.drain_contiguous(&mut out);
            return out;
        }

        // seq > next_expected, within window: buffer it.
        self.pending.insert(seq, Pending { payload, received_at_ms: now_ms });
        Vec::new()
    }

    /// Drain any pending packets whose seq is now `next_expected`,
    /// advancing the counter. Appends delivered payloads to `out` in
    /// order. Used after every advance of `next_expected`.
    fn drain_contiguous(&mut self, out: &mut Vec<T>) {
        while let Some(p) = self.pending.remove(&self.next_expected) {
            out.push(p.payload);
            self.next_expected += 1;
            self.delivered += 1;
        }
    }

    /// Time-based gap release. If the oldest pending packet has been
    /// waiting longer than `gap_timeout_ms`, declare the gap between
    /// `next_expected` and that packet lost, skip past it, and drain
    /// everything that is now contiguous.
    pub fn poll_timeout(&mut self, now_ms: u64) -> Vec<T> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        // Find the oldest (by received_at_ms) pending entry. For the
        // small windows we expect (~128), a linear scan is cheaper
        // than maintaining a secondary index.
        let oldest_age = self
            .pending
            .values()
            .map(|p| now_ms.saturating_sub(p.received_at_ms))
            .max()
            .unwrap_or(0);
        if oldest_age < self.gap_timeout_ms {
            return Vec::new();
        }
        // Skip `next_expected` forward to the earliest pending seq
        // that is actually in the buffer. BTreeMap keys are sorted
        // so `.next()` gives the smallest.
        let oldest_seq = *self.pending.keys().next().unwrap();
        if oldest_seq > self.next_expected {
            let skipped = oldest_seq - self.next_expected;
            self.lost += skipped;
            self.next_expected = oldest_seq;
        }
        let mut out = Vec::new();
        self.drain_contiguous(&mut out);
        out
    }
}

impl<T> core::fmt::Debug for ReorderBuffer<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReorderBuffer")
            .field("next_expected", &self.next_expected)
            .field("pending", &self.pending.len())
            .field("delivered", &self.delivered)
            .field("lost", &self.lost)
            .field("duplicates", &self.duplicates)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_buf() -> ReorderBuffer<u32> {
        ReorderBuffer::new(128, 50)
    }

    #[test]
    fn in_order_stream_delivers_immediately() {
        let mut buf = new_buf();
        for seq in 0..10u64 {
            let out = buf.push(seq, seq as u32, 0);
            assert_eq!(out, vec![seq as u32]);
        }
        assert_eq!(buf.delivered_count(), 10);
        assert_eq!(buf.lost_count(), 0);
        assert_eq!(buf.duplicate_count(), 0);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn first_packet_can_be_nonzero_seq() {
        let mut buf = new_buf();
        let out = buf.push(500, 500u32, 0);
        assert_eq!(out, vec![500u32]);
        assert_eq!(buf.next_expected(), 501);
    }

    #[test]
    fn out_of_order_packet_is_buffered_until_gap_fills() {
        let mut buf = new_buf();
        assert_eq!(buf.push(0, 0u32, 0), vec![0]);
        // seq 2 arrives before seq 1.
        assert!(buf.push(2, 2u32, 1).is_empty());
        assert_eq!(buf.pending_count(), 1);
        // seq 1 unlocks both.
        let out = buf.push(1, 1u32, 2);
        assert_eq!(out, vec![1, 2]);
        assert_eq!(buf.pending_count(), 0);
        assert_eq!(buf.delivered_count(), 3);
    }

    #[test]
    fn multiple_out_of_order_drain_in_correct_order() {
        let mut buf = new_buf();
        assert_eq!(buf.push(0, 0, 0), vec![0]);
        assert!(buf.push(3, 3, 1).is_empty());
        assert!(buf.push(5, 5, 2).is_empty());
        assert!(buf.push(2, 2, 3).is_empty());
        assert!(buf.push(4, 4, 4).is_empty());
        // 1 arrives — unlocks 1,2,3,4,5.
        let out = buf.push(1, 1, 5);
        assert_eq!(out, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn duplicate_of_already_delivered_is_dropped() {
        let mut buf = new_buf();
        buf.push(0, 0, 0);
        buf.push(1, 1, 0);
        let out = buf.push(0, 0, 1);
        assert!(out.is_empty());
        assert_eq!(buf.duplicate_count(), 1);
        assert_eq!(buf.delivered_count(), 2);
    }

    #[test]
    fn duplicate_of_buffered_pending_is_dropped() {
        let mut buf = new_buf();
        buf.push(0, 0, 0);
        buf.push(3, 3, 1);
        let out = buf.push(3, 3, 2);
        assert!(out.is_empty());
        assert_eq!(buf.duplicate_count(), 1);
        assert_eq!(buf.pending_count(), 1);
    }

    #[test]
    fn window_pressure_forces_skip() {
        let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(4, 1_000);
        buf.push(0, 0, 0);
        // Next expected is 1; push seq 1 + window = 5 -> force skip
        // the seqs 1, 2, 3, 4 as lost and deliver seq 5 immediately.
        let out = buf.push(5, 5, 1);
        assert_eq!(out, vec![5]);
        assert_eq!(buf.lost_count(), 4);
        assert_eq!(buf.delivered_count(), 2);
    }

    #[test]
    fn gap_timeout_fires_and_skips_missing_packet() {
        let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(128, 50);
        buf.push(0, 0, 0);
        buf.push(2, 2, 10);
        assert_eq!(buf.pending_count(), 1);
        // t=30: not enough time has passed yet.
        assert!(buf.poll_timeout(30).is_empty());
        assert_eq!(buf.pending_count(), 1);
        // t=65: packet 2 has been waiting 55ms > 50ms timeout.
        let out = buf.poll_timeout(65);
        assert_eq!(out, vec![2]);
        assert_eq!(buf.lost_count(), 1);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn gap_timeout_drains_chain_once_gap_clears() {
        let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(128, 50);
        buf.push(0, 0, 0);
        buf.push(2, 2, 10);
        buf.push(3, 3, 10);
        // 1 is missing; timeout skips past it and delivers 2, 3.
        let out = buf.poll_timeout(100);
        assert_eq!(out, vec![2, 3]);
        assert_eq!(buf.lost_count(), 1);
    }

    #[test]
    fn pending_count_tracks_buffered_entries() {
        let mut buf = new_buf();
        buf.push(0, 0, 0);
        assert_eq!(buf.pending_count(), 0);
        buf.push(3, 3, 0);
        assert_eq!(buf.pending_count(), 1);
        buf.push(5, 5, 0);
        assert_eq!(buf.pending_count(), 2);
        buf.push(1, 1, 0);
        // 1 released 1 + nothing else (2 is still missing).
        assert_eq!(buf.pending_count(), 2);
        buf.push(2, 2, 0);
        // Chain 2, 3 released. Only 5 still buffered.
        assert_eq!(buf.pending_count(), 1);
    }

    #[test]
    fn very_late_packet_after_force_skip_is_duplicate() {
        let mut buf: ReorderBuffer<u32> = ReorderBuffer::new(4, 1_000);
        buf.push(0, 0, 0);
        buf.push(5, 5, 1); // force-skip: next_expected becomes 6
        let out = buf.push(3, 3, 2);
        assert!(out.is_empty());
        assert_eq!(buf.duplicate_count(), 1);
    }

    #[test]
    fn next_expected_advances_monotonically() {
        let mut buf = new_buf();
        buf.push(0, 0, 0);
        assert_eq!(buf.next_expected(), 1);
        buf.push(2, 2, 0);
        assert_eq!(buf.next_expected(), 1); // still waiting for 1
        buf.push(1, 1, 0);
        assert_eq!(buf.next_expected(), 3); // released 1 + 2
    }
}
