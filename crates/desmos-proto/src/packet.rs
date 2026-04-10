//! Owning packet buffer and per-packet metadata.
//!
//! Buffers are sized `mtu + OVERHEAD` so there is always room for the
//! 16-byte DWP header, the 16-byte AEAD tag, and a little slack for
//! alignment and in-place crypto work. This matches `IMPLEMENTATION.md §2.6`.

use crate::types::InterfaceId;
use crate::types::TimestampUs;

/// Headroom + tailroom reserved on top of the tunnel MTU.
///
/// The budget is: 16 bytes DWP header + 16 bytes AEAD tag + space for
/// fragmentation metadata, control-packet fields, and alignment padding.
/// 256 bytes is easy to reason about and aligns well on 64-byte cache lines.
pub const PACKET_OVERHEAD: usize = 256;

/// A single owned packet buffer. The backing storage is a boxed slice so the
/// allocation is exactly one `Box<[u8]>` regardless of how many times the
/// buffer is passed through the pipeline.
#[derive(Debug)]
pub struct PacketBuf {
    data: Box<[u8]>,
    len: usize,
}

impl PacketBuf {
    /// Allocate a fresh buffer sized for the given tunnel MTU.
    ///
    /// Total capacity = `mtu + PACKET_OVERHEAD`. The buffer starts empty
    /// (length zero); call [`PacketBuf::set_len`] after writing into
    /// [`PacketBuf::as_mut_capacity`] to publish the filled region.
    pub fn new(mtu: usize) -> Self {
        let capacity = mtu.saturating_add(PACKET_OVERHEAD);
        Self { data: vec![0u8; capacity].into_boxed_slice(), len: 0 }
    }

    /// Total capacity in bytes (including [`PACKET_OVERHEAD`]).
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Number of bytes currently published as the packet payload.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Immutable view of the published region.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Mutable view of the published region.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Mutable view of the full backing buffer, used by I/O code that writes
    /// directly into the capacity (e.g. `recvmsg`) before calling
    /// [`PacketBuf::set_len`] to publish the read length.
    pub fn as_mut_capacity(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Publish `len` bytes as the packet payload.
    ///
    /// # Panics
    /// Panics if `len > capacity()`.
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.data.len(), "PacketBuf::set_len out of range");
        self.len = len;
    }

    /// Clear the published region without reallocating.
    pub fn reset(&mut self) {
        self.len = 0;
    }
}

/// Per-packet metadata that rides alongside the [`PacketBuf`] through the
/// pipeline. Stored separately so the hot path can move metadata via plain
/// `Copy` semantics without touching the heap-allocated buffer.
#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    pub interface_id: InterfaceId,
    pub received_at_us: TimestampUs,
    pub is_inbound: bool,
}

impl PacketMeta {
    pub fn inbound(interface_id: InterfaceId, received_at_us: TimestampUs) -> Self {
        Self { interface_id, received_at_us, is_inbound: true }
    }

    pub fn outbound(interface_id: InterfaceId, scheduled_at_us: TimestampUs) -> Self {
        Self { interface_id, received_at_us: scheduled_at_us, is_inbound: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_allocates_mtu_plus_overhead() {
        let b = PacketBuf::new(1400);
        assert_eq!(b.capacity(), 1400 + PACKET_OVERHEAD);
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn set_len_updates_published_region() {
        let mut b = PacketBuf::new(512);
        b.as_mut_capacity()[..5].copy_from_slice(b"hello");
        b.set_len(5);
        assert_eq!(b.len(), 5);
        assert_eq!(b.as_slice(), b"hello");
    }

    #[test]
    fn reset_zeroes_length_only() {
        let mut b = PacketBuf::new(64);
        b.as_mut_capacity()[..3].copy_from_slice(b"abc");
        b.set_len(3);
        b.reset();
        assert_eq!(b.len(), 0);
        // Capacity still populated with old bytes; that's intentional.
        assert_eq!(&b.as_mut_capacity()[..3], b"abc");
    }

    #[test]
    #[should_panic(expected = "PacketBuf::set_len out of range")]
    fn set_len_panics_on_overflow() {
        let mut b = PacketBuf::new(16);
        b.set_len(16 + PACKET_OVERHEAD + 1);
    }

    #[test]
    fn packet_meta_constructors() {
        let inbound = PacketMeta::inbound(InterfaceId(2), TimestampUs(100));
        assert!(inbound.is_inbound);
        let outbound = PacketMeta::outbound(InterfaceId(3), TimestampUs(200));
        assert!(!outbound.is_inbound);
    }
}
