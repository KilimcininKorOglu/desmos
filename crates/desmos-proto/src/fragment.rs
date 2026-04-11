//! In-protocol fragmentation for oversized DWP payloads.
//!
//! The DWP wire format carries a u16 `payload_len`, so any single
//! encrypted packet fits in 64 KiB. On a real tunnel the useful limit
//! is the path MTU of the slowest link (after the encapsulation
//! overhead): typically ~1200 bytes over IPv4 or 1220 over IPv6.
//! TCP inside the tunnel will clamp to the MSS that PMTUD advertises,
//! but the tunnel itself must still cope with oversized UDP packets
//! (for example, an application pushing a 9 KiB jumbogram straight
//! into the TUN).
//!
//! The solution is symmetric with IP fragmentation but at the DWP
//! layer: split the plaintext into pieces that each fit under the
//! measured MTU minus overhead, tag every fragment with a small
//! per-group sub-header, set `Flags::FRAG` in the DWP header, and
//! let the receiver reassemble into the original plaintext before
//! handing it to the TUN.
//!
//! # Wire layout
//!
//! When `Flags::FRAG` is set, the encrypted payload starts with a
//! 4-byte fragment sub-header:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          fragment_id          |     offset    |     total     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `fragment_id` groups all fragments of a single original packet;
//! `offset` is the fragment index (0-based); `total` is the fragment
//! count. `total == 1` is a valid (degenerate) encoding of an
//! unfragmented packet — receivers should never see it on the wire
//! but the library handles it without special-casing.
//!
//! The sub-header is part of the AEAD plaintext, so tampering with
//! it is caught by the tag check — fragment metadata is
//! authenticated end-to-end for free.

use core::fmt;

/// Fixed size of the on-wire fragment sub-header, in bytes.
pub const FRAGMENT_HEADER_LEN: usize = 4;

/// Maximum fragments we support per original packet. `offset` and
/// `total` are u8s so the wire limit is 255; we clamp at 64 for
/// the fragmenter and reassembler so a single malicious packet cannot
/// pin 255 allocations inside the reassembler before the AEAD ever
/// catches it. `64 × 1400` is 89 KiB, well past any realistic tunnel
/// payload.
pub const MAX_FRAGMENTS: usize = 64;

/// Errors produced by the fragment encoder, decoder, and reassembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// `FragmentHeader::decode` was given a slice shorter than the
    /// 4-byte sub-header.
    ShortHeader,
    /// `total == 0` or `offset >= total`.
    InvalidHeader,
    /// Fragment count exceeded `MAX_FRAGMENTS`.
    TooManyFragments,
    /// `fragment(...)` was asked to produce fragments larger than the
    /// caller's allowed size after sub-header overhead.
    FragmentTooLarge,
    /// `fragment(...)` was given a zero-byte payload.
    EmptyPayload,
    /// Reassembler saw two fragments with the same `(fragment_id,
    /// offset)` whose bodies did not match — treated as tampering,
    /// the entire group is discarded.
    Inconsistent,
    /// Reassembler saw a fragment whose `total` did not match the
    /// `total` previously reported for the same `fragment_id`.
    MismatchedTotal,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader => f.write_str("fragment: header shorter than 4 bytes"),
            Self::InvalidHeader => f.write_str("fragment: offset >= total or total == 0"),
            Self::TooManyFragments => f.write_str("fragment: too many fragments"),
            Self::FragmentTooLarge => f.write_str("fragment: requested fragment size too large"),
            Self::EmptyPayload => f.write_str("fragment: cannot fragment empty payload"),
            Self::Inconsistent => f.write_str("fragment: duplicate offset with different body"),
            Self::MismatchedTotal => f.write_str("fragment: total count disagrees with earlier"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// 4-byte fragment sub-header carried at the start of every FRAG
/// payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    pub fragment_id: u16,
    pub offset: u8,
    pub total: u8,
}

impl FragmentHeader {
    /// Construct and validate. Returns `InvalidHeader` if `total`
    /// is zero or `offset >= total`.
    pub fn new(fragment_id: u16, offset: u8, total: u8) -> Result<Self, FragmentError> {
        if total == 0 || offset >= total {
            return Err(FragmentError::InvalidHeader);
        }
        Ok(Self { fragment_id, offset, total })
    }

    /// Encode the header into the first 4 bytes of `buf`. Returns
    /// `ShortHeader` if `buf.len() < 4`.
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), FragmentError> {
        if buf.len() < FRAGMENT_HEADER_LEN {
            return Err(FragmentError::ShortHeader);
        }
        buf[..2].copy_from_slice(&self.fragment_id.to_be_bytes());
        buf[2] = self.offset;
        buf[3] = self.total;
        Ok(())
    }

    /// Decode the first 4 bytes of `buf`. Returns `ShortHeader` on
    /// truncation and `InvalidHeader` on `total == 0` or
    /// `offset >= total`.
    pub fn decode(buf: &[u8]) -> Result<Self, FragmentError> {
        if buf.len() < FRAGMENT_HEADER_LEN {
            return Err(FragmentError::ShortHeader);
        }
        let fragment_id = u16::from_be_bytes([buf[0], buf[1]]);
        let offset = buf[2];
        let total = buf[3];
        Self::new(fragment_id, offset, total)
    }

    /// `true` when this is the last fragment in its group.
    pub fn is_last(&self) -> bool {
        self.offset + 1 == self.total
    }
}

/// Split `payload` into fragments whose pre-framed length (header +
/// body) fits in `max_fragment_len` bytes. The output is a vector of
/// ready-to-seal fragments, each already carrying its own sub-header.
///
/// `max_fragment_len` is the post-header budget, so the caller
/// computes it as `tunnel_mtu - PACKET_OVERHEAD`. A value smaller
/// than `FRAGMENT_HEADER_LEN + 1` returns [`FragmentError::FragmentTooLarge`].
pub fn fragment(
    payload: &[u8],
    max_fragment_len: usize,
    fragment_id: u16,
) -> Result<Vec<Vec<u8>>, FragmentError> {
    if payload.is_empty() {
        return Err(FragmentError::EmptyPayload);
    }
    if max_fragment_len <= FRAGMENT_HEADER_LEN {
        return Err(FragmentError::FragmentTooLarge);
    }
    let body_per_fragment = max_fragment_len - FRAGMENT_HEADER_LEN;
    let total = payload.len().div_ceil(body_per_fragment);
    if total == 0 || total > MAX_FRAGMENTS || total > u8::MAX as usize {
        return Err(FragmentError::TooManyFragments);
    }
    let total_u8 = total as u8;

    let mut out = Vec::with_capacity(total);
    for (idx, chunk) in payload.chunks(body_per_fragment).enumerate() {
        let hdr = FragmentHeader::new(fragment_id, idx as u8, total_u8)?;
        let mut buf = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        buf.extend_from_slice(&[0u8; FRAGMENT_HEADER_LEN]);
        hdr.encode(&mut buf[..FRAGMENT_HEADER_LEN])?;
        buf.extend_from_slice(chunk);
        out.push(buf);
    }
    Ok(out)
}

/// Reassemble fragments for multiple logical packets in parallel.
///
/// The receiver feeds every decrypted fragment payload (starting with
/// the 4-byte sub-header) into [`Reassembler::push`]. When the last
/// fragment of a group arrives the method returns the fully
/// reassembled original plaintext; earlier calls return `Ok(None)`.
///
/// `Reassembler` is per-session: the pipeline stage creates one
/// inside each `Session<Established>` slot (or equivalent). Fragment
/// IDs are 16-bit and wrap every 65 536 logical packets, which is
/// far more than the reassembler's working set; we take an LRU
/// policy and drop the oldest in-flight group if the total in-flight
/// count exceeds `in_flight_limit`.
#[derive(Debug, Clone)]
pub struct Reassembler {
    in_flight: std::collections::HashMap<u16, PartialGroup>,
    /// Insertion order — oldest groups expire first.
    order: std::collections::VecDeque<u16>,
    in_flight_limit: usize,
}

#[derive(Debug, Clone)]
struct PartialGroup {
    total: u8,
    /// `Option<Vec<u8>>` per offset slot so we can tell "not yet
    /// arrived" apart from "empty fragment".
    slots: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(32)
    }
}

impl Reassembler {
    /// Construct with a configurable LRU cap on in-flight groups.
    pub fn new(in_flight_limit: usize) -> Self {
        Self {
            in_flight: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            in_flight_limit: in_flight_limit.max(1),
        }
    }

    /// Number of logical packets currently being reassembled.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Feed one fragment. Returns `Ok(Some(payload))` when this
    /// fragment completes its group, `Ok(None)` when more fragments
    /// are still outstanding, or an error on a malformed / conflict
    /// fragment.
    pub fn push(&mut self, fragment_bytes: &[u8]) -> Result<Option<Vec<u8>>, FragmentError> {
        let hdr = FragmentHeader::decode(fragment_bytes)?;
        let body = &fragment_bytes[FRAGMENT_HEADER_LEN..];

        let total = hdr.total as usize;
        if total > MAX_FRAGMENTS {
            return Err(FragmentError::TooManyFragments);
        }

        // Evict the oldest group if we are already at capacity and
        // this fragment belongs to a new group.
        if !self.in_flight.contains_key(&hdr.fragment_id)
            && self.in_flight.len() >= self.in_flight_limit
        {
            if let Some(oldest) = self.order.pop_front() {
                self.in_flight.remove(&oldest);
            }
        }

        use std::collections::hash_map::Entry;
        let group = match self.in_flight.entry(hdr.fragment_id) {
            Entry::Vacant(e) => {
                self.order.push_back(hdr.fragment_id);
                e.insert(PartialGroup { total: hdr.total, slots: vec![None; total], received: 0 })
            }
            Entry::Occupied(e) => e.into_mut(),
        };

        if group.total != hdr.total {
            return Err(FragmentError::MismatchedTotal);
        }

        let slot = &mut group.slots[hdr.offset as usize];
        match slot {
            Some(existing) if existing.as_slice() != body => {
                return Err(FragmentError::Inconsistent);
            }
            Some(_) => {
                // Idempotent duplicate, drop silently.
            }
            None => {
                *slot = Some(body.to_vec());
                group.received += 1;
            }
        }

        if group.received == total {
            // Complete. Drain the slots in order.
            let done = self.in_flight.remove(&hdr.fragment_id).expect("present by construction");
            // Remove from the order deque so future evictions skip it.
            if let Some(pos) = self.order.iter().position(|&id| id == hdr.fragment_id) {
                self.order.remove(pos);
            }
            let mut out = Vec::new();
            for slot in done.slots {
                out.extend_from_slice(&slot.expect("every slot is Some when received == total"));
            }
            return Ok(Some(out));
        }

        Ok(None)
    }

    /// Drop every in-flight group. Called when a rekey happens or
    /// the session is closed — the reassembler's state is scoped to
    /// one epoch.
    pub fn clear(&mut self) {
        self.in_flight.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let hdr = FragmentHeader::new(0xBEEF, 2, 4).unwrap();
        let mut buf = [0u8; FRAGMENT_HEADER_LEN];
        hdr.encode(&mut buf).unwrap();
        assert_eq!(buf, [0xBE, 0xEF, 0x02, 0x04]);
        let decoded = FragmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, hdr);
        assert!(!hdr.is_last());
        assert!(FragmentHeader::new(0xBEEF, 3, 4).unwrap().is_last());
    }

    #[test]
    fn header_rejects_zero_total() {
        assert_eq!(FragmentHeader::new(1, 0, 0).unwrap_err(), FragmentError::InvalidHeader,);
    }

    #[test]
    fn header_rejects_offset_out_of_range() {
        assert_eq!(FragmentHeader::new(1, 3, 3).unwrap_err(), FragmentError::InvalidHeader,);
        assert_eq!(FragmentHeader::new(1, 99, 4).unwrap_err(), FragmentError::InvalidHeader,);
    }

    #[test]
    fn header_decode_rejects_short_buffer() {
        assert_eq!(FragmentHeader::decode(&[0u8; 3]).unwrap_err(), FragmentError::ShortHeader,);
    }

    #[test]
    fn fragment_roundtrip_single_fragment_unsplit() {
        // Payload small enough to fit in one fragment.
        let payload = b"small payload";
        let out = fragment(payload, 100, 1).unwrap();
        assert_eq!(out.len(), 1);
        let hdr = FragmentHeader::decode(&out[0]).unwrap();
        assert_eq!(hdr.total, 1);
        assert_eq!(hdr.offset, 0);
        assert_eq!(&out[0][FRAGMENT_HEADER_LEN..], payload);
    }

    #[test]
    fn fragment_roundtrip_four_times_tunnel_mtu() {
        // Simulate a 1 KiB tunnel MTU and a ~4 KiB application payload.
        let max_fragment_len = 1_024;
        let body_per_fragment = max_fragment_len - FRAGMENT_HEADER_LEN;
        let payload: Vec<u8> = (0..4_000u32).map(|i| i as u8).collect();
        let fragments = fragment(&payload, max_fragment_len, 0x1234).unwrap();
        // ceil(4000 / 1020) = 4.
        assert_eq!(fragments.len(), 4);
        for (i, frag) in fragments.iter().enumerate() {
            let hdr = FragmentHeader::decode(frag).unwrap();
            assert_eq!(hdr.fragment_id, 0x1234);
            assert_eq!(hdr.offset, i as u8);
            assert_eq!(hdr.total, 4);
            assert!(frag.len() - FRAGMENT_HEADER_LEN <= body_per_fragment);
        }

        // Reassemble — out-of-order to exercise the slot-based path.
        let mut reasm = Reassembler::default();
        assert!(reasm.push(&fragments[1]).unwrap().is_none());
        assert!(reasm.push(&fragments[3]).unwrap().is_none());
        assert!(reasm.push(&fragments[0]).unwrap().is_none());
        let out = reasm.push(&fragments[2]).unwrap().unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn fragment_empty_payload_is_rejected() {
        assert_eq!(fragment(&[], 128, 0).unwrap_err(), FragmentError::EmptyPayload,);
    }

    #[test]
    fn fragment_too_small_budget_is_rejected() {
        // Budget ≤ header size leaves no room for body.
        assert_eq!(
            fragment(b"x", FRAGMENT_HEADER_LEN, 0).unwrap_err(),
            FragmentError::FragmentTooLarge,
        );
    }

    #[test]
    fn fragment_over_max_fragments_is_rejected() {
        // Payload that would need more than MAX_FRAGMENTS pieces at
        // a 5-byte budget (= 1 body byte per fragment).
        let payload = vec![0u8; MAX_FRAGMENTS + 1];
        let err = fragment(&payload, 5, 0).unwrap_err();
        assert_eq!(err, FragmentError::TooManyFragments);
    }

    #[test]
    fn reassembler_duplicate_fragment_is_idempotent() {
        // 4-byte payload at 2-byte body budget = 2 fragments.
        let fragments = fragment(&[1u8, 2, 3, 4], 6, 0).unwrap();
        assert_eq!(fragments.len(), 2);
        let mut reasm = Reassembler::default();
        reasm.push(&fragments[0]).unwrap();
        // Duplicate of offset 0 — idempotent, still pending.
        assert!(reasm.push(&fragments[0]).unwrap().is_none());
        let out = reasm.push(&fragments[1]).unwrap();
        assert!(out.is_some());
    }

    #[test]
    fn reassembler_conflicting_duplicate_is_rejected() {
        let fragments = fragment(&[1u8, 2, 3, 4, 5], 6, 0).unwrap();
        let mut tampered = fragments[0].clone();
        tampered[FRAGMENT_HEADER_LEN] ^= 0xff;
        let mut reasm = Reassembler::default();
        reasm.push(&fragments[0]).unwrap();
        assert_eq!(reasm.push(&tampered).unwrap_err(), FragmentError::Inconsistent,);
    }

    #[test]
    fn reassembler_mismatched_total_is_rejected() {
        // 10 bytes / 2-byte body = 5 fragments. The rogue claims 7
        // fragments (still inside MAX_FRAGMENTS so the total-bound
        // check does not fire first).
        let fragments = fragment(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10], 6, 0).unwrap();
        assert_eq!(fragments.len(), 5);
        let rogue_hdr = FragmentHeader::new(0, 0, 7).unwrap();
        let mut rogue = vec![0u8; FRAGMENT_HEADER_LEN];
        rogue_hdr.encode(&mut rogue).unwrap();
        rogue.extend_from_slice(b"x");
        let mut reasm = Reassembler::default();
        reasm.push(&fragments[0]).unwrap();
        assert_eq!(reasm.push(&rogue).unwrap_err(), FragmentError::MismatchedTotal,);
    }

    #[test]
    fn reassembler_lru_eviction_kicks_oldest_group() {
        let mut reasm = Reassembler::new(2);
        let a = fragment(&[1u8; 10], 6, 1).unwrap();
        let b = fragment(&[2u8; 10], 6, 2).unwrap();
        let c = fragment(&[3u8; 10], 6, 3).unwrap();
        reasm.push(&a[0]).unwrap();
        reasm.push(&b[0]).unwrap();
        assert_eq!(reasm.in_flight(), 2);
        reasm.push(&c[0]).unwrap();
        // Group `a` was evicted; `b` and `c` remain.
        assert_eq!(reasm.in_flight(), 2);
        // Pushing the rest of `a` starts a brand-new group; its
        // earlier offset 0 is gone, so we never complete.
        reasm.push(&a[1]).unwrap();
        // In the LRU-evicted scenario the reassembler sees `a[1]` as
        // the start of a new group with missing offset 0, so it
        // lingers until eviction or completion by offset 0.
        assert!(reasm.in_flight() > 0);
    }

    #[test]
    fn reassembler_clear_drops_everything() {
        let mut reasm = Reassembler::new(4);
        let f = fragment(&[1u8, 2, 3, 4, 5], 6, 0).unwrap();
        reasm.push(&f[0]).unwrap();
        assert_eq!(reasm.in_flight(), 1);
        reasm.clear();
        assert_eq!(reasm.in_flight(), 0);
    }

    #[test]
    fn reassembler_single_fragment_completes_immediately() {
        let fragments = fragment(b"fits", 100, 7).unwrap();
        assert_eq!(fragments.len(), 1);
        let mut reasm = Reassembler::default();
        let out = reasm.push(&fragments[0]).unwrap().unwrap();
        assert_eq!(out, b"fits");
    }
}
