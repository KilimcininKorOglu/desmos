//! DWP header codec.
//!
//! The Desmos Wire Protocol header is a fixed 16-byte big-endian frame that
//! sits in front of an encrypted payload and its 128-bit AEAD tag. See
//! `IMPLEMENTATION.md §4.1` for the layout:
//!
//! ```text
//! Offset  Size  Field
//!  0      1B    (version<<4) | type
//!  1      1B    flags
//!  2      2B    session_id   (big-endian u16)
//!  4      4B    sequence     (big-endian u32)
//!  8      4B    timestamp_us (big-endian u32)
//! 12      2B    payload_len  (big-endian u16)
//! 14      1B    interface_id
//! 15      1B    reserved
//! ```

use crate::errors::WireError;
use crate::flags::Flags;
use crate::types::InterfaceId;
use crate::types::Seq;
use crate::types::SessionId;
use crate::types::TimestampUs;

/// Size of the unencrypted header in bytes.
pub const HEADER_LEN: usize = 16;

/// Protocol version carried in the high nibble of byte 0.
pub const WIRE_VERSION: u8 = 1;

/// Size of the trailing Poly1305 authentication tag (bytes).
pub const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    Data = 0,
    Handshake = 1,
    Keepalive = 2,
    Probe = 3,
    Control = 4,
}

impl PacketType {
    pub const fn as_nibble(self) -> u8 {
        self as u8
    }

    pub const fn from_nibble(n: u8) -> Result<Self, WireError> {
        match n {
            0 => Ok(Self::Data),
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Keepalive),
            3 => Ok(Self::Probe),
            4 => Ok(Self::Control),
            other => Err(WireError::UnknownPacketType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: Flags,
    pub session_id: SessionId,
    pub sequence: Seq,
    pub timestamp_us: TimestampUs,
    pub payload_len: u16,
    pub interface_id: InterfaceId,
}

impl Header {
    /// Build a fresh header with `version = WIRE_VERSION`, empty flags,
    /// zero timestamp / sequence, and no payload.
    pub fn new(packet_type: PacketType, session_id: SessionId) -> Self {
        Self {
            version: WIRE_VERSION,
            packet_type,
            flags: Flags::EMPTY,
            session_id,
            sequence: Seq(0),
            timestamp_us: TimestampUs(0),
            payload_len: 0,
            interface_id: InterfaceId(0),
        }
    }

    /// Serialise into the first 16 bytes of `out`. Returns `HEADER_LEN` on
    /// success so callers can advance a cursor.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if out.len() < HEADER_LEN {
            return Err(WireError::BufferTooShort { need: HEADER_LEN, got: out.len() });
        }
        out[0] = ((self.version & 0x0f) << 4) | (self.packet_type.as_nibble() & 0x0f);
        out[1] = self.flags.bits();
        out[2..4].copy_from_slice(&self.session_id.0.to_be_bytes());
        out[4..8].copy_from_slice(&self.sequence.0.to_be_bytes());
        out[8..12].copy_from_slice(&self.timestamp_us.0.to_be_bytes());
        out[12..14].copy_from_slice(&self.payload_len.to_be_bytes());
        out[14] = self.interface_id.0;
        out[15] = 0;
        Ok(HEADER_LEN)
    }

    /// Parse a header from the first 16 bytes of `bytes`. Returns
    /// `WireError::UnsupportedVersion` when the high nibble is not
    /// [`WIRE_VERSION`], and `WireError::UnknownPacketType` when the low
    /// nibble does not map to a known [`PacketType`].
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < HEADER_LEN {
            return Err(WireError::BufferTooShort { need: HEADER_LEN, got: bytes.len() });
        }
        let version = (bytes[0] >> 4) & 0x0f;
        if version != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }
        let packet_type = PacketType::from_nibble(bytes[0] & 0x0f)?;
        let flags = Flags::from_bits(bytes[1]);
        let session_id = SessionId(u16::from_be_bytes([bytes[2], bytes[3]]));
        let sequence = Seq(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
        let timestamp_us =
            TimestampUs(u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]));
        let payload_len = u16::from_be_bytes([bytes[12], bytes[13]]);
        let interface_id = InterfaceId(bytes[14]);
        // bytes[15] is reserved; deliberately ignored.

        Ok(Self {
            version,
            packet_type,
            flags,
            session_id,
            sequence,
            timestamp_us,
            payload_len,
            interface_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            version: WIRE_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::ACK | Flags::PRIORITY,
            session_id: SessionId(0xBEEF),
            sequence: Seq(0x1234_5678),
            timestamp_us: TimestampUs(0xCAFE_BABE),
            payload_len: 1280,
            interface_id: InterfaceId(7),
        }
    }

    #[test]
    fn encode_produces_exactly_16_bytes() {
        let mut buf = [0u8; HEADER_LEN];
        let n = sample().encode(&mut buf).unwrap();
        assert_eq!(n, HEADER_LEN);
    }

    #[test]
    fn layout_matches_big_endian_spec() {
        let mut buf = [0u8; HEADER_LEN];
        sample().encode(&mut buf).unwrap();
        // byte 0: version (0x10) | type (Data=0) = 0x10
        assert_eq!(buf[0], 0x10);
        // byte 1: ACK (0x02) | PRIORITY (0x10) = 0x12
        assert_eq!(buf[1], 0x12);
        // session_id big-endian 0xBEEF
        assert_eq!(&buf[2..4], &[0xBE, 0xEF]);
        // sequence big-endian 0x12345678
        assert_eq!(&buf[4..8], &[0x12, 0x34, 0x56, 0x78]);
        // timestamp_us big-endian 0xCAFEBABE
        assert_eq!(&buf[8..12], &[0xCA, 0xFE, 0xBA, 0xBE]);
        // payload_len big-endian 1280 = 0x0500
        assert_eq!(&buf[12..14], &[0x05, 0x00]);
        assert_eq!(buf[14], 7);
        assert_eq!(buf[15], 0);
    }

    #[test]
    fn decode_round_trips_known_sample() {
        let mut buf = [0u8; HEADER_LEN];
        let h = sample();
        h.encode(&mut buf).unwrap();
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut buf = [0u8; HEADER_LEN];
        sample().encode(&mut buf).unwrap();
        buf[0] = 9 << 4; // version 9, type Data
        let err = Header::decode(&buf).unwrap_err();
        assert_eq!(err, WireError::UnsupportedVersion(9));
    }

    #[test]
    fn decode_rejects_unknown_packet_type() {
        let mut buf = [0u8; HEADER_LEN];
        sample().encode(&mut buf).unwrap();
        buf[0] = (WIRE_VERSION << 4) | 0x0f; // valid version, unknown type 15
        let err = Header::decode(&buf).unwrap_err();
        assert!(matches!(err, WireError::UnknownPacketType(15)));
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let short = [0u8; 10];
        let err = Header::decode(&short).unwrap_err();
        assert_eq!(err, WireError::BufferTooShort { need: HEADER_LEN, got: 10 });
    }

    #[test]
    fn encode_rejects_short_buffer() {
        let mut short = [0u8; 8];
        let err = sample().encode(&mut short).unwrap_err();
        assert_eq!(err, WireError::BufferTooShort { need: HEADER_LEN, got: 8 });
    }

    #[test]
    fn reserved_byte_is_preserved_as_zero_on_encode() {
        let mut buf = [0xFFu8; HEADER_LEN];
        sample().encode(&mut buf).unwrap();
        assert_eq!(buf[15], 0);
    }

    #[test]
    fn unknown_flag_bits_round_trip_verbatim() {
        let mut h = sample();
        h.flags = Flags::from_bits(0b1110_1001);
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf).unwrap();
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded.flags.bits(), 0b1110_1001);
    }

    #[test]
    fn packet_type_nibble_roundtrip() {
        for t in [
            PacketType::Data,
            PacketType::Handshake,
            PacketType::Keepalive,
            PacketType::Probe,
            PacketType::Control,
        ] {
            assert_eq!(PacketType::from_nibble(t.as_nibble()).unwrap(), t);
        }
    }

    #[test]
    fn new_constructor_defaults() {
        let h = Header::new(PacketType::Handshake, SessionId(1));
        assert_eq!(h.version, WIRE_VERSION);
        assert_eq!(h.packet_type, PacketType::Handshake);
        assert_eq!(h.flags, Flags::EMPTY);
        assert_eq!(h.sequence, Seq(0));
    }
}
