//! Errors produced while encoding or decoding DWP wire frames.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Buffer is smaller than the 16-byte header.
    BufferTooShort { need: usize, got: usize },
    /// Version nibble does not match [`crate::wire::WIRE_VERSION`].
    UnsupportedVersion(u8),
    /// Type nibble does not map to a known [`crate::wire::PacketType`].
    UnknownPacketType(u8),
    /// `payload_len` claims more bytes than the buffer contains after the header.
    PayloadTruncated { declared: usize, available: usize },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { need, got } => {
                write!(f, "wire: buffer too short. need {need} bytes, got {got}. check MTU.")
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "wire: unsupported version {v}. peer speaks a newer protocol.")
            }
            Self::UnknownPacketType(t) => {
                write!(f, "wire: unknown packet type {t}. dropping.")
            }
            Self::PayloadTruncated { declared, available } => {
                write!(
                    f,
                    "wire: payload truncated. header says {declared} bytes, {available} available.",
                )
            }
        }
    }
}

impl std::error::Error for WireError {}
