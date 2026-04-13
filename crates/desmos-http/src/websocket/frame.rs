//! WebSocket frame codec (RFC 6455 §5).
//!
//! Encodes and decodes WebSocket frames.  Server-to-client frames
//! are never masked.  Client-to-server frames must be masked per
//! the RFC; the decoder handles unmasking.
//!
//! Supports: Text (0x1), Binary (0x2), Close (0x8), Ping (0x9),
//! Pong (0xA).  Continuation frames (0x0) are not supported —
//! the Desmos API uses only small JSON messages.

use std::io;

// ---- Opcodes ----------------------------------------------------------------

/// WebSocket frame opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    /// Parse from the 4-bit opcode field.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x0F {
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// Encode to the 4-bit opcode value.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control frame.
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

// ---- Frame ------------------------------------------------------------------

/// A decoded WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Whether this is the final fragment.
    pub fin: bool,
    /// Frame opcode.
    pub opcode: Opcode,
    /// Payload data (unmasked).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a text frame.
    pub fn text(data: &str) -> Self {
        Self { fin: true, opcode: Opcode::Text, payload: data.as_bytes().to_vec() }
    }

    /// Create a binary frame.
    pub fn binary(data: Vec<u8>) -> Self {
        Self { fin: true, opcode: Opcode::Binary, payload: data }
    }

    /// Create a close frame with an optional status code.
    pub fn close(code: Option<u16>) -> Self {
        let payload = match code {
            Some(c) => c.to_be_bytes().to_vec(),
            None => Vec::new(),
        };
        Self { fin: true, opcode: Opcode::Close, payload }
    }

    /// Create a ping frame.
    pub fn ping(data: &[u8]) -> Self {
        Self { fin: true, opcode: Opcode::Ping, payload: data.to_vec() }
    }

    /// Create a pong frame (echo the ping payload).
    pub fn pong(data: &[u8]) -> Self {
        Self { fin: true, opcode: Opcode::Pong, payload: data.to_vec() }
    }

    /// Get the payload as a UTF-8 string (for text frames).
    pub fn as_text(&self) -> Option<&str> {
        if self.opcode == Opcode::Text {
            std::str::from_utf8(&self.payload).ok()
        } else {
            None
        }
    }

    /// Get the close code, if present.
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode == Opcode::Close && self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }
}

// ---- Encoder ----------------------------------------------------------------

/// Encode a frame to bytes (server-to-client: unmasked).
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + frame.payload.len());

    // Byte 0: FIN + opcode.
    let b0 = if frame.fin { 0x80 } else { 0x00 } | frame.opcode.to_byte();
    buf.push(b0);

    // Byte 1+: payload length (no mask bit for server frames).
    let len = frame.payload.len();
    if len < 126 {
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(126);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(127);
        buf.extend_from_slice(&(len as u64).to_be_bytes());
    }

    buf.extend_from_slice(&frame.payload);
    buf
}

// ---- Decoder ----------------------------------------------------------------

/// Maximum frame payload size: 1 MiB.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// Decode a frame from a byte buffer.
///
/// Returns the frame and the number of bytes consumed, or `None`
/// if the buffer doesn't contain a complete frame yet.
pub fn decode_frame(buf: &[u8]) -> io::Result<Option<(Frame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let b0 = buf[0];
    let b1 = buf[1];

    let fin = b0 & 0x80 != 0;
    let opcode = Opcode::from_byte(b0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown WebSocket opcode"))?;

    let masked = b1 & 0x80 != 0;
    let len_byte = b1 & 0x7F;

    let (payload_len, header_size) = match len_byte {
        0..=125 => (len_byte as usize, 2),
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            (len, 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let len = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]) as usize;
            (len, 10)
        }
        _ => unreachable!(),
    };

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame payload too large"));
    }

    let mask_size = if masked { 4 } else { 0 };
    let total = header_size + mask_size + payload_len;

    if buf.len() < total {
        return Ok(None); // Need more data.
    }

    let mut payload = buf[header_size + mask_size..total].to_vec();

    // Unmask if client frame.
    if masked {
        let mask_key = &buf[header_size..header_size + 4];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[i % 4];
        }
    }

    Ok(Some((Frame { fin, opcode, payload }, total)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_roundtrip() {
        for op in [Opcode::Text, Opcode::Binary, Opcode::Close, Opcode::Ping, Opcode::Pong] {
            assert_eq!(Opcode::from_byte(op.to_byte()), Some(op));
        }
    }

    #[test]
    fn opcode_unknown() {
        assert_eq!(Opcode::from_byte(0x03), None);
        assert_eq!(Opcode::from_byte(0x0B), None);
    }

    #[test]
    fn opcode_is_control() {
        assert!(!Opcode::Text.is_control());
        assert!(!Opcode::Binary.is_control());
        assert!(Opcode::Close.is_control());
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Pong.is_control());
    }

    #[test]
    fn encode_short_text() {
        let f = Frame::text("hello");
        let bytes = encode_frame(&f);
        assert_eq!(bytes[0], 0x81); // FIN + Text
        assert_eq!(bytes[1], 5); // length
        assert_eq!(&bytes[2..], b"hello");
    }

    #[test]
    fn encode_medium_payload() {
        let data = vec![0xAB; 300];
        let f = Frame::binary(data.clone());
        let bytes = encode_frame(&f);
        assert_eq!(bytes[0], 0x82); // FIN + Binary
        assert_eq!(bytes[1], 126); // extended 16-bit length
        let len = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(len, 300);
        assert_eq!(&bytes[4..], &data[..]);
    }

    #[test]
    fn encode_close_with_code() {
        let f = Frame::close(Some(1000));
        let bytes = encode_frame(&f);
        assert_eq!(bytes[0], 0x88); // FIN + Close
        assert_eq!(bytes[1], 2); // 2-byte payload (status code)
        assert_eq!(&bytes[2..4], &1000u16.to_be_bytes());
    }

    #[test]
    fn encode_ping() {
        let f = Frame::ping(b"ping");
        let bytes = encode_frame(&f);
        assert_eq!(bytes[0], 0x89); // FIN + Ping
        assert_eq!(&bytes[2..], b"ping");
    }

    #[test]
    fn decode_unmasked_text() {
        let f = Frame::text("hi");
        let bytes = encode_frame(&f);
        let (decoded, consumed) = decode_frame(&bytes).unwrap().unwrap();
        assert!(decoded.fin);
        assert_eq!(decoded.opcode, Opcode::Text);
        assert_eq!(decoded.as_text(), Some("hi"));
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn decode_masked_frame() {
        // Build a masked client frame manually.
        let payload = b"Hello";
        let mask_key: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

        let mut buf = vec![0x81u8]; // FIN + Text
        buf.push(0x80 | payload.len() as u8); // MASK bit + length
        buf.extend_from_slice(&mask_key);
        for (i, &b) in payload.iter().enumerate() {
            buf.push(b ^ mask_key[i % 4]);
        }

        let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(decoded.opcode, Opcode::Text);
        assert_eq!(decoded.as_text(), Some("Hello"));
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn decode_incomplete_returns_none() {
        assert!(decode_frame(&[0x81]).unwrap().is_none());
        assert!(decode_frame(&[]).unwrap().is_none());
    }

    #[test]
    fn decode_medium_length() {
        let data = vec![0x42; 300];
        let f = Frame::binary(data);
        let bytes = encode_frame(&f);
        let (decoded, _) = decode_frame(&bytes).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 300);
    }

    #[test]
    fn frame_close_code() {
        let f = Frame::close(Some(1001));
        assert_eq!(f.close_code(), Some(1001));

        let f2 = Frame::close(None);
        assert_eq!(f2.close_code(), None);
    }

    #[test]
    fn frame_pong() {
        let f = Frame::pong(b"pong-data");
        assert_eq!(f.opcode, Opcode::Pong);
        assert_eq!(f.payload, b"pong-data");
    }

    #[test]
    fn roundtrip_all_opcodes() {
        let frames = vec![
            Frame::text("test"),
            Frame::binary(vec![1, 2, 3]),
            Frame::close(Some(1000)),
            Frame::ping(b"p"),
            Frame::pong(b"p"),
        ];

        for original in &frames {
            let bytes = encode_frame(original);
            let (decoded, consumed) = decode_frame(&bytes).unwrap().unwrap();
            assert_eq!(decoded.opcode, original.opcode);
            assert_eq!(decoded.payload, original.payload);
            assert_eq!(decoded.fin, original.fin);
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn text_frame_as_text() {
        let f = Frame::text("hello");
        assert_eq!(f.as_text(), Some("hello"));

        let f2 = Frame::binary(vec![0xFF]);
        assert_eq!(f2.as_text(), None);
    }

    #[test]
    fn reject_oversized_payload() {
        let mut buf = vec![0x82, 127]; // Binary + 64-bit length
        buf.extend_from_slice(&((MAX_FRAME_PAYLOAD as u64 + 1).to_be_bytes()));
        let err = decode_frame(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
