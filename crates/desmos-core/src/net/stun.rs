//! Minimal RFC 5389 STUN Binding client.
//!
//! Scope: exactly what the UDP hole-punching path
//! needs to discover its own public `(ip, port)` reflection
//! from a public STUN server. Implements:
//!
//! - `Binding Request` encode
//! - `Binding Success Response` decode, walking attributes for
//!   `XOR-MAPPED-ADDRESS` (preferred, RFC 5389 §15.2) or
//!   `MAPPED-ADDRESS` (fallback, RFC 5389 §15.1)
//! - `Binding Error Response` recognition (surfaced as
//!   [`StunError::ErrorResponse`])
//! - transaction-id generation via a xorshift64 stream seeded
//!   from `SystemTime` + a process-wide atomic counter — this
//!   is NOT a cryptographic nonce, just a per-request unique
//!   value, which is all RFC 5389 §6 actually requires
//! - a [`query_binding`] helper that drives a blocking
//!   `std::net::UdpSocket` with a retry schedule of
//!   500 / 1000 / 2000 ms (3 attempts), total deadline 3.5 s
//!
//! Out of scope: TLS / TCP transports (RFC 5389 §7), `FINGERPRINT`
//! and `MESSAGE-INTEGRITY` attributes (RFC 5389 §15.5 / §15.4),
//! `USERNAME` / `REALM` authentication (STUN long-term credentials),
//! `CHANGE-REQUEST` (RFC 3489 legacy), ICE candidate attributes.
//! Future work can add any of these on top of the primitives
//! without re-touching the parser.
//!
//! # Wire shape (§6)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                     Transaction ID (96 bits)                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;
pub const TRANSACTION_ID_LEN: usize = 12;

pub const MSG_TYPE_BINDING_REQUEST: u16 = 0x0001;
pub const MSG_TYPE_BINDING_SUCCESS: u16 = 0x0101;
pub const MSG_TYPE_BINDING_ERROR: u16 = 0x0111;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_ERROR_CODE: u16 = 0x0009;

pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

/// Errors the STUN parser / client can surface. Kept
/// deliberately narrow — every ill-formed input folds into one
/// of these variants so the caller's retry / fallback logic
/// has a fixed match arm set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    /// Message is shorter than it claims or the attribute walk
    /// ran past the end of the buffer.
    Truncated,
    /// The four magic-cookie bytes did not match `0x2112A442`.
    BadMagic,
    /// Transaction ID did not match the request's.
    TransactionMismatch,
    /// The STUN method was something other than Binding.
    NotBinding,
    /// Server returned a Binding Error Response.
    ErrorResponse,
    /// A `MAPPED-ADDRESS` family byte was neither IPv4 nor IPv6.
    BadFamily,
    /// An attribute body was the wrong length or malformed.
    BadAttribute,
    /// The server answered Binding Success but did not include
    /// any mapped-address attribute.
    NoMappedAddress,
    /// The blocking query timed out after every retry.
    Timeout,
    /// `std::net::UdpSocket` operation failed.
    Io(String),
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("stun: response truncated"),
            Self::BadMagic => f.write_str("stun: magic cookie mismatch"),
            Self::TransactionMismatch => f.write_str("stun: transaction id mismatch"),
            Self::NotBinding => f.write_str("stun: unexpected message method"),
            Self::ErrorResponse => f.write_str("stun: server returned Binding Error"),
            Self::BadFamily => f.write_str("stun: unknown address family"),
            Self::BadAttribute => f.write_str("stun: malformed attribute body"),
            Self::NoMappedAddress => f.write_str("stun: response carried no mapped address"),
            Self::Timeout => f.write_str("stun: every retry timed out"),
            Self::Io(e) => write!(f, "stun: io: {e}"),
        }
    }
}

impl std::error::Error for StunError {}

/// STUN transaction identifier — 96 bits, uniquely linking a
/// response to the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId([u8; TRANSACTION_ID_LEN]);

impl TransactionId {
    /// Produce a fresh transaction id from a xorshift64 stream
    /// seeded by wall-clock nanoseconds and a process-wide
    /// atomic counter. Not cryptographically random — STUN
    /// only needs uniqueness across in-flight requests.
    pub fn generate() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut state = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        if state == 0 {
            state = 0xDEAD_BEEF_1234_5678;
        }
        // Two xorshift64 steps give us 16 bytes; we only need 12.
        let a = next_xorshift64(&mut state);
        let b = next_xorshift64(&mut state);
        let mut out = [0u8; TRANSACTION_ID_LEN];
        out[0..8].copy_from_slice(&a.to_be_bytes());
        out[8..12].copy_from_slice(&b.to_be_bytes()[..4]);
        Self(out)
    }

    pub fn from_bytes(bytes: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; TRANSACTION_ID_LEN] {
        &self.0
    }
}

fn next_xorshift64(state: &mut u64) -> u64 {
    let mut s = *state;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *state = s;
    s
}

/// Build a 20-byte Binding Request header (no attributes).
/// That is all a basic-client Binding query carries over the
/// wire — no `FINGERPRINT`, no `MESSAGE-INTEGRITY`, no
/// `USERNAME`.
pub fn build_binding_request(tx: &TransactionId) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..2].copy_from_slice(&MSG_TYPE_BINDING_REQUEST.to_be_bytes());
    h[2..4].copy_from_slice(&0u16.to_be_bytes()); // length = 0
    h[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    h[8..20].copy_from_slice(tx.as_bytes());
    h
}

/// Parse a Binding Response and extract the reflected
/// `(public_ip, public_port)` socket address. Prefers
/// `XOR-MAPPED-ADDRESS` when present, falls back to the
/// plaintext `MAPPED-ADDRESS` otherwise (some legacy / RFC 3489
/// servers still only send the latter).
pub fn parse_binding_response(
    bytes: &[u8],
    expected: &TransactionId,
) -> Result<SocketAddr, StunError> {
    if bytes.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let magic = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if magic != MAGIC_COOKIE {
        return Err(StunError::BadMagic);
    }
    if &bytes[8..20] != expected.as_bytes() {
        return Err(StunError::TransactionMismatch);
    }
    if HEADER_LEN + body_len > bytes.len() {
        return Err(StunError::Truncated);
    }
    if msg_type == MSG_TYPE_BINDING_ERROR {
        return Err(StunError::ErrorResponse);
    }
    if msg_type != MSG_TYPE_BINDING_SUCCESS {
        return Err(StunError::NotBinding);
    }

    let attrs = &bytes[HEADER_LEN..HEADER_LEN + body_len];
    // `cookie_and_txid` is the 16-byte slice that XOR-MAPPED-ADDRESS
    // for IPv6 XORs against. It lives at bytes[4..20].
    let cookie_and_txid = &bytes[4..20];

    let mut xor_addr: Option<SocketAddr> = None;
    let mut plain_addr: Option<SocketAddr> = None;
    let mut cursor = 0usize;

    while cursor + 4 <= attrs.len() {
        let atype = u16::from_be_bytes([attrs[cursor], attrs[cursor + 1]]);
        let alen = u16::from_be_bytes([attrs[cursor + 2], attrs[cursor + 3]]) as usize;
        let padded = (alen + 3) & !3usize;
        if cursor + 4 + padded > attrs.len() {
            // STUN attributes are 4-byte padded, but the outer
            // body length in the header only counts up to the
            // last real byte. Accept an under-padded trailing
            // attribute by clamping.
            if cursor + 4 + alen > attrs.len() {
                return Err(StunError::Truncated);
            }
        }
        let value_end = (cursor + 4 + alen).min(attrs.len());
        let value = &attrs[cursor + 4..value_end];

        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_addr = Some(decode_xor_mapped_address(value, cookie_and_txid)?);
            }
            ATTR_MAPPED_ADDRESS => {
                plain_addr = Some(decode_mapped_address(value)?);
            }
            _ => {
                // Ignore unknown comprehension-optional
                // attributes (RFC 5389 §15). Comprehension-
                // required unknowns would need us to surface
                // an error, but we never set that bit in our
                // own request.
            }
        }

        cursor += 4 + padded;
    }

    xor_addr.or(plain_addr).ok_or(StunError::NoMappedAddress)
}

fn decode_mapped_address(value: &[u8]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::BadAttribute);
    }
    if value[0] != 0 {
        return Err(StunError::BadAttribute);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        FAMILY_IPV4 => {
            if value.len() != 8 {
                return Err(StunError::BadAttribute);
            }
            let ip = Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FAMILY_IPV6 => {
            if value.len() != 20 {
                return Err(StunError::BadAttribute);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::BadFamily),
    }
}

fn decode_xor_mapped_address(
    value: &[u8],
    cookie_and_txid: &[u8],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::BadAttribute);
    }
    if value[0] != 0 {
        return Err(StunError::BadAttribute);
    }
    let family = value[1];
    let x_port = u16::from_be_bytes([value[2], value[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        FAMILY_IPV4 => {
            if value.len() != 8 {
                return Err(StunError::BadAttribute);
            }
            let x_addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = x_addr ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        FAMILY_IPV6 => {
            if value.len() != 20 {
                return Err(StunError::BadAttribute);
            }
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ cookie_and_txid[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::BadFamily),
    }
}

/// Blocking STUN Binding query over a caller-supplied
/// `std::net::UdpSocket`. Sends the request, waits up to the
/// retry deadline for a matching response, and decodes the
/// reflected public address. Retry schedule (RFC 5389 §7.2.1
/// simplified): 500 ms, 1000 ms, 2000 ms — three attempts,
/// total 3.5 s, after which [`StunError::Timeout`] is returned.
pub fn query_binding(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr, StunError> {
    const TIMEOUTS_MS: [u64; 3] = [500, 1000, 2000];
    let tx = TransactionId::generate();
    let req = build_binding_request(&tx);

    let mut buf = [0u8; 1500];
    for &timeout_ms in &TIMEOUTS_MS {
        socket.send_to(&req, server).map_err(|e| StunError::Io(e.to_string()))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
            .map_err(|e| StunError::Io(e.to_string()))?;

        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                match parse_binding_response(&buf[..n], &tx) {
                    Ok(addr) => return Ok(addr),
                    // A stray packet from a *different* STUN
                    // request shouldn't abort us — try again.
                    Err(StunError::TransactionMismatch) => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(e) => {
                let kind = e.kind();
                if kind == std::io::ErrorKind::WouldBlock || kind == std::io::ErrorKind::TimedOut {
                    continue;
                }
                return Err(StunError::Io(e.to_string()));
            }
        }
    }
    Err(StunError::Timeout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ---- Pure protocol ---------------------------------------------------

    #[test]
    fn build_request_has_correct_header_shape() {
        let tx = TransactionId::from_bytes([0xABu8; TRANSACTION_ID_LEN]);
        let req = build_binding_request(&tx);
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(&req[2..4], &[0x00, 0x00]); // zero-length body
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&req[8..20], &[0xAB; 12]);
    }

    fn mk_response(tx: &TransactionId, attrs: &[u8], msg_type: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + attrs.len());
        out.extend_from_slice(&msg_type.to_be_bytes());
        out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(tx.as_bytes());
        out.extend_from_slice(attrs);
        out
    }

    fn xor_mapped_v4_attr(tx: &TransactionId, addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let _ = tx;
        let x_port = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let x_addr = u32::from(addr) ^ MAGIC_COOKIE;
        let mut value = Vec::with_capacity(8);
        value.push(0x00);
        value.push(FAMILY_IPV4);
        value.extend_from_slice(&x_port.to_be_bytes());
        value.extend_from_slice(&x_addr.to_be_bytes());
        let mut attr = Vec::with_capacity(12);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        attr
    }

    fn mapped_v4_attr(addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut value = Vec::with_capacity(8);
        value.push(0x00);
        value.push(FAMILY_IPV4);
        value.extend_from_slice(&port.to_be_bytes());
        value.extend_from_slice(&addr.octets());
        let mut attr = Vec::with_capacity(12);
        attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        attr
    }

    #[test]
    fn parse_xor_mapped_address_v4() {
        let tx = TransactionId::from_bytes([0x01u8; TRANSACTION_ID_LEN]);
        let attr = xor_mapped_v4_attr(&tx, Ipv4Addr::new(203, 0, 113, 42), 51820);
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
        let addr = parse_binding_response(&resp, &tx).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 51820));
    }

    #[test]
    fn parse_xor_mapped_address_v6() {
        let tx = TransactionId::from_bytes([0xCCu8; TRANSACTION_ID_LEN]);
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
        let port: u16 = 4242;
        // Build the XOR-MAPPED-ADDRESS value.
        let cookie_and_txid = {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            v.extend_from_slice(tx.as_bytes());
            v
        };
        let mut value = Vec::with_capacity(20);
        value.push(0x00);
        value.push(FAMILY_IPV6);
        value.extend_from_slice(&(port ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        let octets = ip.octets();
        for i in 0..16 {
            value.push(octets[i] ^ cookie_and_txid[i]);
        }
        let mut attr = Vec::with_capacity(24);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);

        let addr = parse_binding_response(&resp, &tx).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(ip), port));
    }

    #[test]
    fn plain_mapped_address_used_as_fallback() {
        let tx = TransactionId::from_bytes([0x02u8; TRANSACTION_ID_LEN]);
        let attr = mapped_v4_attr(Ipv4Addr::new(198, 51, 100, 7), 1234);
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
        let addr = parse_binding_response(&resp, &tx).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 1234));
    }

    #[test]
    fn xor_mapped_beats_plain_when_both_present() {
        let tx = TransactionId::from_bytes([0x03u8; TRANSACTION_ID_LEN]);
        let mut attrs = xor_mapped_v4_attr(&tx, Ipv4Addr::new(203, 0, 113, 1), 5555);
        attrs.extend_from_slice(&mapped_v4_attr(Ipv4Addr::new(9, 9, 9, 9), 9999));
        let resp = mk_response(&tx, &attrs, MSG_TYPE_BINDING_SUCCESS);
        let addr = parse_binding_response(&resp, &tx).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert_eq!(addr.port(), 5555);
    }

    #[test]
    fn rejects_short_header() {
        let err =
            parse_binding_response(&[0u8; 10], &TransactionId::from_bytes([0; 12])).unwrap_err();
        assert_eq!(err, StunError::Truncated);
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..2].copy_from_slice(&MSG_TYPE_BINDING_SUCCESS.to_be_bytes());
        // bytes[4..8] stays zero — wrong magic.
        let err = parse_binding_response(&bytes, &TransactionId::from_bytes([0; 12])).unwrap_err();
        assert_eq!(err, StunError::BadMagic);
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let tx = TransactionId::from_bytes([0x11u8; 12]);
        let attr = xor_mapped_v4_attr(&tx, Ipv4Addr::new(1, 2, 3, 4), 1);
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
        let err =
            parse_binding_response(&resp, &TransactionId::from_bytes([0x22u8; 12])).unwrap_err();
        assert_eq!(err, StunError::TransactionMismatch);
    }

    #[test]
    fn rejects_error_response() {
        let tx = TransactionId::from_bytes([0x44u8; 12]);
        // Empty body — just the 20-byte header tagged Binding Error.
        let resp = mk_response(&tx, &[], MSG_TYPE_BINDING_ERROR);
        let err = parse_binding_response(&resp, &tx).unwrap_err();
        assert_eq!(err, StunError::ErrorResponse);
    }

    #[test]
    fn rejects_wrong_method() {
        let tx = TransactionId::from_bytes([0x55u8; 12]);
        // Allocation success (0x0103) — not a Binding method.
        let resp = mk_response(&tx, &[], 0x0103);
        let err = parse_binding_response(&resp, &tx).unwrap_err();
        assert_eq!(err, StunError::NotBinding);
    }

    #[test]
    fn rejects_body_length_overflow() {
        let tx = TransactionId::from_bytes([0x66u8; 12]);
        let mut bytes = mk_response(&tx, &[], MSG_TYPE_BINDING_SUCCESS);
        // Lie about body length — claim 100 bytes when there
        // are none.
        bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
        let err = parse_binding_response(&bytes, &tx).unwrap_err();
        assert_eq!(err, StunError::Truncated);
    }

    #[test]
    fn rejects_reserved_byte_not_zero() {
        let tx = TransactionId::from_bytes([0x77u8; 12]);
        let mut attr = xor_mapped_v4_attr(&tx, Ipv4Addr::new(1, 2, 3, 4), 80);
        // attr layout: type(2) len(2) value[0]=reserved, clobber it.
        attr[4] = 0xFF;
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
        let err = parse_binding_response(&resp, &tx).unwrap_err();
        assert_eq!(err, StunError::BadAttribute);
    }

    #[test]
    fn rejects_unknown_family() {
        let tx = TransactionId::from_bytes([0x88u8; 12]);
        // Build an XOR-MAPPED-ADDRESS with a bogus family byte.
        let mut value = vec![0x00, 0x03]; // family=3
        value.extend_from_slice(&0u16.to_be_bytes());
        value.extend_from_slice(&0u32.to_be_bytes());
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attr.extend_from_slice(&value);
        let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
        let err = parse_binding_response(&resp, &tx).unwrap_err();
        assert_eq!(err, StunError::BadFamily);
    }

    #[test]
    fn rejects_when_no_mapped_address_attribute_present() {
        let tx = TransactionId::from_bytes([0x99u8; 12]);
        // Success response with zero attributes.
        let resp = mk_response(&tx, &[], MSG_TYPE_BINDING_SUCCESS);
        let err = parse_binding_response(&resp, &tx).unwrap_err();
        assert_eq!(err, StunError::NoMappedAddress);
    }

    #[test]
    fn unknown_attribute_is_skipped() {
        let tx = TransactionId::from_bytes([0xA1u8; 12]);
        // Unknown attribute type 0x8022 (SOFTWARE), 5 bytes body "abcde".
        let unknown_body = b"abcde";
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0x8022u16.to_be_bytes());
        unknown.extend_from_slice(&(unknown_body.len() as u16).to_be_bytes());
        unknown.extend_from_slice(unknown_body);
        // Pad to 4-byte boundary.
        unknown.extend_from_slice(&[0, 0, 0]);
        // Then the XOR-MAPPED-ADDRESS that should actually be decoded.
        unknown.extend_from_slice(&xor_mapped_v4_attr(&tx, Ipv4Addr::new(172, 16, 99, 99), 4242));
        let resp = mk_response(&tx, &unknown, MSG_TYPE_BINDING_SUCCESS);
        let addr = parse_binding_response(&resp, &tx).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(172, 16, 99, 99)));
        assert_eq!(addr.port(), 4242);
    }

    #[test]
    fn transaction_ids_are_distinct_across_calls() {
        let a = TransactionId::generate();
        let b = TransactionId::generate();
        assert_ne!(a, b);
    }

    // ---- Blocking query over loopback ------------------------------------

    #[test]
    fn query_binding_against_loopback_fake_server() {
        // Spin up a fake STUN server on an ephemeral loopback
        // port, send a single response, and assert the client
        // decodes it.
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server_sock.recv_from(&mut buf).unwrap();
            // Parse the request to pull out the transaction id.
            assert_eq!(n, HEADER_LEN);
            let mut tx_bytes = [0u8; TRANSACTION_ID_LEN];
            tx_bytes.copy_from_slice(&buf[8..20]);
            let tx = TransactionId::from_bytes(tx_bytes);
            let attr = xor_mapped_v4_attr(&tx, Ipv4Addr::new(203, 0, 113, 9), 33333);
            let resp = mk_response(&tx, &attr, MSG_TYPE_BINDING_SUCCESS);
            server_sock.send_to(&resp, from).unwrap();
        });

        let mapped = query_binding(&client_sock, server_addr).unwrap();
        assert_eq!(mapped, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 33333));
        handle.join().unwrap();
    }

    #[test]
    fn query_binding_times_out_when_no_server() {
        // Connect to an address with no listener. We bind
        // the server socket, then drop it immediately so the
        // port becomes a black hole within the same process.
        let dead = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Hack the retry schedule by shortening the first
        // timeout via set_read_timeout — actually query_binding
        // overwrites it. We'll have to wait the full 3.5 s.
        // Keep the test off the default run set by gating on
        // the SLOW env var.
        if std::env::var_os("DESMOS_STUN_SLOW_TEST").is_none() {
            return;
        }
        let err = query_binding(&client, dead).unwrap_err();
        assert_eq!(err, StunError::Timeout);
    }

    #[test]
    fn display_covers_every_variant() {
        assert_eq!(StunError::Truncated.to_string(), "stun: response truncated");
        assert_eq!(StunError::BadMagic.to_string(), "stun: magic cookie mismatch");
        assert_eq!(StunError::TransactionMismatch.to_string(), "stun: transaction id mismatch");
        assert_eq!(StunError::NotBinding.to_string(), "stun: unexpected message method");
        assert_eq!(StunError::ErrorResponse.to_string(), "stun: server returned Binding Error");
        assert_eq!(StunError::BadFamily.to_string(), "stun: unknown address family");
        assert_eq!(StunError::BadAttribute.to_string(), "stun: malformed attribute body");
        assert_eq!(
            StunError::NoMappedAddress.to_string(),
            "stun: response carried no mapped address"
        );
        assert_eq!(StunError::Timeout.to_string(), "stun: every retry timed out");
        assert_eq!(StunError::Io("boom".into()).to_string(), "stun: io: boom");
    }
}
