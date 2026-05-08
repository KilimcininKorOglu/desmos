//! Anti-amplification handshake cookie.
//!
//! Noise IK msg1 is ~48 bytes; msg2 is ~96 bytes. Without a
//! return-routability check, an attacker who spoofs a victim's
//! source IP can aim msg2 floods at that victim — a 2x
//! amplification vector. The cookie breaks that: on the first
//! msg1 from an unseen source, the server replies with a tiny
//! `CookieReply` packet (type 5) carrying an HMAC over the
//! observed source address. The client echoes the cookie in its
//! next msg1. Only after a valid echo does the server spend
//! msg2-worth of work and bandwidth.
//!
//! # Shape
//!
//! - [`CookieKey`] is a 32-byte HMAC secret. The daemon holds
//!   the current key plus one "previous" key so a just-rotated
//!   session can still validate in-flight echoes. Both are
//!   regenerated from `ring::rand::SystemRandom`.
//! - [`compute_cookie`] derives a 16-byte cookie via
//!   `HMAC-SHA256(key, v4_ip || port || "\x04")` or
//!   `(key, v6_ip || port || "\x06")` and truncates to the
//!   first 16 bytes. Truncating HMAC output is RFC 2104 §5
//!   approved as long as the output is at least `L/2` bytes —
//!   16 of 32 is exactly that boundary.
//! - [`verify_cookie`] walks the current + previous keys,
//!   recomputes each cookie, and compares the candidate in
//!   constant time. Returns `true` if any key matches.
//!
//! # What this module is NOT
//!
//! This module does not know about sockets, session state, or
//! wire framing. The `ClientRegistry` wraps it: on an
//! unseen source it sends a `CookieReply`, then admits the
//! subsequent msg1 only after `verify_cookie` succeeds.

use core::fmt;
use std::net::{IpAddr, SocketAddr};

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

use crate::crypto::hkdf;

/// Byte length of the 32-byte HMAC secret.
pub const COOKIE_KEY_LEN: usize = 32;

/// Byte length of the on-wire cookie.
pub const COOKIE_LEN: usize = 16;

/// Keyed HMAC secret used to mint anti-amplification cookies.
/// Callers regenerate periodically (typical: every 120 s) and
/// keep the previous value around for a full rotation period
/// so echoes mid-rotation still validate.
#[derive(Clone)]
pub struct CookieKey(pub(crate) [u8; COOKIE_KEY_LEN]);

impl CookieKey {
    /// Draw a fresh key from `SystemRandom`. Returns
    /// `Err(CookieError::Rng)` if the system RNG refuses to
    /// produce bytes (a catastrophic condition — daemons
    /// should surface and exit).
    pub fn generate() -> Result<Self, CookieError> {
        let mut buf = [0u8; COOKIE_KEY_LEN];
        SystemRandom::new().fill(&mut buf).map_err(|_| CookieError::Rng)?;
        Ok(Self(buf))
    }

    /// Construct from a caller-supplied byte string. Mostly
    /// useful for deterministic tests.
    pub fn from_bytes(bytes: [u8; COOKIE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Returned as `&[u8]` rather than
    /// `[u8; 32]` so the key cannot accidentally leak through a
    /// `Copy` and the caller is forced to hash it instead of
    /// reusing the reference.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieKey")
            .field("len", &self.0.len())
            .field("prefix", &format_args!("{:02x}{:02x}..", self.0[0], self.0[1]))
            .finish()
    }
}

/// Failures returned by [`CookieKey::generate`]. Kept narrow —
/// the cookie path cannot fail for any other reason at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    Rng,
}

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => f.write_str("cookie: system RNG refused"),
        }
    }
}

impl std::error::Error for CookieError {}

/// Compute a 16-byte cookie binding `src` to `key`. Callers
/// transmit this as-is in the `CookieReply` packet; the client
/// echoes it back in its next msg1 and the server runs
/// [`verify_cookie`].
pub fn compute_cookie(key: &CookieKey, src: SocketAddr) -> [u8; COOKIE_LEN] {
    let mac = hmac_over_source(key, src);
    let mut out = [0u8; COOKIE_LEN];
    out.copy_from_slice(&mac[..COOKIE_LEN]);
    out
}

/// Verify that `candidate` was minted for `src` by any of the
/// supplied keys. Walks every key without short-circuiting so
/// the check is constant-time in the key count.
pub fn verify_cookie(keys: &[CookieKey], src: SocketAddr, candidate: &[u8]) -> bool {
    if candidate.len() != COOKIE_LEN {
        return false;
    }
    let mut matched = false;
    for key in keys {
        let expected = compute_cookie(key, src);
        // constant-time eq over the 16-byte prefix.
        let mut diff: u8 = 0;
        for i in 0..COOKIE_LEN {
            diff |= expected[i] ^ candidate[i];
        }
        matched |= diff == 0;
    }
    matched
}

/// Serialise `(ip, port, family_tag)` into a deterministic byte
/// string suitable for `hkdf::extract(key, ikm)` — which is
/// literally `HMAC-SHA256(key, ikm)` per RFC 5869 §2.2. The
/// family tag disambiguates `::ffff:1.2.3.4` from `1.2.3.4` so
/// an attacker cannot re-use an IPv4 cookie on the same address
/// mapped into IPv6 or vice versa.
fn hmac_over_source(key: &CookieKey, src: SocketAddr) -> [u8; 32] {
    let mut ikm = [0u8; 16 + 2 + 1];
    let used = match src.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            ikm[0..4].copy_from_slice(&octets);
            let port = src.port().to_be_bytes();
            ikm[4..6].copy_from_slice(&port);
            ikm[6] = 0x04;
            7
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            ikm[0..16].copy_from_slice(&octets);
            let port = src.port().to_be_bytes();
            ikm[16..18].copy_from_slice(&port);
            ikm[18] = 0x06;
            19
        }
    };
    hkdf::extract(key.as_bytes(), &ikm[..used])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn addr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn round_trip_v4() {
        let key = CookieKey::from_bytes([0x11u8; COOKIE_KEY_LEN]);
        let src = addr_v4(203, 0, 113, 7, 51820);
        let c = compute_cookie(&key, src);
        assert!(verify_cookie(&[key.clone()], src, &c));
    }

    #[test]
    fn round_trip_v6() {
        let key = CookieKey::from_bytes([0x22u8; COOKIE_KEY_LEN]);
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12345);
        let c = compute_cookie(&key, src);
        assert!(verify_cookie(&[key], src, &c));
    }

    #[test]
    fn rejects_wrong_source() {
        let key = CookieKey::from_bytes([0x33u8; COOKIE_KEY_LEN]);
        let src_a = addr_v4(198, 51, 100, 1, 443);
        let src_b = addr_v4(198, 51, 100, 2, 443);
        let c = compute_cookie(&key, src_a);
        assert!(!verify_cookie(&[key], src_b, &c));
    }

    #[test]
    fn rejects_wrong_port() {
        let key = CookieKey::from_bytes([0x44u8; COOKIE_KEY_LEN]);
        let src_a = addr_v4(192, 0, 2, 1, 1000);
        let src_b = addr_v4(192, 0, 2, 1, 1001);
        let c = compute_cookie(&key, src_a);
        assert!(!verify_cookie(&[key], src_b, &c));
    }

    #[test]
    fn ipv4_mapped_v6_does_not_collide_with_raw_v4() {
        let key = CookieKey::from_bytes([0x55u8; COOKIE_KEY_LEN]);
        let raw = addr_v4(10, 0, 0, 1, 4242);
        let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()), 4242);
        let c_raw = compute_cookie(&key, raw);
        let c_mapped = compute_cookie(&key, mapped);
        assert_ne!(c_raw, c_mapped);
    }

    #[test]
    fn rotation_grace_period_accepts_previous_key() {
        let previous = CookieKey::from_bytes([0x66u8; COOKIE_KEY_LEN]);
        let current = CookieKey::from_bytes([0x77u8; COOKIE_KEY_LEN]);
        let src = addr_v4(172, 16, 0, 9, 9000);
        // Cookie was minted with the previous key.
        let c = compute_cookie(&previous, src);
        // Server rotated: now verifies against [current, previous].
        assert!(verify_cookie(&[current, previous], src, &c));
    }

    #[test]
    fn unrelated_keys_do_not_accept_the_cookie() {
        let key_a = CookieKey::from_bytes([0x88u8; COOKIE_KEY_LEN]);
        let key_b = CookieKey::from_bytes([0x99u8; COOKIE_KEY_LEN]);
        let src = addr_v4(8, 8, 8, 8, 53);
        let c = compute_cookie(&key_a, src);
        assert!(!verify_cookie(&[key_b], src, &c));
    }

    #[test]
    fn rejects_truncated_cookie() {
        let key = CookieKey::from_bytes([0xAAu8; COOKIE_KEY_LEN]);
        let src = addr_v4(127, 0, 0, 1, 1234);
        let c = compute_cookie(&key, src);
        assert!(!verify_cookie(&[key], src, &c[..COOKIE_LEN - 1]));
    }

    #[test]
    fn rejects_oversized_cookie() {
        let key = CookieKey::from_bytes([0xBBu8; COOKIE_KEY_LEN]);
        let src = addr_v4(127, 0, 0, 1, 1234);
        let c = compute_cookie(&key, src);
        let mut too_long = c.to_vec();
        too_long.push(0xFF);
        assert!(!verify_cookie(&[key], src, &too_long));
    }

    #[test]
    fn generate_draws_distinct_keys() {
        let a = CookieKey::generate().unwrap();
        let b = CookieKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn debug_redacts_key_body() {
        let key = CookieKey::from_bytes([0xCCu8; COOKIE_KEY_LEN]);
        let s = format!("{key:?}");
        assert!(s.contains("prefix"));
        assert!(s.contains("cccc.."));
        assert!(!s.contains("cccccccc")); // not the full dump
    }

    #[test]
    fn display_covers_rng_variant() {
        assert_eq!(CookieError::Rng.to_string(), "cookie: system RNG refused");
    }
}
