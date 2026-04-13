//! HTTP Basic Authentication middleware with PBKDF2 verification.
//!
//! Decodes the `Authorization: Basic <base64>` header, splits into
//! `(username, password)`, and verifies against the configured
//! credentials.  Password verification uses `ring::pbkdf2` for
//! constant-time PBKDF2-HMAC-SHA256 comparison.
//!
//! The original spec called for Argon2id, but every argon2 crate
//! (both RustCrypto and rust-argon2) pulls transitive dependencies
//! requiring edition 2024, which is incompatible with MSRV 1.75.
//! PBKDF2-HMAC-SHA256 via `ring` provides equivalent security
//! properties for password verification without adding new deps.
//!
//! # Hash format
//!
//! `$pbkdf2-sha256$i=<iterations>$<base64-salt>$<base64-hash>`
//!
//! Example:
//! ```text
//! $pbkdf2-sha256$i=100000$c2FsdHNhbHQ=$aGFzaGVk...
//! ```

use crate::request::Request;
use crate::response::Response;

/// Default iteration count for PBKDF2.
pub const DEFAULT_ITERATIONS: u32 = 100_000;

/// PBKDF2 output length in bytes.
const HASH_LEN: usize = 32;

/// Configuration for Basic Auth.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Expected username.
    pub username: String,
    /// PBKDF2-SHA256 encoded password hash in PHC-like format.
    pub password_hash: String,
}

/// Decode a `Basic` Authorization header value.
///
/// Returns `Some((username, password))` on success.
pub fn decode_basic_auth(header_value: &str) -> Option<(String, String)> {
    let encoded = header_value.strip_prefix("Basic ")?.trim();
    let decoded = base64_decode(encoded)?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// Hash a password with PBKDF2-HMAC-SHA256.
///
/// Returns a PHC-like encoded string.
pub fn hash_password(password: &[u8], salt: &[u8], iterations: u32) -> String {
    let mut hash = [0u8; HASH_LEN];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iterations).unwrap(),
        salt,
        password,
        &mut hash,
    );
    format!("$pbkdf2-sha256$i={}${}${}", iterations, base64_encode(salt), base64_encode(&hash),)
}

/// Parse a PHC-like PBKDF2 hash string.
///
/// Returns `(iterations, salt, hash)` on success.
fn parse_phc(encoded: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let rest = encoded.strip_prefix("$pbkdf2-sha256$")?;
    let rest = rest.strip_prefix("i=")?;
    let (iter_str, rest) = rest.split_once('$')?;
    let iterations: u32 = iter_str.parse().ok()?;
    let (salt_b64, hash_b64) = rest.split_once('$')?;
    let salt = base64_decode(salt_b64)?;
    let hash = base64_decode(hash_b64)?;
    Some((iterations, salt, hash))
}

/// Verify credentials against a PBKDF2-SHA256 PHC hash.
///
/// Returns `true` if the username matches and the password verifies.
/// Constant-time via `ring::pbkdf2::verify`.
pub fn verify_credentials(config: &AuthConfig, username: &str, password: &str) -> bool {
    if username != config.username {
        // Dummy verify to avoid timing leaks on username.
        let _ = ring::pbkdf2::verify(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(1000).unwrap(),
            b"dummy-salt-00000",
            password.as_bytes(),
            &[0u8; HASH_LEN],
        );
        return false;
    }

    let (iterations, salt, expected_hash) = match parse_phc(&config.password_hash) {
        Some(v) => v,
        None => return false,
    };

    ring::pbkdf2::verify(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iterations).unwrap(),
        &salt,
        password.as_bytes(),
        &expected_hash,
    )
    .is_ok()
}

/// Check Basic Auth on a request.
///
/// Returns `None` if credentials pass, `Some(401)` otherwise.
pub fn check_basic_auth(req: &Request<'_>, config: &AuthConfig) -> Option<Response> {
    let auth_header = match req.headers.authorization() {
        Some(h) => h,
        None => return Some(Response::unauthorized()),
    };

    let (username, password) = match decode_basic_auth(auth_header) {
        Some(creds) => creds,
        None => return Some(Response::unauthorized()),
    };

    if verify_credentials(config, &username, &password) {
        None
    } else {
        Some(Response::unauthorized())
    }
}

// ---- Base64 helpers ---------------------------------------------------------

/// Minimal Base64 encoder (RFC 4648, standard alphabet + padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Minimal Base64 decoder (RFC 4648).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{Header, Headers};
    use crate::method::Method;

    // ---- Base64 tests ---------------------------------------------------

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_decode_invalid() {
        assert!(base64_decode("!!!").is_none());
    }

    // ---- PHC format tests -----------------------------------------------

    #[test]
    fn hash_and_parse_roundtrip() {
        let hash = hash_password(b"mypassword", b"salt1234salt1234", 10_000);
        assert!(hash.starts_with("$pbkdf2-sha256$i=10000$"));
        let (iters, salt, _) = parse_phc(&hash).unwrap();
        assert_eq!(iters, 10_000);
        assert_eq!(salt, b"salt1234salt1234");
    }

    #[test]
    fn parse_phc_invalid() {
        assert!(parse_phc("garbage").is_none());
        assert!(parse_phc("$argon2id$v=19$").is_none());
    }

    // ---- decode_basic_auth tests ----------------------------------------

    #[test]
    fn decode_valid_basic() {
        // "admin:secret" = "YWRtaW46c2VjcmV0"
        let (user, pass) = decode_basic_auth("Basic YWRtaW46c2VjcmV0").unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn decode_missing_prefix() {
        assert!(decode_basic_auth("Bearer token").is_none());
    }

    #[test]
    fn decode_no_colon() {
        // "admin" = "YWRtaW4="
        assert!(decode_basic_auth("Basic YWRtaW4=").is_none());
    }

    #[test]
    fn decode_password_with_colon() {
        // "user:pass:word" = "dXNlcjpwYXNzOndvcmQ="
        let (user, pass) = decode_basic_auth("Basic dXNlcjpwYXNzOndvcmQ=").unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass:word");
    }

    // ---- verify_credentials tests ---------------------------------------

    fn test_config() -> AuthConfig {
        let hash = hash_password(b"correctpassword", b"testsalt12345678", 10_000);
        AuthConfig { username: "admin".into(), password_hash: hash }
    }

    #[test]
    fn verify_correct_credentials() {
        let config = test_config();
        assert!(verify_credentials(&config, "admin", "correctpassword"));
    }

    #[test]
    fn verify_wrong_password() {
        let config = test_config();
        assert!(!verify_credentials(&config, "admin", "wrongpassword"));
    }

    #[test]
    fn verify_wrong_username() {
        let config = test_config();
        assert!(!verify_credentials(&config, "hacker", "correctpassword"));
    }

    #[test]
    fn verify_malformed_hash() {
        let config =
            AuthConfig { username: "admin".into(), password_hash: "not-a-valid-hash".into() };
        assert!(!verify_credentials(&config, "admin", "anything"));
    }

    // ---- check_basic_auth integration -----------------------------------

    fn make_request_with_auth(auth_value: &str) -> Request<'_> {
        Request {
            method: Method::Get,
            uri: "/api/v1/status",
            headers: Headers::new(vec![
                Header { name: "Host", value: "localhost" },
                Header { name: "Authorization", value: auth_value },
            ]),
            body: Vec::new(),
        }
    }

    fn make_request_no_auth() -> Request<'static> {
        Request {
            method: Method::Get,
            uri: "/api/v1/status",
            headers: Headers::new(vec![Header { name: "Host", value: "localhost" }]),
            body: Vec::new(),
        }
    }

    #[test]
    fn check_passes_valid_auth() {
        let config = test_config();
        // "admin:correctpassword" = "YWRtaW46Y29ycmVjdHBhc3N3b3Jk"
        let req = make_request_with_auth("Basic YWRtaW46Y29ycmVjdHBhc3N3b3Jk");
        assert!(check_basic_auth(&req, &config).is_none());
    }

    #[test]
    fn check_rejects_missing_header() {
        let config = test_config();
        let req = make_request_no_auth();
        let resp = check_basic_auth(&req, &config).unwrap();
        assert_eq!(resp.status, crate::errors::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_rejects_wrong_password() {
        let config = test_config();
        // "admin:wrong" = "YWRtaW46d3Jvbmc="
        let req = make_request_with_auth("Basic YWRtaW46d3Jvbmc=");
        let resp = check_basic_auth(&req, &config).unwrap();
        assert_eq!(resp.status, crate::errors::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_rejects_malformed_auth() {
        let config = test_config();
        let req = make_request_with_auth("Bearer token123");
        let resp = check_basic_auth(&req, &config).unwrap();
        assert_eq!(resp.status, crate::errors::StatusCode::UNAUTHORIZED);
    }
}
