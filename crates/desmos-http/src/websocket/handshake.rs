//! WebSocket upgrade handshake (RFC 6455 §4.2).
//!
//! Validates the client's `Upgrade: websocket` request and produces
//! the `101 Switching Protocols` response with the correct
//! `Sec-WebSocket-Accept` hash.
//!
//! The accept key is `BASE64(SHA-1(client_key + MAGIC_GUID))`.
//! We use `ring::digest::digest(SHA1_FOR_LEGACY_USE_ONLY, ...)` for
//! the SHA-1 hash — this is the one legitimate use of SHA-1 in the
//! project (mandated by RFC 6455).

use crate::errors::StatusCode;
use crate::request::Request;
use crate::response::Response;

/// The RFC 6455 magic GUID appended to the client key.
const WS_MAGIC: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Validate the upgrade request and return a 101 response.
///
/// Returns `None` if the request is not a valid WebSocket upgrade.
pub fn try_upgrade(req: &Request<'_>) -> Option<Response> {
    // Must be GET.
    if req.method != crate::method::Method::Get {
        return None;
    }

    // Must have Upgrade: websocket + Connection: Upgrade.
    if !req.headers.is_websocket_upgrade() {
        return None;
    }

    // Must have Sec-WebSocket-Key.
    let key = req.headers.websocket_key()?;

    // Must have Sec-WebSocket-Version: 13.
    let version = req.headers.get("sec-websocket-version")?;
    if version.trim() != "13" {
        return None;
    }

    let accept = compute_accept_key(key);

    let mut resp = Response::new(StatusCode(101));
    resp.header("Upgrade", "websocket");
    resp.header("Connection", "Upgrade");
    resp.header("Sec-WebSocket-Accept", &accept);

    Some(resp)
}

/// Compute the `Sec-WebSocket-Accept` value.
///
/// `accept = BASE64(SHA-1(client_key || MAGIC_GUID))`
fn compute_accept_key(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_MAGIC.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_MAGIC);

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64_encode(digest.as_ref())
}

/// Minimal Base64 encoder (RFC 4648, no padding omission).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{Header, Headers};
    use crate::method::Method;

    fn ws_request(key: &str) -> Request<'_> {
        Request {
            method: Method::Get,
            uri: "/ws",
            headers: Headers::new(vec![
                Header { name: "Upgrade", value: "websocket" },
                Header { name: "Connection", value: "Upgrade" },
                Header { name: "Sec-WebSocket-Key", value: key },
                Header { name: "Sec-WebSocket-Version", value: "13" },
            ]),
            body: Vec::new(),
        }
    }

    #[test]
    fn accept_key_rfc_vector() {
        // RFC 6455 §4.2.2 example.
        let accept = compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn valid_upgrade_returns_101() {
        let req = ws_request("dGhlIHNhbXBsZSBub25jZQ==");
        let resp = try_upgrade(&req).unwrap();
        assert_eq!(resp.status, StatusCode(101));
    }

    #[test]
    fn missing_key_returns_none() {
        let req = Request {
            method: Method::Get,
            uri: "/ws",
            headers: Headers::new(vec![
                Header { name: "Upgrade", value: "websocket" },
                Header { name: "Connection", value: "Upgrade" },
                Header { name: "Sec-WebSocket-Version", value: "13" },
            ]),
            body: Vec::new(),
        };
        assert!(try_upgrade(&req).is_none());
    }

    #[test]
    fn wrong_version_returns_none() {
        let req = Request {
            method: Method::Get,
            uri: "/ws",
            headers: Headers::new(vec![
                Header { name: "Upgrade", value: "websocket" },
                Header { name: "Connection", value: "Upgrade" },
                Header { name: "Sec-WebSocket-Key", value: "dGhlIHNhbXBsZSBub25jZQ==" },
                Header { name: "Sec-WebSocket-Version", value: "8" },
            ]),
            body: Vec::new(),
        };
        assert!(try_upgrade(&req).is_none());
    }

    #[test]
    fn post_method_returns_none() {
        let req = Request {
            method: Method::Post,
            uri: "/ws",
            headers: Headers::new(vec![
                Header { name: "Upgrade", value: "websocket" },
                Header { name: "Connection", value: "Upgrade" },
                Header { name: "Sec-WebSocket-Key", value: "dGhlIHNhbXBsZSBub25jZQ==" },
                Header { name: "Sec-WebSocket-Version", value: "13" },
            ]),
            body: Vec::new(),
        };
        assert!(try_upgrade(&req).is_none());
    }

    #[test]
    fn no_upgrade_header_returns_none() {
        let req = Request {
            method: Method::Get,
            uri: "/ws",
            headers: Headers::new(vec![
                Header { name: "Sec-WebSocket-Key", value: "dGhlIHNhbXBsZSBub25jZQ==" },
                Header { name: "Sec-WebSocket-Version", value: "13" },
            ]),
            body: Vec::new(),
        };
        assert!(try_upgrade(&req).is_none());
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_padding() {
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }
}
