//! HTTP/1.1 response builder.
//!
//! Constructs a raw HTTP response (status line + headers + body)
//! ready to be written to the TCP socket.

use crate::errors::StatusCode;
use std::fmt::Write;

/// An HTTP response ready to be serialized to the wire.
#[derive(Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers as `(name, value)` pairs.
    headers: Vec<(String, String)>,
    /// Response body.
    body: Vec<u8>,
}

impl Response {
    /// Create a new response with the given status code.
    pub fn new(status: StatusCode) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    /// Shorthand for a 200 OK response.
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Shorthand for a 404 Not Found response.
    pub fn not_found() -> Self {
        let mut r = Self::new(StatusCode::NOT_FOUND);
        r.body_text("Not Found");
        r
    }

    /// Shorthand for a 400 Bad Request response.
    pub fn bad_request(msg: &str) -> Self {
        let mut r = Self::new(StatusCode::BAD_REQUEST);
        r.body_text(msg);
        r
    }

    /// Shorthand for a 500 Internal Server Error response.
    pub fn internal_error() -> Self {
        let mut r = Self::new(StatusCode::INTERNAL_SERVER_ERROR);
        r.body_text("Internal Server Error");
        r
    }

    /// Shorthand for a 401 Unauthorized response.
    pub fn unauthorized() -> Self {
        let mut r = Self::new(StatusCode::UNAUTHORIZED);
        r.header("WWW-Authenticate", "Basic realm=\"desmos\"");
        r.body_text("Unauthorized");
        r
    }

    /// Shorthand for a 405 Method Not Allowed response.
    pub fn method_not_allowed() -> Self {
        let mut r = Self::new(StatusCode::METHOD_NOT_ALLOWED);
        r.body_text("Method Not Allowed");
        r
    }

    /// Add a response header.
    pub fn header(&mut self, name: &str, value: &str) -> &mut Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Set a plain text body.
    pub fn body_text(&mut self, text: &str) -> &mut Self {
        self.body = text.as_bytes().to_vec();
        self.set_content_type_if_missing("text/plain; charset=utf-8");
        self
    }

    /// Set a JSON body.
    pub fn body_json(&mut self, json: &str) -> &mut Self {
        self.body = json.as_bytes().to_vec();
        self.set_content_type_if_missing("application/json");
        self
    }

    /// Set a raw body with explicit content type.
    pub fn body_raw(&mut self, content_type: &str, data: Vec<u8>) -> &mut Self {
        self.body = data;
        self.set_content_type_if_missing(content_type);
        self
    }

    /// Serialize the response to bytes for the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = String::with_capacity(256 + self.body.len());

        // Status line.
        let _ = write!(buf, "HTTP/1.1 {}\r\n", self.status);

        // Content-Length (always set for non-empty bodies).
        if !self.body.is_empty() {
            let _ = write!(buf, "Content-Length: {}\r\n", self.body.len());
        }

        // User headers.
        for (name, value) in &self.headers {
            let _ = write!(buf, "{name}: {value}\r\n");
        }

        // End of headers.
        buf.push_str("\r\n");

        let mut bytes = buf.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// The body as a byte slice.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    // ---- Private helpers ----------------------------------------------------

    fn set_content_type_if_missing(&mut self, ct: &str) {
        let has_ct = self.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-type"));
        if !has_ct {
            self.headers.push(("Content-Type".to_owned(), ct.to_owned()));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_response_serializes() {
        let mut r = Response::ok();
        r.body_text("hello");
        let bytes = r.to_bytes();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn not_found_response() {
        let r = Response::not_found();
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        assert_eq!(r.body(), b"Not Found");
    }

    #[test]
    fn json_response() {
        let mut r = Response::ok();
        r.body_json("{\"status\":\"ok\"}");
        let s = String::from_utf8(r.to_bytes()).unwrap();
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.ends_with("{\"status\":\"ok\"}"));
    }

    #[test]
    fn unauthorized_has_www_authenticate() {
        let r = Response::unauthorized();
        let s = String::from_utf8(r.to_bytes()).unwrap();
        assert!(s.contains("WWW-Authenticate: Basic realm=\"desmos\"\r\n"));
        assert!(s.contains("401 Unauthorized"));
    }

    #[test]
    fn custom_header() {
        let mut r = Response::ok();
        r.header("X-Custom", "test-value");
        r.body_text("hi");
        let s = String::from_utf8(r.to_bytes()).unwrap();
        assert!(s.contains("X-Custom: test-value\r\n"));
    }

    #[test]
    fn empty_body_no_content_length() {
        let r = Response::new(StatusCode(204));
        let s = String::from_utf8(r.to_bytes()).unwrap();
        assert!(!s.contains("Content-Length"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn content_type_not_duplicated() {
        let mut r = Response::ok();
        r.header("Content-Type", "text/html");
        r.body_text("hello");
        let s = String::from_utf8(r.to_bytes()).unwrap();
        // Should have only one Content-Type.
        assert_eq!(s.matches("Content-Type").count(), 1);
        assert!(s.contains("Content-Type: text/html\r\n"));
    }

    #[test]
    fn bad_request_response() {
        let r = Response::bad_request("missing host");
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.body(), b"missing host");
    }

    #[test]
    fn method_not_allowed() {
        let r = Response::method_not_allowed();
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn internal_error() {
        let r = Response::internal_error();
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn raw_body() {
        let mut r = Response::ok();
        r.body_raw("application/octet-stream", vec![0xDE, 0xAD]);
        assert_eq!(r.body(), &[0xDE, 0xAD]);
        let bytes = r.to_bytes();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("Content-Type: application/octet-stream"));
    }
}
