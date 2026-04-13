//! HTTP header parsing and typed wrappers.
//!
//! Headers are stored as `(name, value)` slices borrowed from the
//! read buffer.  Names are compared case-insensitively per RFC 7230.

use std::fmt;

/// Maximum number of headers per request.
pub const MAX_HEADERS: usize = 64;

/// Maximum length of a single header line (name: value).
pub const MAX_HEADER_LINE: usize = 8192;

/// A single HTTP header: `(name, value)`.
///
/// Both name and value are borrowed from the parse buffer and are
/// valid for the lifetime of the request.
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// A collection of parsed HTTP headers.
#[derive(Debug)]
pub struct Headers<'a> {
    entries: Vec<Header<'a>>,
}

impl<'a> Headers<'a> {
    /// Create from a vec of parsed headers.
    pub fn new(entries: Vec<Header<'a>>) -> Self {
        Self { entries }
    }

    /// Create an empty header set.
    pub fn empty() -> Self {
        Self { entries: Vec::new() }
    }

    /// Look up the first header matching `name` (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
    }

    /// Iterate over all headers.
    pub fn iter(&self) -> impl Iterator<Item = &Header<'a>> {
        self.entries.iter()
    }

    /// Number of headers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the header set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get `Content-Length` as a `usize`, if present and valid.
    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length").and_then(|v| v.trim().parse().ok())
    }

    /// Check if `Transfer-Encoding: chunked` is set.
    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    /// Get `Content-Type` value.
    pub fn content_type(&self) -> Option<&str> {
        self.get("content-type")
    }

    /// Get `Host` value.
    pub fn host(&self) -> Option<&str> {
        self.get("host")
    }

    /// Get `Connection` value.
    pub fn connection(&self) -> Option<&str> {
        self.get("connection")
    }

    /// Check if `Connection: keep-alive` is set.
    pub fn is_keep_alive(&self) -> bool {
        self.connection().map(|v| v.eq_ignore_ascii_case("keep-alive")).unwrap_or(false)
    }

    /// Check if `Connection: close` is set.
    pub fn is_close(&self) -> bool {
        self.connection().map(|v| v.eq_ignore_ascii_case("close")).unwrap_or(false)
    }

    /// Check if this is a WebSocket upgrade request.
    pub fn is_websocket_upgrade(&self) -> bool {
        let upgrade =
            self.get("upgrade").map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false);
        let conn = self
            .get("connection")
            .map(|v| v.split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade")))
            .unwrap_or(false);
        upgrade && conn
    }

    /// Get `Sec-WebSocket-Key` for the upgrade handshake.
    pub fn websocket_key(&self) -> Option<&str> {
        self.get("sec-websocket-key")
    }

    /// Get `Authorization` header value.
    pub fn authorization(&self) -> Option<&str> {
        self.get("authorization")
    }
}

impl<'a> fmt::Display for Headers<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for h in &self.entries {
            writeln!(f, "{}: {}", h.name, h.value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_headers() -> Headers<'static> {
        Headers::new(vec![
            Header { name: "Host", value: "example.com" },
            Header { name: "Content-Length", value: "42" },
            Header { name: "Content-Type", value: "application/json" },
            Header { name: "Connection", value: "keep-alive" },
            Header { name: "Transfer-Encoding", value: "chunked" },
        ])
    }

    #[test]
    fn get_case_insensitive() {
        let h = sample_headers();
        assert_eq!(h.get("host"), Some("example.com"));
        assert_eq!(h.get("HOST"), Some("example.com"));
        assert_eq!(h.get("Host"), Some("example.com"));
    }

    #[test]
    fn get_missing_returns_none() {
        let h = sample_headers();
        assert_eq!(h.get("Accept"), None);
    }

    #[test]
    fn content_length() {
        let h = sample_headers();
        assert_eq!(h.content_length(), Some(42));
    }

    #[test]
    fn is_chunked() {
        let h = sample_headers();
        assert!(h.is_chunked());
    }

    #[test]
    fn content_type() {
        let h = sample_headers();
        assert_eq!(h.content_type(), Some("application/json"));
    }

    #[test]
    fn host() {
        let h = sample_headers();
        assert_eq!(h.host(), Some("example.com"));
    }

    #[test]
    fn is_keep_alive() {
        let h = sample_headers();
        assert!(h.is_keep_alive());
        assert!(!h.is_close());
    }

    #[test]
    fn is_close() {
        let h = Headers::new(vec![Header { name: "Connection", value: "close" }]);
        assert!(h.is_close());
        assert!(!h.is_keep_alive());
    }

    #[test]
    fn websocket_upgrade_detection() {
        let h = Headers::new(vec![
            Header { name: "Upgrade", value: "websocket" },
            Header { name: "Connection", value: "Upgrade" },
            Header { name: "Sec-WebSocket-Key", value: "dGhlIHNhbXBsZSBub25jZQ==" },
        ]);
        assert!(h.is_websocket_upgrade());
        assert_eq!(h.websocket_key(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
    }

    #[test]
    fn websocket_upgrade_missing_connection() {
        let h = Headers::new(vec![Header { name: "Upgrade", value: "websocket" }]);
        assert!(!h.is_websocket_upgrade());
    }

    #[test]
    fn empty_headers() {
        let h = Headers::empty();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert_eq!(h.content_length(), None);
    }

    #[test]
    fn len_and_iter() {
        let h = sample_headers();
        assert_eq!(h.len(), 5);
        assert_eq!(h.iter().count(), 5);
    }

    #[test]
    fn display_formats_headers() {
        let h = Headers::new(vec![Header { name: "X-Test", value: "foo" }]);
        assert_eq!(h.to_string(), "X-Test: foo\n");
    }
}
