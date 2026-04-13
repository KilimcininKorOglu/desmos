//! HTTP/1.1 request parser.
//!
//! Parses the request line and headers from a byte buffer, then
//! reads the body based on `Content-Length` or `Transfer-Encoding:
//! chunked`.  Header parsing is zero-copy — names and values borrow
//! from the input buffer.
//!
//! Body reading supports both content-length and chunked transfer
//! encoding, capped at [`MAX_BODY_SIZE`] (1 MiB).

use crate::errors::HttpError;
use crate::headers::{Header, Headers, MAX_HEADERS, MAX_HEADER_LINE};
use crate::method::Method;

/// Maximum request body size: 1 MiB.
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Maximum request line length (method + URI + version).
pub const MAX_REQUEST_LINE: usize = 8192;

/// A parsed HTTP request.
#[derive(Debug)]
pub struct Request<'a> {
    /// HTTP method.
    pub method: Method,
    /// Request URI (path + optional query string).
    pub uri: &'a str,
    /// Parsed headers.
    pub headers: Headers<'a>,
    /// Request body (empty for GET/HEAD/DELETE).
    pub body: Vec<u8>,
}

impl<'a> Request<'a> {
    /// The path component of the URI (before `?`).
    pub fn path(&self) -> &str {
        self.uri.split('?').next().unwrap_or(self.uri)
    }

    /// The query string (after `?`), if any.
    pub fn query(&self) -> Option<&str> {
        self.uri.split_once('?').map(|(_, q)| q)
    }
}

/// Parse a complete HTTP/1.1 request from a buffer.
///
/// The buffer must contain the full header section (terminated by
/// `\r\n\r\n`).  Returns the parsed request and the number of
/// bytes consumed from the buffer (headers only — body is read
/// separately).
///
/// # Errors
///
/// Returns `HttpError` for malformed requests, oversized headers,
/// unknown methods, etc.
pub fn parse_request(buf: &str) -> Result<(Request<'_>, usize), HttpError> {
    // Find the end of headers.
    let header_end = buf.find("\r\n\r\n").ok_or(HttpError::BadRequest("incomplete headers"))?;

    let header_section = &buf[..header_end];
    let consumed = header_end + 4; // include \r\n\r\n

    // Parse request line.
    let (request_line, header_lines) =
        header_section.split_once("\r\n").ok_or(HttpError::BadRequest("no request line"))?;

    if request_line.len() > MAX_REQUEST_LINE {
        return Err(HttpError::UriTooLong);
    }

    let (method, uri, _version) = parse_request_line(request_line)?;

    // Parse headers.
    let headers = parse_headers(header_lines)?;

    // Read body based on headers.
    let body = if headers.is_chunked() {
        let remaining = &buf[consumed..];
        decode_chunked_body(remaining)?
    } else if let Some(len) = headers.content_length() {
        if len > MAX_BODY_SIZE {
            return Err(HttpError::PayloadTooLarge);
        }
        let remaining = &buf[consumed..];
        if remaining.len() < len {
            return Err(HttpError::BadRequest("incomplete body"));
        }
        remaining[..len].as_bytes().to_vec()
    } else {
        Vec::new()
    };

    Ok((Request { method, uri, headers, body }, consumed))
}

/// Parse `METHOD /path HTTP/1.1`.
fn parse_request_line(line: &str) -> Result<(Method, &str, &str), HttpError> {
    let mut parts = line.splitn(3, ' ');

    let method_str = parts.next().ok_or(HttpError::BadRequest("missing method"))?;
    let uri = parts.next().ok_or(HttpError::BadRequest("missing URI"))?;
    let version = parts.next().ok_or(HttpError::BadRequest("missing HTTP version"))?;

    let method = Method::parse(method_str).ok_or(HttpError::BadRequest("unknown method"))?;

    if !version.starts_with("HTTP/") {
        return Err(HttpError::BadRequest("bad HTTP version"));
    }

    Ok((method, uri, version))
}

/// Parse header lines into a `Headers` collection.
fn parse_headers(section: &str) -> Result<Headers<'_>, HttpError> {
    if section.is_empty() {
        return Ok(Headers::empty());
    }

    let mut entries = Vec::with_capacity(16);

    for line in section.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_HEADER_LINE {
            return Err(HttpError::HeaderTooLong);
        }
        if entries.len() >= MAX_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }

        let (name, value) =
            line.split_once(':').ok_or(HttpError::BadRequest("malformed header"))?;

        entries.push(Header { name: name.trim(), value: value.trim() });
    }

    Ok(Headers::new(entries))
}

/// Decode a chunked transfer-encoded body.
///
/// Each chunk: `<hex-size>\r\n<data>\r\n`, terminated by `0\r\n\r\n`.
fn decode_chunked_body(data: &str) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut remaining = data;

    loop {
        // Read chunk size line.
        let (size_line, rest) =
            remaining.split_once("\r\n").ok_or(HttpError::BadRequest("truncated chunk size"))?;

        let chunk_size = usize::from_str_radix(size_line.trim(), 16)
            .map_err(|_| HttpError::BadRequest("invalid chunk size"))?;

        if chunk_size == 0 {
            // Terminal chunk.
            break;
        }

        if body.len() + chunk_size > MAX_BODY_SIZE {
            return Err(HttpError::PayloadTooLarge);
        }

        if rest.len() < chunk_size + 2 {
            return Err(HttpError::BadRequest("truncated chunk data"));
        }

        body.extend_from_slice(rest[..chunk_size].as_bytes());
        remaining = &rest[chunk_size + 2..]; // skip data + \r\n
    }

    Ok(body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, consumed) = parse_request(raw).unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.uri, "/");
        assert_eq!(req.path(), "/");
        assert_eq!(req.query(), None);
        assert_eq!(req.headers.host(), Some("localhost"));
        assert!(req.body.is_empty());
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn parse_get_with_query() {
        let raw = "GET /api/v1/status?format=json HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = parse_request(raw).unwrap();
        assert_eq!(req.path(), "/api/v1/status");
        assert_eq!(req.query(), Some("format=json"));
    }

    #[test]
    fn parse_post_with_body() {
        let raw = "POST /api/v1/config HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Content-Length: 13\r\n\
                    Content-Type: application/json\r\n\
                    \r\n\
                    {\"key\":\"val\"}";
        let (req, _) = parse_request(raw).unwrap();
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.body, b"{\"key\":\"val\"}");
        assert_eq!(req.headers.content_type(), Some("application/json"));
    }

    #[test]
    fn parse_chunked_body() {
        let raw = "POST /upload HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    5\r\n\
                    Hello\r\n\
                    6\r\n\
                    World!\r\n\
                    0\r\n\
                    \r\n";
        let (req, _) = parse_request(raw).unwrap();
        assert_eq!(req.body, b"HelloWorld!");
    }

    #[test]
    fn reject_unknown_method() {
        let raw = "TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let err = parse_request(raw).unwrap_err();
        assert!(matches!(err, HttpError::BadRequest("unknown method")));
    }

    #[test]
    fn reject_missing_version() {
        let raw = "GET /\r\nHost: localhost\r\n\r\n";
        let err = parse_request(raw).unwrap_err();
        assert!(matches!(err, HttpError::BadRequest(_)));
    }

    #[test]
    fn reject_incomplete_headers() {
        let raw = "GET / HTTP/1.1\r\nHost: localhost\r\n";
        let err = parse_request(raw).unwrap_err();
        assert!(matches!(err, HttpError::BadRequest("incomplete headers")));
    }

    #[test]
    fn reject_body_too_large() {
        let len = MAX_BODY_SIZE + 1;
        let raw = format!("POST / HTTP/1.1\r\nContent-Length: {len}\r\n\r\n{}", "x".repeat(len));
        let err = parse_request(&raw).unwrap_err();
        assert!(matches!(err, HttpError::PayloadTooLarge));
    }

    #[test]
    fn reject_malformed_header() {
        let raw = "GET / HTTP/1.1\r\nBadHeader\r\n\r\n";
        let err = parse_request(raw).unwrap_err();
        assert!(matches!(err, HttpError::BadRequest("malformed header")));
    }

    #[test]
    fn empty_body_for_get() {
        let raw = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        let (req, _) = parse_request(raw).unwrap();
        assert!(req.body.is_empty());
    }

    #[test]
    fn multiple_headers_same_request() {
        let raw = "GET / HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Accept: text/html\r\n\
                    Accept-Language: en\r\n\
                    Connection: close\r\n\
                    \r\n";
        let (req, _) = parse_request(raw).unwrap();
        assert_eq!(req.headers.len(), 4);
        assert!(req.headers.is_close());
    }

    #[test]
    fn chunked_empty_body() {
        let raw = "POST / HTTP/1.1\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    0\r\n\
                    \r\n";
        let (req, _) = parse_request(raw).unwrap();
        assert!(req.body.is_empty());
    }
}
