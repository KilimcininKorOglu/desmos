//! HTTP error types.

use std::fmt;
use std::io;

/// HTTP-layer errors.
#[derive(Debug)]
pub enum HttpError {
    /// Underlying I/O error.
    Io(io::Error),
    /// Malformed request line or headers.
    BadRequest(&'static str),
    /// Request body exceeds the configured limit.
    PayloadTooLarge,
    /// Unsupported Transfer-Encoding (not chunked or identity).
    UnsupportedEncoding,
    /// Request timed out.
    Timeout,
    /// Connection closed by peer before request was complete.
    ConnectionClosed,
    /// URI too long (> 8 KiB).
    UriTooLong,
    /// Too many headers (> 64).
    TooManyHeaders,
    /// Header line too long (> 8 KiB).
    HeaderTooLong,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::BadRequest(msg) => write!(f, "bad request: {msg}"),
            Self::PayloadTooLarge => f.write_str("payload too large"),
            Self::UnsupportedEncoding => f.write_str("unsupported transfer encoding"),
            Self::Timeout => f.write_str("timeout"),
            Self::ConnectionClosed => f.write_str("connection closed"),
            Self::UriTooLong => f.write_str("URI too long"),
            Self::TooManyHeaders => f.write_str("too many headers"),
            Self::HeaderTooLong => f.write_str("header line too long"),
        }
    }
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const OK: Self = Self(200);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const URI_TOO_LONG: Self = Self(414);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Standard reason phrase for the status code.
    pub fn reason(self) -> &'static str {
        match self.0 {
            200 => "OK",
            204 => "No Content",
            301 => "Moved Permanently",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_display() {
        assert_eq!(StatusCode::OK.to_string(), "200 OK");
        assert_eq!(StatusCode::NOT_FOUND.to_string(), "404 Not Found");
    }

    #[test]
    fn status_code_reason_unknown() {
        assert_eq!(StatusCode(999).reason(), "Unknown");
    }

    #[test]
    fn http_error_display() {
        assert_eq!(HttpError::PayloadTooLarge.to_string(), "payload too large");
        assert_eq!(HttpError::BadRequest("no host").to_string(), "bad request: no host");
    }

    #[test]
    fn http_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "broken");
        let http_err = HttpError::from(io_err);
        assert!(matches!(http_err, HttpError::Io(_)));
    }
}
