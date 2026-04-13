//! `GET /api/v1/logs` — retrieve recent log entries.
//!
//! Returns:
//! ```json
//! {
//!   "data": {
//!     "entries": [
//!       {
//!         "timestamp_us": 1744291200000000,
//!         "level": "info",
//!         "target": "desmos_core::session",
//!         "message": "session established with peer"
//!       }
//!     ]
//!   },
//!   "meta": { ... }
//! }
//! ```
//!
//! Query parameters:
//! - `limit=N` — max entries to return (default 100, max 1000).
//! - `level=warn` — minimum level filter (debug/info/warn/error).

use crate::dto::success_envelope;
use desmos_http::json::Value;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// Default number of log entries to return.
const DEFAULT_LIMIT: usize = 100;

/// Maximum number of log entries per request.
const MAX_LIMIT: usize = 1000;

/// GET /api/v1/logs
pub fn list(req: &Request<'_>, _params: &Params) -> Response {
    let query = req.query().unwrap_or("");
    let _limit = parse_limit(query);
    let _level = parse_level(query);

    // TODO: wire to real log ring buffer.
    let mut data = BTreeMap::new();
    data.insert("entries".into(), Value::Array(vec![]));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// Parse `?limit=N` from a query string.
fn parse_limit(query: &str) -> usize {
    parse_query_param(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.min(MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT)
}

/// Parse `?level=...` from a query string.
fn parse_level(query: &str) -> &str {
    parse_query_param(query, "level").unwrap_or("debug")
}

/// Extract a single query parameter value from a query string.
fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_limit_default() {
        assert_eq!(parse_limit(""), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_limit_explicit() {
        assert_eq!(parse_limit("limit=50"), 50);
    }

    #[test]
    fn parse_limit_clamped() {
        assert_eq!(parse_limit("limit=9999"), MAX_LIMIT);
    }

    #[test]
    fn parse_limit_invalid() {
        assert_eq!(parse_limit("limit=abc"), DEFAULT_LIMIT);
    }

    #[test]
    fn parse_level_default() {
        assert_eq!(parse_level(""), "debug");
    }

    #[test]
    fn parse_level_explicit() {
        assert_eq!(parse_level("level=warn"), "warn");
    }

    #[test]
    fn parse_multiple_params() {
        let q = "limit=25&level=error";
        assert_eq!(parse_limit(q), 25);
        assert_eq!(parse_level(q), "error");
    }

    #[test]
    fn parse_query_param_missing() {
        assert_eq!(parse_query_param("foo=bar", "baz"), None);
    }

    #[test]
    fn parse_query_param_present() {
        assert_eq!(parse_query_param("foo=bar&key=val", "key"), Some("val"));
    }
}
