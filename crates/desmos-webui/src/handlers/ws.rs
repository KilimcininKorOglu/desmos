//! WebSocket live-stream endpoints.
//!
//! `GET /api/v1/ws/stats` — stream stats snapshots at ≥ 2 Hz.
//! `GET /api/v1/ws/logs`  — stream log entries as they occur.
//!
//! Both endpoints require Basic Auth and a valid WebSocket upgrade
//! request (RFC 6455).  On successful upgrade, the handler returns
//! a `101 Switching Protocols` response.  The actual frame loop
//! runs in the daemon's connection handler after the upgrade.
//!
//! ## Stats stream
//!
//! Emits a JSON text frame every 500ms (2 Hz) containing the same
//! shape as `GET /api/v1/stats` minus the envelope:
//!
//! ```json
//! {
//!   "total_tx_bytes": 1234567890,
//!   "total_rx_bytes": 987654321,
//!   "interfaces": [{ "name": "eth0", "rtt_us": 4210, ... }]
//! }
//! ```
//!
//! ## Logs stream
//!
//! Emits a JSON text frame per log entry matching the minimum level
//! from the `?level=` query parameter (default: info):
//!
//! ```json
//! { "timestamp_us": 1744291200000000, "level": "warn", "target": "...", "message": "..." }
//! ```

use crate::dto::error_envelope;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use desmos_http::websocket::handshake;

/// Minimum interval between stats frames (milliseconds).
pub const STATS_INTERVAL_MS: u64 = 500;

/// Default minimum log level for the logs stream.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// GET /api/v1/ws/stats — WebSocket upgrade for live stats.
///
/// Returns a 101 response on valid upgrade, 400 otherwise.
/// The caller (server connection loop) must switch to frame I/O
/// after sending this response.
pub fn stats(req: &Request<'_>, _params: &Params) -> Response {
    match handshake::try_upgrade(req) {
        Some(resp) => resp,
        None => {
            let body = error_envelope("upgrade_required", "WebSocket upgrade required");
            let mut r = Response::bad_request("upgrade required");
            r.body_json(&body);
            r
        }
    }
}

/// GET /api/v1/ws/logs — WebSocket upgrade for live log stream.
///
/// Accepts an optional `?level=` query parameter to filter the
/// minimum log level (debug/info/warn/error).  Default: info.
pub fn logs(req: &Request<'_>, _params: &Params) -> Response {
    match handshake::try_upgrade(req) {
        Some(resp) => resp,
        None => {
            let body = error_envelope("upgrade_required", "WebSocket upgrade required");
            let mut r = Response::bad_request("upgrade required");
            r.body_json(&body);
            r
        }
    }
}

/// Parse the `?level=` query parameter for the logs WebSocket.
///
/// Returns one of "debug", "info", "warn", "error".
/// Unknown values fall back to the default.
pub fn parse_ws_log_level(req: &Request<'_>) -> &'static str {
    if let Some(query) = req.query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "level" {
                    return match value {
                        "trace" => "trace",
                        "debug" => "debug",
                        "info" => "info",
                        "warn" => "warn",
                        "error" => "error",
                        _ => DEFAULT_LOG_LEVEL,
                    };
                }
            }
        }
    }
    DEFAULT_LOG_LEVEL
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::headers::{Header, Headers};
    use desmos_http::json;
    use desmos_http::method::Method;
    use desmos_http::StatusCode;

    fn make_ws_upgrade(uri: &str) -> Request<'_> {
        Request {
            method: Method::Get,
            uri,
            headers: Headers::new(vec![
                Header { name: "Host", value: "localhost" },
                Header { name: "Upgrade", value: "websocket" },
                Header { name: "Connection", value: "Upgrade" },
                Header { name: "Sec-WebSocket-Key", value: "dGhlIHNhbXBsZSBub25jZQ==" },
                Header { name: "Sec-WebSocket-Version", value: "13" },
            ]),
            body: Vec::new(),
        }
    }

    fn make_non_ws(uri: &str) -> Request<'_> {
        Request {
            method: Method::Get,
            uri,
            headers: Headers::new(vec![Header { name: "Host", value: "localhost" }]),
            body: Vec::new(),
        }
    }

    #[test]
    fn stats_upgrade_returns_101() {
        let req = make_ws_upgrade("/api/v1/ws/stats");
        let resp = stats(&req, &Params::new());
        assert_eq!(resp.status, StatusCode(101));
    }

    #[test]
    fn stats_non_ws_returns_400() {
        let req = make_non_ws("/api/v1/ws/stats");
        let resp = stats(&req, &Params::new());
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("error").unwrap().get("code").unwrap().as_str(), Some("upgrade_required"));
    }

    #[test]
    fn logs_upgrade_returns_101() {
        let req = make_ws_upgrade("/api/v1/ws/logs");
        let resp = logs(&req, &Params::new());
        assert_eq!(resp.status, StatusCode(101));
    }

    #[test]
    fn logs_non_ws_returns_400() {
        let req = make_non_ws("/api/v1/ws/logs");
        let resp = logs(&req, &Params::new());
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_log_level_default() {
        let req = make_non_ws("/api/v1/ws/logs");
        assert_eq!(parse_ws_log_level(&req), "info");
    }

    #[test]
    fn parse_log_level_explicit() {
        let req = make_non_ws("/api/v1/ws/logs?level=warn");
        assert_eq!(parse_ws_log_level(&req), "warn");
    }

    #[test]
    fn parse_log_level_debug() {
        let req = make_non_ws("/api/v1/ws/logs?level=debug");
        assert_eq!(parse_ws_log_level(&req), "debug");
    }

    #[test]
    fn parse_log_level_unknown_fallback() {
        let req = make_non_ws("/api/v1/ws/logs?level=banana");
        assert_eq!(parse_ws_log_level(&req), DEFAULT_LOG_LEVEL);
    }

    #[test]
    fn stats_interval_is_2hz() {
        assert_eq!(STATS_INTERVAL_MS, 500);
    }

    #[test]
    fn stats_upgrade_has_accept_header() {
        let req = make_ws_upgrade("/api/v1/ws/stats");
        let resp = stats(&req, &Params::new());
        assert_eq!(resp.status, StatusCode(101));
        let bytes = resp.to_bytes();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("Sec-WebSocket-Accept:"));
        assert!(s.contains("Upgrade: websocket"));
    }
}
