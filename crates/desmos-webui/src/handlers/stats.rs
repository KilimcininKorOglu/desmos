//! `GET /api/v1/stats` — traffic and link quality statistics.
//!
//! Supports dual-format output:
//! - JSON (default): standard envelope with per-interface counters.
//! - Prometheus text: `?format=prometheus` query parameter.
//!
//! JSON shape:
//! ```json
//! {
//!   "data": {
//!     "total_tx_bytes": 1234567890,
//!     "total_rx_bytes": 987654321,
//!     "interfaces": [
//!       { "name": "eth0", "tx_bytes": 1234, "rx_bytes": 5678, "rtt_us": 4210 }
//!     ]
//!   },
//!   "meta": { ... }
//! }
//! ```

use crate::dto::success_envelope;
use desmos_http::json::Value;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// GET /api/v1/stats
pub fn get(req: &Request<'_>, _params: &Params) -> Response {
    // Check for ?format=prometheus
    if is_prometheus_format(req) {
        return prometheus_response();
    }

    json_response()
}

/// Check if the request asks for Prometheus format.
fn is_prometheus_format(req: &Request<'_>) -> bool {
    if let Some(query) = req.query() {
        // Simple query string parsing for "format=prometheus".
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "format" && value == "prometheus" {
                    return true;
                }
            }
        }
    }
    false
}

/// Build JSON stats response.
fn json_response() -> Response {
    // TODO: wire to real counters.
    let mut data = BTreeMap::new();
    data.insert("total_tx_bytes".into(), Value::Number(0.0));
    data.insert("total_rx_bytes".into(), Value::Number(0.0));
    data.insert("interfaces".into(), Value::Array(vec![]));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// Build Prometheus text format response.
fn prometheus_response() -> Response {
    // TODO: wire to real counters.
    let body = concat!(
        "# HELP desmos_bytes_tx Total bytes transmitted through the tunnel\n",
        "# TYPE desmos_bytes_tx counter\n",
        "\n",
        "# HELP desmos_bytes_rx Total bytes received through the tunnel\n",
        "# TYPE desmos_bytes_rx counter\n",
        "\n",
        "# HELP desmos_link_rtt_us Current RTT in microseconds\n",
        "# TYPE desmos_link_rtt_us gauge\n",
    );

    let mut r = Response::ok();
    r.body_raw("text/plain; version=0.0.4; charset=utf-8", body.as_bytes().to_vec());
    r
}
