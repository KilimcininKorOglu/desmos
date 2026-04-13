//! `GET /api/v1/stats` — traffic and link quality statistics.
//!
//! Supports dual-format output:
//! - **JSON** (default): standard envelope with per-interface counters.
//! - **Prometheus text**: `?format=prometheus` query parameter or
//!   `Accept: text/plain; version=0.0.4` header.
//!
//! JSON shape:
//! ```json
//! {
//!   "data": {
//!     "total_tx_bytes": 1234567890,
//!     "total_rx_bytes": 987654321,
//!     "interfaces": [
//!       {
//!         "name": "eth0",
//!         "tx_bytes": 1234, "rx_bytes": 5678,
//!         "tx_packets": 100, "rx_packets": 95,
//!         "rtt_us": 4210, "loss_pct": 0.1, "jitter_us": 320
//!       }
//!     ]
//!   },
//!   "meta": { ... }
//! }
//! ```

use crate::dto::success_envelope;
use crate::prometheus::{self, InterfaceStats};
use desmos_http::json::Value;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// GET /api/v1/stats
pub fn get(req: &Request<'_>, _params: &Params) -> Response {
    if wants_prometheus(req) {
        return prometheus_response();
    }
    json_response()
}

/// Check if the request asks for Prometheus format via query param or Accept header.
fn wants_prometheus(req: &Request<'_>) -> bool {
    // Check ?format=prometheus query parameter.
    if let Some(query) = req.query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "format" && value == "prometheus" {
                    return true;
                }
            }
        }
    }

    // Check Accept header for Prometheus content type.
    if let Some(accept) = req.headers.accept() {
        if accept.contains("text/plain") && accept.contains("version=0.0.4") {
            return true;
        }
    }

    false
}

/// Collect current interface stats.
///
/// TODO: wire to real daemon state.  Returns stub data for now.
fn collect_stats() -> Vec<InterfaceStats> {
    Vec::new()
}

/// Build JSON stats response.
fn json_response() -> Response {
    let ifaces = collect_stats();

    let mut total_tx: u64 = 0;
    let mut total_rx: u64 = 0;
    let iface_values: Vec<Value> = ifaces
        .iter()
        .map(|i| {
            total_tx = total_tx.saturating_add(i.tx_bytes);
            total_rx = total_rx.saturating_add(i.rx_bytes);

            let mut obj = BTreeMap::new();
            obj.insert("name".into(), Value::String(i.name.clone()));
            obj.insert("tx_bytes".into(), Value::Number(i.tx_bytes as f64));
            obj.insert("rx_bytes".into(), Value::Number(i.rx_bytes as f64));
            obj.insert("tx_packets".into(), Value::Number(i.tx_packets as f64));
            obj.insert("rx_packets".into(), Value::Number(i.rx_packets as f64));
            obj.insert("rtt_us".into(), Value::Number(i.rtt_us as f64));
            obj.insert("loss_pct".into(), Value::Number(i.loss_pct));
            obj.insert("jitter_us".into(), Value::Number(i.jitter_us as f64));
            Value::Object(obj)
        })
        .collect();

    let mut data = BTreeMap::new();
    data.insert("total_tx_bytes".into(), Value::Number(total_tx as f64));
    data.insert("total_rx_bytes".into(), Value::Number(total_rx as f64));
    data.insert("interfaces".into(), Value::Array(iface_values));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// Build Prometheus text format response.
fn prometheus_response() -> Response {
    let ifaces = collect_stats();
    let families = prometheus::build_desmos_metrics(&ifaces);
    let text = prometheus::render(&families);

    let mut r = Response::ok();
    r.body_raw(prometheus::PROMETHEUS_CONTENT_TYPE, text.into_bytes());
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::headers::{Header, Headers};
    use desmos_http::method::Method;

    fn make_get(uri: &str) -> Request<'_> {
        Request { method: Method::Get, uri, headers: Headers::empty(), body: Vec::new() }
    }

    fn make_get_with_accept<'a>(uri: &'a str, accept: &'a str) -> Request<'a> {
        Request {
            method: Method::Get,
            uri,
            headers: Headers::new(vec![
                Header { name: "Host", value: "localhost" },
                Header { name: "Accept", value: accept },
            ]),
            body: Vec::new(),
        }
    }

    #[test]
    fn default_returns_json() {
        let req = make_get("/api/v1/stats");
        let resp = get(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).unwrap();
        let v = desmos_http::json::decode(body).unwrap();
        assert!(v.get("data").is_some());
        assert!(v.get("data").unwrap().get("total_tx_bytes").is_some());
    }

    #[test]
    fn query_param_returns_prometheus() {
        let req = make_get("/api/v1/stats?format=prometheus");
        let resp = get(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).unwrap();
        assert!(body.contains("# HELP desmos_bytes_tx"));
        assert!(body.contains("# TYPE desmos_bytes_tx counter"));
    }

    #[test]
    fn accept_header_returns_prometheus() {
        let req = make_get_with_accept("/api/v1/stats", "text/plain; version=0.0.4");
        let resp = get(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).unwrap();
        assert!(body.contains("# HELP desmos_bytes_tx"));
    }

    #[test]
    fn accept_json_returns_json() {
        let req = make_get_with_accept("/api/v1/stats", "application/json");
        let resp = get(&req, &Params::new());
        let body = std::str::from_utf8(resp.body()).unwrap();
        assert!(desmos_http::json::decode(body).is_ok());
    }

    #[test]
    fn query_param_overrides_accept() {
        // Even with JSON accept, ?format=prometheus wins.
        let req = make_get_with_accept("/api/v1/stats?format=prometheus", "application/json");
        let resp = get(&req, &Params::new());
        let body = std::str::from_utf8(resp.body()).unwrap();
        assert!(body.contains("# HELP"));
    }

    #[test]
    fn json_response_has_interface_array() {
        let req = make_get("/api/v1/stats");
        let resp = get(&req, &Params::new());
        let body = std::str::from_utf8(resp.body()).unwrap();
        let v = desmos_http::json::decode(body).unwrap();
        let data = v.get("data").unwrap();
        assert!(data.get("interfaces").unwrap().as_array().is_some());
    }

    #[test]
    fn prometheus_has_all_metric_families() {
        let req = make_get("/api/v1/stats?format=prometheus");
        let resp = get(&req, &Params::new());
        let body = std::str::from_utf8(resp.body()).unwrap();
        // All 8 metric families should have HELP lines.
        for name in &[
            "desmos_bytes_tx",
            "desmos_bytes_rx",
            "desmos_packets_tx",
            "desmos_packets_rx",
            "desmos_errors_total",
            "desmos_link_rtt_us",
            "desmos_link_loss_pct",
            "desmos_link_jitter_us",
        ] {
            assert!(body.contains(&format!("# HELP {name}")), "missing HELP for {name}");
            assert!(body.contains(&format!("# TYPE {name}")), "missing TYPE for {name}");
        }
    }
}
