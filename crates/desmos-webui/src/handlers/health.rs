//! `GET /api/v1/health` — unauthenticated health check.
//!
//! Returns `{ "status": "ok", "version": "...", "tunnel_state": "...", "uptime_s": N }`.
//! This endpoint intentionally does NOT use the standard envelope
//! format — it is a lightweight probe for load-balancers and monitors.

use desmos_http::json::{encode, Value};
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// The Desmos version string (from Cargo workspace).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// GET /api/v1/health
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    let mut obj = BTreeMap::new();
    obj.insert("status".into(), Value::String("ok".into()));
    obj.insert("version".into(), Value::String(VERSION.into()));
    // TODO: wire to real daemon state when available.
    obj.insert("tunnel_state".into(), Value::String("unknown".into()));
    obj.insert("uptime_s".into(), Value::Number(0.0));

    let json = encode(&Value::Object(obj));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
