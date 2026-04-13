//! `GET /api/v1/bonding` — current bonding engine state.
//!
//! Returns:
//! ```json
//! {
//!   "data": {
//!     "strategy": "latency-adaptive",
//!     "active_links": 3,
//!     "degraded_links": 0,
//!     "dead_links": 0
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

/// GET /api/v1/bonding
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    // TODO: wire to real bonding engine state.
    let mut data = BTreeMap::new();
    data.insert("strategy".into(), Value::String("round-robin".into()));
    data.insert("active_links".into(), Value::Number(0.0));
    data.insert("degraded_links".into(), Value::Number(0.0));
    data.insert("dead_links".into(), Value::Number(0.0));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
