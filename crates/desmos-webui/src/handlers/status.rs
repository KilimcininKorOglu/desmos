//! `GET /api/v1/status` — tunnel and bonding status overview.
//!
//! Returns:
//! ```json
//! {
//!   "data": {
//!     "tunnel_state": "up",
//!     "session_id": 17,
//!     "uptime_s": 42310,
//!     "strategy": "latency-adaptive",
//!     "interfaces": [{ "name": "eth0", "state": "healthy", "rtt_us": 4210 }]
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

/// GET /api/v1/status
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    // TODO: wire to real daemon state.
    let mut data = BTreeMap::new();
    data.insert("tunnel_state".into(), Value::String("unknown".into()));
    data.insert("session_id".into(), Value::Number(0.0));
    data.insert("uptime_s".into(), Value::Number(0.0));
    data.insert("strategy".into(), Value::String("round-robin".into()));
    data.insert("interfaces".into(), Value::Array(vec![]));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
