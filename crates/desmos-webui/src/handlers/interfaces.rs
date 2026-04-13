//! `GET /api/v1/interfaces` — list configured network interfaces.
//!
//! Returns:
//! ```json
//! {
//!   "data": {
//!     "interfaces": [
//!       {
//!         "name": "eth0",
//!         "state": "healthy",
//!         "rtt_us": 4210,
//!         "loss_pct": 0.1,
//!         "jitter_us": 320,
//!         "tx_bytes": 123456,
//!         "rx_bytes": 654321,
//!         "weight": 100
//!       }
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

/// GET /api/v1/interfaces
pub fn list(_req: &Request<'_>, _params: &Params) -> Response {
    // TODO: wire to real interface discovery + link stats.
    let mut data = BTreeMap::new();
    data.insert("interfaces".into(), Value::Array(vec![]));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
