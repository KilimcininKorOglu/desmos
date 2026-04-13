//! `GET /api/v1/clients` — list active client sessions (server mode).
//!
//! Returns:
//! ```json
//! {
//!   "data": {
//!     "clients": [
//!       {
//!         "session_id": 17,
//!         "remote_addr": "192.168.1.100:51820",
//!         "connected_at_us": 1744291200000000,
//!         "tx_bytes": 12345,
//!         "rx_bytes": 67890
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

/// GET /api/v1/clients
pub fn list(_req: &Request<'_>, _params: &Params) -> Response {
    // TODO: wire to real server session list.
    let mut data = BTreeMap::new();
    data.insert("clients".into(), Value::Array(vec![]));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
