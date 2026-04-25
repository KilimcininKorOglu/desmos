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
    let mut data = BTreeMap::new();

    match desmos_core::daemon::try_context() {
        Some(ctx) => {
            data.insert("tunnel_state".into(), Value::String(ctx.tunnel_state().as_str().into()));
            data.insert("session_id".into(), Value::Number(1.0));
            data.insert("uptime_s".into(), Value::Number(ctx.uptime_secs() as f64));
            data.insert(
                "strategy".into(),
                Value::String(ctx.engine.current_strategy_name().into()),
            );

            let links = ctx.engine.links_snapshot();
            let iface_arr: Vec<Value> = links
                .all()
                .iter()
                .map(|link| {
                    let mut m = BTreeMap::new();
                    m.insert("name".into(), Value::String(link.name.clone()));
                    m.insert("state".into(), Value::String("active".into()));
                    m.insert("rtt_us".into(), Value::Number(0.0));
                    Value::Object(m)
                })
                .collect();
            data.insert("interfaces".into(), Value::Array(iface_arr));
        }
        None => {
            data.insert("tunnel_state".into(), Value::String("unknown".into()));
            data.insert("session_id".into(), Value::Number(0.0));
            data.insert("uptime_s".into(), Value::Number(0.0));
            data.insert("strategy".into(), Value::String("round-robin".into()));
            data.insert("interfaces".into(), Value::Array(vec![]));
        }
    }

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
