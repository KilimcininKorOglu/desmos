//! `GET /api/v1/interfaces` — list configured network interfaces.
//! `PUT /api/v1/interfaces/:name` — enable, disable, or reweight an interface.
//!
//! GET returns:
//! ```json
//! {
//!   "data": {
//!     "interfaces": [
//!       { "name": "eth0", "state": "healthy", "rtt_us": 4210, ... }
//!     ]
//!   },
//!   "meta": { ... }
//! }
//! ```
//!
//! PUT accepts:
//! ```json
//! { "enabled": true, "weight": 150 }
//! ```

use crate::dto::{error_envelope, success_envelope};
use desmos_http::json::{self, Value};
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// GET /api/v1/interfaces
pub fn list(_req: &Request<'_>, _params: &Params) -> Response {
    let iface_arr = match desmos_core::daemon::try_context() {
        Some(ctx) => {
            let links = ctx.engine.links_snapshot();
            links
                .all()
                .iter()
                .map(|link| {
                    let mut m = BTreeMap::new();
                    m.insert("name".into(), Value::String(link.name.clone()));
                    m.insert("id".into(), Value::Number(link.id as f64));
                    m.insert("state".into(), Value::String("active".into()));
                    m.insert("rtt_us".into(), Value::Number(0.0));
                    m.insert("loss_pct".into(), Value::Number(0.0));
                    m.insert("jitter_us".into(), Value::Number(0.0));
                    m.insert("tx_bytes".into(), Value::Number(0.0));
                    m.insert("rx_bytes".into(), Value::Number(0.0));
                    m.insert("weight".into(), Value::Number(link.weight as f64));
                    m.insert("enabled".into(), Value::Bool(true));
                    Value::Object(m)
                })
                .collect()
        }
        None => vec![],
    };

    let mut data = BTreeMap::new();
    data.insert("interfaces".into(), Value::Array(iface_arr));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// PUT /api/v1/interfaces/:name
///
/// Accepts JSON body with optional `enabled` (bool) and `weight` (u32).
pub fn update(req: &Request<'_>, params: &Params) -> Response {
    let name = match params.get("name") {
        Some(n) => n,
        None => {
            let body = error_envelope("missing_param", "Interface name is required");
            let mut r = Response::bad_request("missing param");
            r.body_json(&body);
            return r;
        }
    };

    // Parse request body as JSON.
    let body_str = match std::str::from_utf8(&req.body) {
        Ok(s) => s,
        Err(_) => {
            let body = error_envelope("invalid_body", "Request body is not valid UTF-8");
            let mut r = Response::bad_request("invalid body");
            r.body_json(&body);
            return r;
        }
    };

    let body_value = match json::decode(body_str) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("Invalid JSON: {e}");
            let body = error_envelope("invalid_json", &msg);
            let mut r = Response::bad_request("invalid json");
            r.body_json(&body);
            return r;
        }
    };

    // Validate the update fields.
    let obj = match body_value.as_object() {
        Some(o) => o,
        None => {
            let body = error_envelope("invalid_body", "Expected a JSON object");
            let mut r = Response::bad_request("invalid body");
            r.body_json(&body);
            return r;
        }
    };

    // Validate weight if present.
    if let Some(w) = obj.get("weight") {
        match w.as_f64() {
            Some(n) if (0.0..=1000.0).contains(&n) && n.fract() == 0.0 => {}
            _ => {
                let body = error_envelope("invalid_weight", "Weight must be 0-1000 integer");
                let mut r = Response::bad_request("invalid weight");
                r.body_json(&body);
                return r;
            }
        }
    }

    // Validate enabled if present.
    if let Some(e) = obj.get("enabled") {
        if e.as_bool().is_none() {
            let body = error_envelope("invalid_enabled", "Enabled must be a boolean");
            let mut r = Response::bad_request("invalid enabled");
            r.body_json(&body);
            return r;
        }
    }

    let weight = obj.get("weight").and_then(|v| v.as_f64()).map(|f| f as u32);
    let enabled = obj.get("enabled").and_then(|v| v.as_bool());

    let ctx = match desmos_core::daemon::try_context() {
        Some(c) => c,
        None => {
            let body = error_envelope("no_daemon", "Daemon not running");
            let mut r = Response::new(desmos_http::StatusCode::SERVICE_UNAVAILABLE);
            r.body_json(&body);
            return r;
        }
    };

    if !ctx.engine.update_link(name, weight, enabled) {
        let body = error_envelope("not_found", "No link with that name");
        let mut r = Response::not_found();
        r.body_json(&body);
        return r;
    }

    let mut data = BTreeMap::new();
    data.insert("name".into(), Value::String(name.to_owned()));
    data.insert("updated".into(), Value::Bool(true));
    if let Some(w) = weight {
        data.insert("weight".into(), Value::Number(w as f64));
    }
    if let Some(e) = enabled {
        data.insert("enabled".into(), Value::Bool(e));
    }

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::headers::Headers;
    use desmos_http::method::Method;

    fn make_put<'a>(uri: &'a str, body: &str) -> Request<'a> {
        Request {
            method: Method::Put,
            uri,
            headers: Headers::empty(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn update_without_daemon_returns_503() {
        let req = make_put("/api/v1/interfaces/eth0", "{\"weight\":150}");
        let mut params = Params::new();
        params.push("name".into(), "eth0".into());
        let resp = update(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn update_invalid_weight_too_high() {
        let req = make_put("/api/v1/interfaces/eth0", "{\"weight\":9999}");
        let mut params = Params::new();
        params.push("name".into(), "eth0".into());
        let resp = update(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn update_invalid_json() {
        let req = make_put("/api/v1/interfaces/eth0", "not json");
        let mut params = Params::new();
        params.push("name".into(), "eth0".into());
        let resp = update(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn update_non_object_body() {
        let req = make_put("/api/v1/interfaces/eth0", "42");
        let mut params = Params::new();
        params.push("name".into(), "eth0".into());
        let resp = update(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }
}
