//! `GET /api/v1/bonding` — current bonding engine state.
//! `PUT /api/v1/bonding/strategy` — hot-switch bonding strategy.
//!
//! PUT accepts:
//! ```json
//! { "strategy": "latency-adaptive" }
//! ```
//!
//! Valid strategies: `round-robin`, `weighted`, `latency-adaptive`, `redundant`.

use crate::dto::{error_envelope, success_envelope};
use desmos_http::json::{self, Value};
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// Valid strategy names for the wire API.
const VALID_STRATEGIES: &[&str] = &["round-robin", "weighted", "latency-adaptive", "redundant"];

/// GET /api/v1/bonding
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    let mut data = BTreeMap::new();

    match desmos_core::daemon::try_context() {
        Some(ctx) => {
            data.insert(
                "strategy".into(),
                Value::String(ctx.engine.current_strategy_name().into()),
            );
            let links = ctx.engine.links_snapshot();
            let total = links.len() as f64;
            data.insert("active_links".into(), Value::Number(total));
            data.insert("degraded_links".into(), Value::Number(0.0));
            data.insert("dead_links".into(), Value::Number(0.0));
        }
        None => {
            data.insert("strategy".into(), Value::String("round-robin".into()));
            data.insert("active_links".into(), Value::Number(0.0));
            data.insert("degraded_links".into(), Value::Number(0.0));
            data.insert("dead_links".into(), Value::Number(0.0));
        }
    }

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// PUT /api/v1/bonding/strategy
///
/// Accepts `{ "strategy": "..." }` and hot-switches the bonding engine.
pub fn set_strategy(req: &Request<'_>, _params: &Params) -> Response {
    // Parse body.
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

    let strategy = match body_value.get("strategy").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            let body = error_envelope("missing_strategy", "Field 'strategy' is required");
            let mut r = Response::bad_request("missing strategy");
            r.body_json(&body);
            return r;
        }
    };

    if !VALID_STRATEGIES.contains(&strategy) {
        let msg =
            format!("Unknown strategy '{}'. Valid: {}", strategy, VALID_STRATEGIES.join(", "));
        let body = error_envelope("invalid_strategy", &msg);
        let mut r = Response::bad_request("invalid strategy");
        r.body_json(&body);
        return r;
    }

    if let Some(ctx) = desmos_core::daemon::try_context() {
        use desmos_core::bonding::{LatencyAdaptive, Redundant, RoundRobin, Weighted};
        use std::sync::Arc;
        let new_strategy: Arc<dyn desmos_core::bonding::BondingStrategy> = match strategy {
            "round-robin" => Arc::new(RoundRobin::new()),
            "weighted" => Arc::new(Weighted::new()),
            "latency-adaptive" => Arc::new(LatencyAdaptive::new()),
            "redundant" => Arc::new(Redundant::new()),
            _ => unreachable!(),
        };
        ctx.engine.swap_strategy(new_strategy);
    }

    let mut data = BTreeMap::new();
    data.insert("strategy".into(), Value::String(strategy.to_owned()));
    data.insert("applied".into(), Value::Bool(true));

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

    fn make_put(body: &str) -> Request<'_> {
        Request {
            method: Method::Put,
            uri: "/api/v1/bonding/strategy",
            headers: Headers::empty(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn set_valid_strategy() {
        for s in VALID_STRATEGIES {
            let body = format!("{{\"strategy\":\"{s}\"}}");
            let req = make_put(&body);
            let resp = set_strategy(&req, &Params::new());
            assert_eq!(resp.status, desmos_http::StatusCode::OK);
            let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
            assert_eq!(v.get("data").unwrap().get("strategy").unwrap().as_str(), Some(*s));
        }
    }

    #[test]
    fn set_invalid_strategy() {
        let req = make_put("{\"strategy\":\"magic\"}");
        let resp = set_strategy(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("error").unwrap().get("code").unwrap().as_str(), Some("invalid_strategy"));
    }

    #[test]
    fn set_missing_strategy_field() {
        let req = make_put("{\"other\":1}");
        let resp = set_strategy(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn set_invalid_json() {
        let req = make_put("not json");
        let resp = set_strategy(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }
}
