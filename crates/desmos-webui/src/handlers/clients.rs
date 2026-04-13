//! `GET /api/v1/clients` — list active client sessions (server mode).
//! `DELETE /api/v1/clients/:session_id` — kick a client session.
//!
//! DELETE returns:
//! ```json
//! {
//!   "data": { "session_id": 17, "kicked": true },
//!   "meta": { ... }
//! }
//! ```

use crate::dto::{error_envelope, success_envelope};
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

/// DELETE /api/v1/clients/:session_id
///
/// Kicks the client with the given session ID.
pub fn kick(_req: &Request<'_>, params: &Params) -> Response {
    let session_id_str = match params.get("session_id") {
        Some(s) => s,
        None => {
            let body = error_envelope("missing_param", "Session ID is required");
            let mut r = Response::bad_request("missing param");
            r.body_json(&body);
            return r;
        }
    };

    let session_id: u16 = match session_id_str.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            let body = error_envelope(
                "invalid_session_id",
                "Session ID must be a positive integer (1-65535)",
            );
            let mut r = Response::bad_request("invalid session id");
            r.body_json(&body);
            return r;
        }
    };

    // TODO: wire to real ClientRegistry::remove_client.
    // For now, report success.  In production, a 404 would be returned
    // if the session doesn't exist.
    let mut data = BTreeMap::new();
    data.insert("session_id".into(), Value::Number(session_id as f64));
    data.insert("kicked".into(), Value::Bool(true));

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
    use desmos_http::json;
    use desmos_http::method::Method;

    fn make_delete(uri: &str) -> Request<'_> {
        Request { method: Method::Delete, uri, headers: Headers::empty(), body: Vec::new() }
    }

    #[test]
    fn kick_valid_session() {
        let req = make_delete("/api/v1/clients/42");
        let mut params = Params::new();
        params.push("session_id".into(), "42".into());
        let resp = kick(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::OK);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        let data = v.get("data").unwrap();
        assert_eq!(data.get("session_id").unwrap().as_f64(), Some(42.0));
        assert_eq!(data.get("kicked").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn kick_invalid_session_id() {
        let req = make_delete("/api/v1/clients/abc");
        let mut params = Params::new();
        params.push("session_id".into(), "abc".into());
        let resp = kick(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn kick_zero_session_id() {
        let req = make_delete("/api/v1/clients/0");
        let mut params = Params::new();
        params.push("session_id".into(), "0".into());
        let resp = kick(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn kick_overflow_session_id() {
        let req = make_delete("/api/v1/clients/99999");
        let mut params = Params::new();
        params.push("session_id".into(), "99999".into());
        let resp = kick(&req, &params);
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }
}
