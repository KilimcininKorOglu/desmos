//! `GET /api/v1/version` — unauthenticated version endpoint.
//!
//! Returns the Desmos version.  Part of the public (no-auth) path set.

use desmos_http::json::{encode, Value};
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// The Desmos version string.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// GET /api/v1/version
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    let mut obj = BTreeMap::new();
    obj.insert("version".into(), Value::String(VERSION.into()));

    let json = encode(&Value::Object(obj));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}
