//! `GET /api/v1/config` — read current configuration (secrets redacted).
//! `PUT /api/v1/config` — hot-reload configuration.
//!
//! GET returns the active config as JSON with sensitive fields replaced
//! by `"***"`.
//!
//! PUT accepts a full TOML configuration body.  The handler:
//! 1. Parses the TOML.
//! 2. Validates the schema.
//! 3. Diffs against the running config.
//! 4. Rejects if any reload-unsafe fields changed.
//! 5. Applies reload-safe changes.
//!
//! Reload-unsafe fields (require restart):
//! - `general.mode`, `server.listen`, `server.public_key`,
//!   `server.private_key_file`, `client.server`,
//!   `client.server_public_key`, `client.private_key_file`

use crate::dto::{error_envelope, error_envelope_with_details, success_envelope};
use desmos_http::json::Value;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Params;
use std::collections::BTreeMap;

/// Keys whose values are redacted in the config GET response.
const REDACTED_KEYS: &[&str] = &["psk", "password_hash", "private_key", "totp_secret"];

/// Redaction placeholder.
const REDACTED: &str = "***";

/// GET /api/v1/config
pub fn get(_req: &Request<'_>, _params: &Params) -> Response {
    // TODO: wire to real config; for now return a stub config shape.
    let mut data = BTreeMap::new();
    data.insert("mode".into(), Value::String("client".into()));

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// PUT /api/v1/config
///
/// Accepts a TOML body, parses → validates → diffs → applies.
pub fn put(req: &Request<'_>, _params: &Params) -> Response {
    let body_str = match std::str::from_utf8(&req.body) {
        Ok(s) => s,
        Err(_) => {
            let body = error_envelope("invalid_body", "Request body is not valid UTF-8");
            let mut r = Response::bad_request("invalid body");
            r.body_json(&body);
            return r;
        }
    };

    if body_str.trim().is_empty() {
        let body = error_envelope("empty_body", "TOML body is required");
        let mut r = Response::bad_request("empty body");
        r.body_json(&body);
        return r;
    }

    // Step 1: Parse TOML.
    let value = match desmos_core::config::parse(body_str) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("TOML parse error: {e}");
            let body = error_envelope("parse_error", &msg);
            let mut r = Response::bad_request("parse error");
            r.body_json(&body);
            return r;
        }
    };

    // Step 2: Validate schema.
    let new_config = match desmos_core::config::Config::from_value(&value) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Validation error: {e}");
            let body = error_envelope("validation_error", &msg);
            let mut r = Response::bad_request("validation error");
            r.body_json(&body);
            return r;
        }
    };

    // Step 3: Diff against current config.
    // TODO: replace stub with real running config.
    // For now, diff against the newly parsed config itself (no-op diff).
    let diff = desmos_core::config::diff::diff(&new_config, &new_config);

    // Step 4: Check for unsafe changes.
    if !diff.is_safe() {
        let unsafe_fields = diff.unsafe_fields();
        let fields_json =
            Value::Array(unsafe_fields.iter().map(|f| Value::String((*f).to_string())).collect());
        let mut details = BTreeMap::new();
        details.insert("unsafe_fields".into(), fields_json);
        let body = error_envelope_with_details(
            "unsafe_reload",
            "Some fields cannot be hot-reloaded and require a restart",
            Some(Value::Object(details)),
        );
        // 409 Conflict for unsafe reload.
        let mut r = Response::new(desmos_http::StatusCode(409));
        r.body_json(&body);
        return r;
    }

    // Step 5: Apply.
    // TODO: wire to real config apply logic.
    let mut data = BTreeMap::new();
    data.insert("applied".into(), Value::Bool(true));
    if !diff.is_empty() {
        let safe = diff.safe_fields();
        data.insert(
            "reloaded_fields".into(),
            Value::Array(safe.iter().map(|f| Value::String((*f).to_string())).collect()),
        );
    }

    let json = success_envelope(Value::Object(data));
    let mut r = Response::ok();
    r.body_json(&json);
    r
}

/// Recursively redact sensitive keys in a JSON Value.
pub fn redact_secrets(value: &Value) -> Value {
    match value {
        Value::Object(obj) => {
            let mut out = BTreeMap::new();
            for (k, v) in obj {
                if REDACTED_KEYS.contains(&k.as_str()) {
                    out.insert(k.clone(), Value::String(REDACTED.into()));
                } else {
                    out.insert(k.clone(), redact_secrets(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact_secrets).collect()),
        other => other.clone(),
    }
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

    fn make_put(body: &str) -> Request<'_> {
        Request {
            method: Method::Put,
            uri: "/api/v1/config",
            headers: Headers::empty(),
            body: body.as_bytes().to_vec(),
        }
    }

    // ---- Redaction tests (carried from Task 55) ----------------------------

    #[test]
    fn redact_top_level_keys() {
        let mut obj = BTreeMap::new();
        obj.insert("psk".into(), Value::String("secret123".into()));
        obj.insert("name".into(), Value::String("eth0".into()));
        let result = redact_secrets(&Value::Object(obj));
        let o = result.as_object().unwrap();
        assert_eq!(o.get("psk").unwrap().as_str(), Some(REDACTED));
        assert_eq!(o.get("name").unwrap().as_str(), Some("eth0"));
    }

    #[test]
    fn redact_nested_keys() {
        let mut inner = BTreeMap::new();
        inner.insert("private_key".into(), Value::String("key-data".into()));
        inner.insert("port".into(), Value::Number(4789.0));
        let mut outer = BTreeMap::new();
        outer.insert("server".into(), Value::Object(inner));
        let result = redact_secrets(&Value::Object(outer));
        let server = result.get("server").unwrap().as_object().unwrap();
        assert_eq!(server.get("private_key").unwrap().as_str(), Some(REDACTED));
        assert_eq!(server.get("port").unwrap().as_f64(), Some(4789.0));
    }

    #[test]
    fn redact_in_array() {
        let mut obj = BTreeMap::new();
        obj.insert("totp_secret".into(), Value::String("JBSWY3DPEHPK3PXP".into()));
        let arr = Value::Array(vec![Value::Object(obj)]);
        let result = redact_secrets(&arr);
        let items = result.as_array().unwrap();
        let first = items[0].as_object().unwrap();
        assert_eq!(first.get("totp_secret").unwrap().as_str(), Some(REDACTED));
    }

    #[test]
    fn redact_preserves_non_sensitive() {
        let v = Value::String("hello".into());
        assert_eq!(redact_secrets(&v), v);
    }

    #[test]
    fn redact_all_secret_keys() {
        for key in REDACTED_KEYS {
            let mut obj = BTreeMap::new();
            obj.insert((*key).to_string(), Value::String("value".into()));
            let result = redact_secrets(&Value::Object(obj));
            assert_eq!(
                result.as_object().unwrap().get(*key).unwrap().as_str(),
                Some(REDACTED),
                "key {key} was not redacted"
            );
        }
    }

    // ---- PUT config tests --------------------------------------------------

    #[test]
    fn put_empty_body_rejected() {
        let req = make_put("");
        let resp = put(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_invalid_toml_rejected() {
        let req = make_put("[[[broken");
        let resp = put(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("error").unwrap().get("code").unwrap().as_str(), Some("parse_error"));
    }

    #[test]
    fn put_valid_toml_missing_general_rejected() {
        // A TOML that parses but fails validation (missing [general]).
        let req = make_put("[webui]\nenabled = true\n");
        let resp = put(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("error").unwrap().get("code").unwrap().as_str(), Some("validation_error"));
    }

    #[test]
    fn put_valid_config_accepted() {
        let toml = concat!(
            "[general]\n",
            "mode = \"client\"\n",
            "log_level = \"info\"\n",
            "tunnel_mtu = 1400\n",
            "\n",
            "[client]\n",
            "server = \"vpn.example.com:4789\"\n",
            "server_public_key = \"pk\"\n",
            "private_key_file = \"/etc/desmos/key\"\n",
            "bonding_strategy = \"latency-adaptive\"\n",
            "reorder_window_ms = 50\n",
            "dns_leak_protection = true\n",
            "dns_servers = [\"1.1.1.1\"]\n",
            "\n",
            "[[client.interfaces]]\n",
            "name = \"eth0\"\n",
            "weight = 100\n",
            "enabled = true\n",
        );
        let req = make_put(toml);
        let resp = put(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::OK);
        let v = json::decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("data").unwrap().get("applied").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn put_non_utf8_rejected() {
        let req = Request {
            method: Method::Put,
            uri: "/api/v1/config",
            headers: Headers::empty(),
            body: vec![0xFF, 0xFE],
        };
        let resp = put(&req, &Params::new());
        assert_eq!(resp.status, desmos_http::StatusCode::BAD_REQUEST);
    }
}
