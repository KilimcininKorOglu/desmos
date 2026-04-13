//! `GET /api/v1/config` — read current configuration (secrets redacted).
//!
//! Returns the active TOML config as JSON with sensitive fields replaced
//! by `"***"`.  Fields that are redacted:
//! - `psk` (pre-shared key)
//! - `password_hash` (web UI password)
//! - `private_key`
//! - `totp_secret`
//!
//! ```json
//! {
//!   "data": {
//!     "mode": "client",
//!     "server": { "address": "vpn.example.com", "port": 4789, "psk": "***" },
//!     "bonding": { "strategy": "latency-adaptive" },
//!     ...
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
}
