//! Data transfer objects and JSON envelope helpers for the REST API.
//!
//! All successful responses follow the envelope:
//!
//! ```json
//! { "data": { ... }, "meta": { "request_id": "0x...", "generated_at_us": 123 } }
//! ```
//!
//! Error responses follow:
//!
//! ```json
//! { "error": { "code": "...", "message": "..." }, "meta": { ... } }
//! ```

use desmos_http::json::Value;
use std::collections::BTreeMap;

// ---- Request ID generator --------------------------------------------------

/// Simple request ID counter.  In a real daemon this would be atomic;
/// for now a per-call counter using a static atomic is fine.
static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Generate a hex request ID like `"0x00000001"`.
pub fn next_request_id() -> String {
    let id = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("0x{:08x}", id)
}

// ---- Timestamp helper ------------------------------------------------------

/// Get current wall-clock time in microseconds since Unix epoch.
///
/// Uses `gettimeofday` on Unix, `GetSystemTimePreciseAsFileTime` on
/// Windows.  Falls back to 0 on unsupported platforms.
pub fn now_us() -> u64 {
    #[cfg(unix)]
    {
        let mut tv = libc_timeval { tv_sec: 0, tv_usec: 0 };
        // SAFETY: gettimeofday with NULL timezone is always safe.
        unsafe { gettimeofday(&mut tv, std::ptr::null_mut()) };
        (tv.tv_sec as u64) * 1_000_000 + (tv.tv_usec as u64)
    }
    #[cfg(windows)]
    {
        // Windows FILETIME: 100-ns intervals since 1601-01-01.
        // Unix epoch offset: 116444736000000000 * 100ns.
        const EPOCH_OFFSET: u64 = 116_444_736_000_000_000;
        let mut ft: [u32; 2] = [0; 2];
        unsafe { GetSystemTimePreciseAsFileTime(ft.as_mut_ptr().cast()) };
        let ticks = (ft[1] as u64) << 32 | ft[0] as u64;
        (ticks - EPOCH_OFFSET) / 10
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}

#[cfg(unix)]
#[repr(C)]
struct libc_timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[cfg(unix)]
extern "C" {
    fn gettimeofday(tv: *mut libc_timeval, tz: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
extern "system" {
    fn GetSystemTimePreciseAsFileTime(lpFileTime: *mut std::ffi::c_void);
}

// ---- Meta object -----------------------------------------------------------

/// Build the `"meta"` envelope object.
fn meta_object(request_id: &str, generated_at_us: u64) -> Value {
    let mut meta = BTreeMap::new();
    meta.insert("request_id".into(), Value::String(request_id.into()));
    meta.insert("generated_at_us".into(), Value::Number(generated_at_us as f64));
    Value::Object(meta)
}

// ---- Envelope builders -----------------------------------------------------

/// Build a success envelope: `{ "data": <payload>, "meta": { ... } }`.
pub fn success_envelope(data: Value) -> String {
    let request_id = next_request_id();
    let ts = now_us();
    let mut root = BTreeMap::new();
    root.insert("data".into(), data);
    root.insert("meta".into(), meta_object(&request_id, ts));
    desmos_http::json::encode(&Value::Object(root))
}

/// Build an error envelope: `{ "error": { "code": ..., "message": ... }, "meta": { ... } }`.
pub fn error_envelope(code: &str, message: &str) -> String {
    error_envelope_with_details(code, message, None)
}

/// Build an error envelope with optional details.
pub fn error_envelope_with_details(code: &str, message: &str, details: Option<Value>) -> String {
    let request_id = next_request_id();
    let ts = now_us();

    let mut err = BTreeMap::new();
    err.insert("code".into(), Value::String(code.into()));
    err.insert("message".into(), Value::String(message.into()));
    if let Some(d) = details {
        err.insert("details".into(), d);
    }

    let mut root = BTreeMap::new();
    root.insert("error".into(), Value::Object(err));
    root.insert("meta".into(), meta_object(&request_id, ts));
    desmos_http::json::encode(&Value::Object(root))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::json::decode;

    #[test]
    fn success_envelope_shape() {
        let data = Value::String("test".into());
        let json = success_envelope(data);
        let v = decode(&json).unwrap();
        assert!(v.get("data").is_some());
        assert!(v.get("meta").is_some());
        let meta = v.get("meta").unwrap();
        assert!(meta.get("request_id").unwrap().as_str().unwrap().starts_with("0x"));
        assert!(meta.get("generated_at_us").unwrap().as_f64().is_some());
    }

    #[test]
    fn error_envelope_shape() {
        let json = error_envelope("not_found", "Resource not found");
        let v = decode(&json).unwrap();
        let err = v.get("error").unwrap();
        assert_eq!(err.get("code").unwrap().as_str(), Some("not_found"));
        assert_eq!(err.get("message").unwrap().as_str(), Some("Resource not found"));
        assert!(v.get("meta").is_some());
    }

    #[test]
    fn error_envelope_with_details_shape() {
        let mut details = BTreeMap::new();
        details.insert("name".into(), Value::String("eth5".into()));
        let json = error_envelope_with_details(
            "iface_not_found",
            "No such interface",
            Some(Value::Object(details)),
        );
        let v = decode(&json).unwrap();
        let err = v.get("error").unwrap();
        let d = err.get("details").unwrap();
        assert_eq!(d.get("name").unwrap().as_str(), Some("eth5"));
    }

    #[test]
    fn request_ids_increment() {
        let a = next_request_id();
        let b = next_request_id();
        assert_ne!(a, b);
        assert!(a.starts_with("0x"));
        assert!(b.starts_with("0x"));
    }

    #[test]
    fn now_us_nonzero() {
        let t = now_us();
        // Should be well past Unix epoch.
        assert!(t > 1_000_000_000_000_000);
    }
}
