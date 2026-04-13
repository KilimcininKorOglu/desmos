//! Web UI authentication layer.
//!
//! Bridges the `desmos-http` Basic Auth middleware with the Desmos
//! config system.  Reads `[webui].username` and `[webui].password_hash`
//! from the daemon config and wires them into the HTTP middleware
//! chain.
//!
//! Public endpoints (e.g. `/api/v1/health`) bypass authentication.

use desmos_http::basic_auth::{check_basic_auth, AuthConfig};
use desmos_http::request::Request;
use desmos_http::response::Response;

/// Paths that are always public (no auth required).
const PUBLIC_PATHS: &[&str] = &["/api/v1/health", "/api/v1/version"];

/// Check if a request path is public.
pub fn is_public_path(path: &str) -> bool {
    PUBLIC_PATHS.contains(&path)
}

/// Run Basic Auth check unless the path is public.
///
/// Returns `None` if the request is allowed (public path or valid
/// credentials), `Some(401)` otherwise.
pub fn auth_gate(req: &Request<'_>, config: &AuthConfig) -> Option<Response> {
    let path = req.path();

    if is_public_path(path) {
        return None;
    }

    check_basic_auth(req, config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::headers::{Header, Headers};
    use desmos_http::method::Method;

    fn make_request<'a>(uri: &'a str, auth: Option<&'a str>) -> Request<'a> {
        let mut hdrs = vec![Header { name: "Host", value: "localhost" }];
        if let Some(a) = auth {
            hdrs.push(Header { name: "Authorization", value: a });
        }
        Request { method: Method::Get, uri, headers: Headers::new(hdrs), body: Vec::new() }
    }

    fn test_config() -> AuthConfig {
        let hash = desmos_http::basic_auth::hash_password(b"testpass", b"saltsaltsaltsalt", 10_000);
        AuthConfig { username: "admin".into(), password_hash: hash }
    }

    #[test]
    fn health_is_public() {
        assert!(is_public_path("/api/v1/health"));
    }

    #[test]
    fn version_is_public() {
        assert!(is_public_path("/api/v1/version"));
    }

    #[test]
    fn status_is_not_public() {
        assert!(!is_public_path("/api/v1/status"));
    }

    #[test]
    fn public_path_bypasses_auth() {
        let config = test_config();
        let req = make_request("/api/v1/health", None);
        assert!(auth_gate(&req, &config).is_none());
    }

    #[test]
    fn private_path_without_auth_returns_401() {
        let config = test_config();
        let req = make_request("/api/v1/status", None);
        let resp = auth_gate(&req, &config).unwrap();
        assert_eq!(resp.status, desmos_http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn private_path_with_valid_auth_passes() {
        let config = test_config();
        // "admin:testpass" = "YWRtaW46dGVzdHBhc3M="
        let req = make_request("/api/v1/status", Some("Basic YWRtaW46dGVzdHBhc3M="));
        assert!(auth_gate(&req, &config).is_none());
    }

    #[test]
    fn private_path_with_wrong_auth_returns_401() {
        let config = test_config();
        // "admin:wrong" = "YWRtaW46d3Jvbmc="
        let req = make_request("/api/v1/status", Some("Basic YWRtaW46d3Jvbmc="));
        let resp = auth_gate(&req, &config).unwrap();
        assert_eq!(resp.status, desmos_http::StatusCode::UNAUTHORIZED);
    }
}
