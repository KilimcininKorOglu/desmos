//! Route registration for the Desmos REST API.
//!
//! Builds a [`Router`] with all `/api/v1/*` endpoints wired up:
//! GET read endpoints, PUT write endpoints, and DELETE kick.
//! Authentication middleware is applied to all routes except the
//! public health and version endpoints.

use crate::auth;
use crate::handlers;
use desmos_http::basic_auth::AuthConfig;
use desmos_http::middleware::MiddlewareChain;
use desmos_http::request::Request;
use desmos_http::response::Response;
use desmos_http::router::Router;

/// Build the complete REST API router.
///
/// The returned router handles all `/api/v1/*` endpoints (GET + PUT + DELETE).
/// Authenticated routes use Basic Auth; health and version are public.
pub fn build_router(auth_config: AuthConfig) -> Router {
    let mut router = Router::new();

    // ---- Public endpoints (no auth) ----------------------------------------

    router.get("/api/v1/health", handlers::health::get);
    router.get("/api/v1/version", handlers::version::get);

    // ---- Authenticated endpoints -------------------------------------------

    let auth_mw = make_auth_middleware(auth_config);

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/status",
        auth_mw.clone(),
        handlers::status::get,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/interfaces",
        auth_mw.clone(),
        handlers::interfaces::list,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/bonding",
        auth_mw.clone(),
        handlers::bonding::get,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/stats",
        auth_mw.clone(),
        handlers::stats::get,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/clients",
        auth_mw.clone(),
        handlers::clients::list,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/config",
        auth_mw.clone(),
        handlers::config::get,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/logs",
        auth_mw.clone(),
        handlers::logs::list,
    );

    // ---- Write endpoints (PUT / DELETE) ------------------------------------

    router.route_with_middleware(
        desmos_http::Method::Put,
        "/api/v1/interfaces/:name",
        auth_mw.clone(),
        handlers::interfaces::update,
    );

    router.route_with_middleware(
        desmos_http::Method::Put,
        "/api/v1/bonding/strategy",
        auth_mw.clone(),
        handlers::bonding::set_strategy,
    );

    router.route_with_middleware(
        desmos_http::Method::Put,
        "/api/v1/config",
        auth_mw.clone(),
        handlers::config::put,
    );

    router.route_with_middleware(
        desmos_http::Method::Delete,
        "/api/v1/clients/:session_id",
        auth_mw.clone(),
        handlers::clients::kick,
    );

    // ---- WebSocket upgrade endpoints ---------------------------------------

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/ws/stats",
        auth_mw.clone(),
        handlers::ws::stats,
    );

    router.route_with_middleware(
        desmos_http::Method::Get,
        "/api/v1/ws/logs",
        auth_mw,
        handlers::ws::logs,
    );

    // ---- Embedded SPA routes -----------------------------------------------

    router.get("/", crate::embed::spa_root);
    // Vite hashed assets live under /assets/*.
    router.get("/assets/:file", crate::embed::spa_static);

    router
}

/// Global auth config, set once at router build time.
///
/// `MiddlewareFn` is a plain `fn` pointer (no closures), so we store
/// the config in a module-level `OnceLock` that the middleware reads.
static GLOBAL_AUTH_CONFIG: std::sync::OnceLock<AuthConfig> = std::sync::OnceLock::new();

/// Auth middleware function (reads from [`GLOBAL_AUTH_CONFIG`]).
fn auth_middleware(req: &Request<'_>) -> Option<Response> {
    let config = match GLOBAL_AUTH_CONFIG.get() {
        Some(c) => c,
        None => return Some(Response::internal_error()),
    };
    auth::auth_gate(req, config)
}

/// Create a Basic Auth middleware chain for the given config.
fn make_auth_middleware(config: AuthConfig) -> MiddlewareChain {
    let _ = GLOBAL_AUTH_CONFIG.set(config);
    let mut chain = MiddlewareChain::new();
    chain.add(auth_middleware);
    chain
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_http::headers::{Header, Headers};
    use desmos_http::json::decode;
    use desmos_http::method::Method;
    use desmos_http::StatusCode;

    fn test_auth_config() -> AuthConfig {
        let hash = desmos_http::basic_auth::hash_password(b"testpass", b"saltsaltsaltsalt", 10_000);
        AuthConfig { username: "admin".into(), password_hash: hash }
    }

    fn make_request<'a>(method: Method, uri: &'a str, auth: Option<&'a str>) -> Request<'a> {
        make_request_with_body(method, uri, auth, Vec::new())
    }

    fn make_request_with_body<'a>(
        method: Method,
        uri: &'a str,
        auth: Option<&'a str>,
        body: Vec<u8>,
    ) -> Request<'a> {
        let mut hdrs = vec![Header { name: "Host", value: "localhost" }];
        if let Some(a) = auth {
            hdrs.push(Header { name: "Authorization", value: a });
        }
        Request { method, uri, headers: Headers::new(hdrs), body }
    }

    fn valid_auth() -> &'static str {
        // "admin:testpass" = "YWRtaW46dGVzdHBhc3M="
        "Basic YWRtaW46dGVzdHBhc3M="
    }

    #[test]
    fn health_is_public() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/health", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        let v = decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert_eq!(v.get("status").unwrap().as_str(), Some("ok"));
    }

    #[test]
    fn version_is_public() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/version", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        let v = decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert!(v.get("version").is_some());
    }

    #[test]
    fn status_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/status", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn status_with_valid_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/status", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        let v = decode(std::str::from_utf8(resp.body()).unwrap()).unwrap();
        assert!(v.get("data").is_some());
        assert!(v.get("meta").is_some());
    }

    #[test]
    fn interfaces_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/interfaces", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn bonding_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/bonding", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn stats_json_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/stats", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).unwrap();
        let v = decode(body).unwrap();
        assert!(v.get("data").is_some());
    }

    #[test]
    fn stats_prometheus_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/stats?format=prometheus", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(resp.body()).unwrap();
        assert!(body.contains("# HELP desmos_bytes_tx"));
        assert!(body.contains("# TYPE desmos_bytes_tx counter"));
    }

    #[test]
    fn clients_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/clients", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn config_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/config", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn logs_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/logs", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn wrong_auth_returns_401() {
        let router = build_router(test_auth_config());
        // "admin:wrong" = "YWRtaW46d3Jvbmc="
        let req = make_request(Method::Get, "/api/v1/status", Some("Basic YWRtaW46d3Jvbmc="));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unknown_path_returns_404() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/unknown", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn wrong_method_returns_405() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Post, "/api/v1/health", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn route_count() {
        let router = build_router(test_auth_config());
        // GET: health + version + status + interfaces + bonding + stats + clients + config + logs = 9
        // PUT: interfaces/:name + bonding/strategy + config = 3
        // DELETE: clients/:session_id = 1
        // WS GET: ws/stats + ws/logs = 2
        // SPA: / + /assets/:file = 2
        // Total = 17
        assert_eq!(router.len(), 17);
    }

    // ---- Write endpoint routing tests --------------------------------------

    #[test]
    fn put_interface_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request_with_body(
            Method::Put,
            "/api/v1/interfaces/eth0",
            None,
            b"{\"weight\":100}".to_vec(),
        );
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn put_interface_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request_with_body(
            Method::Put,
            "/api/v1/interfaces/eth0",
            Some(valid_auth()),
            b"{\"weight\":100}".to_vec(),
        );
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn put_bonding_strategy_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request_with_body(
            Method::Put,
            "/api/v1/bonding/strategy",
            None,
            b"{\"strategy\":\"redundant\"}".to_vec(),
        );
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn put_bonding_strategy_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request_with_body(
            Method::Put,
            "/api/v1/bonding/strategy",
            Some(valid_auth()),
            b"{\"strategy\":\"redundant\"}".to_vec(),
        );
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn put_config_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request_with_body(
            Method::Put,
            "/api/v1/config",
            None,
            b"[general]\nmode = \"client\"\n".to_vec(),
        );
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn delete_client_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Delete, "/api/v1/clients/42", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn delete_client_with_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Delete, "/api/v1/clients/42", Some(valid_auth()));
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    // ---- WebSocket routing tests -------------------------------------------

    #[test]
    fn ws_stats_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/ws/stats", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn ws_logs_requires_auth() {
        let router = build_router(test_auth_config());
        let req = make_request(Method::Get, "/api/v1/ws/logs", None);
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }
}
