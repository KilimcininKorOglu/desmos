//! Path + method HTTP router with parameter extraction.
//!
//! Supports exact-match routes (`/api/v1/status`) and parameterized
//! routes (`/api/v1/clients/:id`).  Each route carries a method
//! filter, an optional middleware chain, and a handler function.
//!
//! # Matching
//!
//! Routes are matched in registration order.  The first match wins.
//! Path segments starting with `:` are treated as named parameters
//! and will match any non-empty segment.
//!
//! # 404 / 405
//!
//! If no route matches the path, a 404 response is returned.
//! If a path matches but the method doesn't, a 405 response is
//! returned.

use crate::method::Method;
use crate::middleware::MiddlewareChain;
use crate::request::Request;
use crate::response::Response;

/// Extracted path parameters from a parameterized route.
///
/// Parameters are stored as `(name, value)` pairs in match order.
#[derive(Debug, Clone)]
pub struct Params {
    entries: Vec<(String, String)>,
}

impl Params {
    /// Create an empty parameter set.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Get a parameter by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// Number of extracted parameters.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the parameter set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert a parameter.  Used by the router internally and by
    /// tests in downstream crates.
    pub fn push(&mut self, name: String, value: String) {
        self.entries.push((name, value));
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

/// A route handler that receives the request and extracted params.
pub type RouteHandler = fn(&Request<'_>, &Params) -> Response;

/// A single registered route.
struct Route {
    method: Method,
    pattern: Vec<Segment>,
    middleware: MiddlewareChain,
    handler: RouteHandler,
}

/// A path segment: either a literal string or a named parameter.
#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Param(String),
}

/// Path + method router.
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    /// Create an empty router.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Register a route with no middleware.
    pub fn route(&mut self, method: Method, path: &str, handler: RouteHandler) -> &mut Self {
        self.route_with_middleware(method, path, MiddlewareChain::new(), handler)
    }

    /// Register a route with a middleware chain.
    pub fn route_with_middleware(
        &mut self,
        method: Method,
        path: &str,
        middleware: MiddlewareChain,
        handler: RouteHandler,
    ) -> &mut Self {
        let pattern = parse_pattern(path);
        self.routes.push(Route { method, pattern, middleware, handler });
        self
    }

    /// Convenience: register a GET route.
    pub fn get(&mut self, path: &str, handler: RouteHandler) -> &mut Self {
        self.route(Method::Get, path, handler)
    }

    /// Convenience: register a POST route.
    pub fn post(&mut self, path: &str, handler: RouteHandler) -> &mut Self {
        self.route(Method::Post, path, handler)
    }

    /// Convenience: register a PUT route.
    pub fn put(&mut self, path: &str, handler: RouteHandler) -> &mut Self {
        self.route(Method::Put, path, handler)
    }

    /// Convenience: register a DELETE route.
    pub fn delete(&mut self, path: &str, handler: RouteHandler) -> &mut Self {
        self.route(Method::Delete, path, handler)
    }

    /// Dispatch a request through the router.
    ///
    /// Returns the handler's response, or 404/405 if no match.
    pub fn dispatch(&self, req: &Request<'_>) -> Response {
        let path = req.path();
        let req_segments: Vec<&str> = split_path(path);

        let mut path_matched = false;

        for route in &self.routes {
            if let Some(params) = match_pattern(&route.pattern, &req_segments) {
                path_matched = true;

                if route.method != req.method {
                    continue;
                }

                // Run middleware chain.
                if let Some(resp) = route.middleware.run(req) {
                    return resp;
                }

                return (route.handler)(req, &params);
            }
        }

        if path_matched {
            Response::method_not_allowed()
        } else {
            Response::not_found()
        }
    }

    /// Number of registered routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the router has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Pattern parsing --------------------------------------------------------

/// Parse a path pattern like `/api/v1/clients/:id` into segments.
fn parse_pattern(path: &str) -> Vec<Segment> {
    split_path(path)
        .into_iter()
        .map(|s| {
            if let Some(name) = s.strip_prefix(':') {
                Segment::Param(name.to_owned())
            } else {
                Segment::Literal(s.to_owned())
            }
        })
        .collect()
}

/// Split a path into non-empty segments.
fn split_path(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Try to match a route pattern against request path segments.
///
/// Returns extracted parameters on success, `None` on mismatch.
fn match_pattern(pattern: &[Segment], segments: &[&str]) -> Option<Params> {
    if pattern.len() != segments.len() {
        return None;
    }

    let mut params = Params::new();

    for (seg, value) in pattern.iter().zip(segments.iter()) {
        match seg {
            Segment::Literal(lit) => {
                if lit != value {
                    return None;
                }
            }
            Segment::Param(name) => {
                if value.is_empty() {
                    return None;
                }
                params.push(name.clone(), (*value).to_owned());
            }
        }
    }

    Some(params)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::StatusCode;
    use crate::headers::Headers;

    fn make_request(method: Method, uri: &str) -> Request<'_> {
        Request { method, uri, headers: Headers::empty(), body: Vec::new() }
    }

    fn hello_handler(_req: &Request<'_>, _params: &Params) -> Response {
        let mut r = Response::ok();
        r.body_text("hello");
        r
    }

    fn echo_id_handler(_req: &Request<'_>, params: &Params) -> Response {
        let id = params.get("id").unwrap_or("none");
        let mut r = Response::ok();
        r.body_text(id);
        r
    }

    fn status_handler(_req: &Request<'_>, _params: &Params) -> Response {
        let mut r = Response::ok();
        r.body_json("{\"status\":\"ok\"}");
        r
    }

    // ---- Pattern parsing tests ------------------------------------------

    #[test]
    fn split_path_basic() {
        assert_eq!(split_path("/api/v1/status"), vec!["api", "v1", "status"]);
    }

    #[test]
    fn split_path_root() {
        assert!(split_path("/").is_empty());
    }

    #[test]
    fn split_path_trailing_slash() {
        assert_eq!(split_path("/api/v1/"), vec!["api", "v1"]);
    }

    #[test]
    fn parse_pattern_literal() {
        let segs = parse_pattern("/api/v1/status");
        assert_eq!(segs.len(), 3);
        assert!(matches!(&segs[0], Segment::Literal(s) if s == "api"));
        assert!(matches!(&segs[2], Segment::Literal(s) if s == "status"));
    }

    #[test]
    fn parse_pattern_with_param() {
        let segs = parse_pattern("/api/v1/clients/:id");
        assert_eq!(segs.len(), 4);
        assert!(matches!(&segs[3], Segment::Param(s) if s == "id"));
    }

    // ---- Match tests ----------------------------------------------------

    #[test]
    fn match_exact() {
        let pattern = parse_pattern("/api/v1/status");
        let segments = split_path("/api/v1/status");
        let params = match_pattern(&pattern, &segments).unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn match_with_param() {
        let pattern = parse_pattern("/api/v1/clients/:id");
        let segments = split_path("/api/v1/clients/42");
        let params = match_pattern(&pattern, &segments).unwrap();
        assert_eq!(params.get("id"), Some("42"));
    }

    #[test]
    fn match_multiple_params() {
        let pattern = parse_pattern("/api/:version/clients/:id");
        let segments = split_path("/api/v2/clients/99");
        let params = match_pattern(&pattern, &segments).unwrap();
        assert_eq!(params.get("version"), Some("v2"));
        assert_eq!(params.get("id"), Some("99"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn no_match_different_length() {
        let pattern = parse_pattern("/api/v1");
        let segments = split_path("/api/v1/extra");
        assert!(match_pattern(&pattern, &segments).is_none());
    }

    #[test]
    fn no_match_different_literal() {
        let pattern = parse_pattern("/api/v1/status");
        let segments = split_path("/api/v2/status");
        assert!(match_pattern(&pattern, &segments).is_none());
    }

    // ---- Router dispatch tests ------------------------------------------

    #[test]
    fn dispatch_exact_get() {
        let mut router = Router::new();
        router.get("/", hello_handler);
        let req = make_request(Method::Get, "/");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body(), b"hello");
    }

    #[test]
    fn dispatch_parameterized_route() {
        let mut router = Router::new();
        router.get("/clients/:id", echo_id_handler);
        let req = make_request(Method::Get, "/clients/42");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body(), b"42");
    }

    #[test]
    fn dispatch_returns_404_on_no_match() {
        let mut router = Router::new();
        router.get("/api/status", status_handler);
        let req = make_request(Method::Get, "/api/missing");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn dispatch_returns_405_on_wrong_method() {
        let mut router = Router::new();
        router.get("/api/status", status_handler);
        let req = make_request(Method::Post, "/api/status");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn dispatch_multiple_routes() {
        let mut router = Router::new();
        router.get("/api/status", status_handler);
        router.get("/api/clients/:id", echo_id_handler);
        router.post("/api/clients", hello_handler);

        let req = make_request(Method::Get, "/api/status");
        assert_eq!(router.dispatch(&req).status, StatusCode::OK);

        let req = make_request(Method::Get, "/api/clients/7");
        let resp = router.dispatch(&req);
        assert_eq!(resp.body(), b"7");

        let req = make_request(Method::Post, "/api/clients");
        assert_eq!(router.dispatch(&req).status, StatusCode::OK);
    }

    #[test]
    fn dispatch_first_match_wins() {
        let mut router = Router::new();
        router.get("/api/:catch_all", hello_handler);
        router.get("/api/specific", status_handler);

        // The parameterized route is registered first, so it wins.
        let req = make_request(Method::Get, "/api/specific");
        let resp = router.dispatch(&req);
        assert_eq!(resp.body(), b"hello");
    }

    #[test]
    fn dispatch_with_middleware_short_circuit() {
        fn block(_req: &Request<'_>) -> Option<Response> {
            Some(Response::unauthorized())
        }

        let mut mw = MiddlewareChain::new();
        mw.add(block);

        let mut router = Router::new();
        router.route_with_middleware(Method::Get, "/secret", mw, status_handler);

        let req = make_request(Method::Get, "/secret");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn dispatch_with_passing_middleware() {
        fn pass(_req: &Request<'_>) -> Option<Response> {
            None
        }

        let mut mw = MiddlewareChain::new();
        mw.add(pass);

        let mut router = Router::new();
        router.route_with_middleware(Method::Get, "/open", mw, status_handler);

        let req = make_request(Method::Get, "/open");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn router_len_and_empty() {
        let mut router = Router::new();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
        router.get("/", hello_handler);
        assert!(!router.is_empty());
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn convenience_methods() {
        let mut router = Router::new();
        router.get("/g", hello_handler);
        router.post("/p", hello_handler);
        router.put("/u", hello_handler);
        router.delete("/d", hello_handler);
        assert_eq!(router.len(), 4);
    }

    #[test]
    fn params_missing_key() {
        let params = Params::new();
        assert_eq!(params.get("missing"), None);
    }

    #[test]
    fn dispatch_query_string_ignored_in_matching() {
        let mut router = Router::new();
        router.get("/api/status", status_handler);
        let req = make_request(Method::Get, "/api/status?format=json");
        let resp = router.dispatch(&req);
        assert_eq!(resp.status, StatusCode::OK);
    }
}
