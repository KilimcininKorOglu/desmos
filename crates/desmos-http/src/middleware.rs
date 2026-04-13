//! Chain-of-responsibility middleware.
//!
//! Middleware functions run before the route handler and can inspect
//! or modify the request, short-circuit with an early response, or
//! pass control to the next middleware / handler.
//!
//! # Short-circuit
//!
//! Returning `Some(Response)` from a middleware skips all remaining
//! middleware and the handler.  Returning `None` passes to the next.

use crate::request::Request;
use crate::response::Response;

/// A middleware function.
///
/// - Returns `Some(Response)` to short-circuit (e.g. 401 Unauthorized).
/// - Returns `None` to continue to the next middleware or handler.
pub type MiddlewareFn = fn(&Request<'_>) -> Option<Response>;

/// An ordered chain of middleware functions.
#[derive(Clone)]
pub struct MiddlewareChain {
    fns: Vec<MiddlewareFn>,
}

impl MiddlewareChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self { fns: Vec::new() }
    }

    /// Append a middleware to the end of the chain.
    pub fn add(&mut self, mw: MiddlewareFn) -> &mut Self {
        self.fns.push(mw);
        self
    }

    /// Run the chain against a request.
    ///
    /// Returns the first `Some(Response)` from any middleware, or
    /// `None` if all middleware passed.
    pub fn run(&self, req: &Request<'_>) -> Option<Response> {
        for mw in &self.fns {
            if let Some(resp) = mw(req) {
                return Some(resp);
            }
        }
        None
    }

    /// Number of middleware in the chain.
    pub fn len(&self) -> usize {
        self.fns.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.fns.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::StatusCode;
    use crate::headers::Headers;
    use crate::method::Method;

    fn make_request() -> Request<'static> {
        Request { method: Method::Get, uri: "/test", headers: Headers::empty(), body: Vec::new() }
    }

    fn pass_through(_req: &Request<'_>) -> Option<Response> {
        None
    }

    fn block_all(_req: &Request<'_>) -> Option<Response> {
        Some(Response::unauthorized())
    }

    #[test]
    fn empty_chain_passes() {
        let chain = MiddlewareChain::new();
        assert!(chain.is_empty());
        let req = make_request();
        assert!(chain.run(&req).is_none());
    }

    #[test]
    fn pass_through_continues() {
        let mut chain = MiddlewareChain::new();
        chain.add(pass_through);
        chain.add(pass_through);
        let req = make_request();
        assert!(chain.run(&req).is_none());
    }

    #[test]
    fn short_circuit_stops_chain() {
        let mut chain = MiddlewareChain::new();
        chain.add(block_all);
        chain.add(pass_through); // should never reach
        let req = make_request();
        let resp = chain.run(&req).unwrap();
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn first_pass_then_block() {
        let mut chain = MiddlewareChain::new();
        chain.add(pass_through);
        chain.add(block_all);
        let req = make_request();
        let resp = chain.run(&req).unwrap();
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn chain_length() {
        let mut chain = MiddlewareChain::new();
        assert_eq!(chain.len(), 0);
        chain.add(pass_through);
        chain.add(block_all);
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn default_is_empty() {
        let chain = MiddlewareChain::default();
        assert!(chain.is_empty());
    }
}
