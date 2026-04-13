//! Desmos hand-rolled HTTP/1.1 server.
//!
//! Provides a minimal HTTP server with request parsing, response
//! building, and a connection loop.  Built without any HTTP framework
//! dependencies — the entire stack is hand-rolled per the project's
//! five-runtime-crate constraint.
//!
//! # Modules
//!
//! - [`errors`] — HTTP error types and status codes.
//! - [`method`] — HTTP method enum.
//! - [`headers`] — Header collection with typed accessors.
//! - [`request`] — Zero-copy request parser (headers + body).
//! - [`response`] — Response builder with status/headers/body.
//! - [`server`] — TCP listener and connection loop.
//! - [`middleware`] — Chain-of-responsibility middleware.
//! - [`router`] — Path + method routing with parameter extraction.
//! - [`json`] — JSON encoder/decoder (subset, depth-limited).

pub mod errors;
pub mod headers;
pub mod json;
pub mod method;
pub mod middleware;
pub mod request;
pub mod response;
pub mod router;
pub mod server;

pub use errors::HttpError;
pub use errors::StatusCode;
pub use headers::Headers;
pub use method::Method;
pub use middleware::MiddlewareChain;
pub use request::Request;
pub use response::Response;
pub use router::Params;
pub use router::Router;
pub use server::HttpServer;
pub use server::ServerConfig;
