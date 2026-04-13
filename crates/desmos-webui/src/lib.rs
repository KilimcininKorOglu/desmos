//! Desmos REST handlers and embedded React SPA.
//!
//! Glues `desmos-core` domain state to the `desmos-http` server. Serves
//! `/api/v1/*` JSON + Prometheus endpoints and the static SPA bundle.
//!
//! # Modules
//!
//! - [`auth`] — Basic Auth gate with public path bypass.

pub mod auth;
