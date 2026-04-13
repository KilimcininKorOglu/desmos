//! Desmos REST handlers and embedded React SPA.
//!
//! Glues `desmos-core` domain state to the `desmos-http` server. Serves
//! `/api/v1/*` JSON + Prometheus endpoints and the static SPA bundle.
//!
//! # Modules
//!
//! - [`auth`] — Basic Auth gate with public path bypass.
//! - [`dto`] — JSON envelope helpers (success / error envelopes).
//! - [`handlers`] — Per-endpoint GET handlers.
//! - [`routes`] — Router builder that wires handlers + middleware.

pub mod auth;
pub mod dto;
pub mod handlers;
pub mod routes;
