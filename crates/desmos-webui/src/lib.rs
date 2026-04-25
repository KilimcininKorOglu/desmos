//! Desmos REST handlers and embedded React SPA.
//!
//! Glues `desmos-core` domain state to the `desmos-http` server. Serves
//! `/api/v1/*` JSON + Prometheus endpoints and the static SPA bundle.
//!
//! # Modules
//!
//! - [`auth`] — Basic Auth gate with public path bypass.
//! - [`dto`] — JSON envelope helpers (success / error envelopes).
//! - [`embed`] — Embedded SPA static file serving (compile-time `include_bytes!`).
//! - [`handlers`] — Per-endpoint GET/PUT/DELETE handlers.
//! - [`prometheus`] — Prometheus text exposition format renderer.
//! - [`routes`] — Router builder that wires handlers + middleware.

pub mod auth;
pub mod dto;
pub mod embed;
pub mod handlers;
pub mod prometheus;
pub mod routes;
pub mod ws_loop;
