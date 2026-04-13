//! REST API handlers for `/api/v1/*`.
//!
//! Each sub-module exposes one or more `RouteHandler`-compatible
//! functions that produce JSON or WebSocket upgrade responses.

pub mod bonding;
pub mod clients;
pub mod config;
pub mod health;
pub mod interfaces;
pub mod logs;
pub mod stats;
pub mod status;
pub mod version;
pub mod ws;
