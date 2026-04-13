//! REST API GET handlers for `/api/v1/*`.
//!
//! Each sub-module exposes one or more `RouteHandler`-compatible
//! functions that produce JSON responses in the standard envelope
//! format.

pub mod bonding;
pub mod clients;
pub mod config;
pub mod health;
pub mod interfaces;
pub mod logs;
pub mod stats;
pub mod status;
pub mod version;
