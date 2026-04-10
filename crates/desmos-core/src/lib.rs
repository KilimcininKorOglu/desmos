//! Desmos domain logic.
//!
//! Hosts bonding strategies, session management, configuration, logger,
//! server, p2p, and authentication. Depends on `desmos-proto` and
//! `desmos-rt` but knows nothing about platform syscalls directly.

pub mod config;
pub mod errors;
pub mod log;

#[cfg(unix)]
pub mod pipeline;

pub use errors::{CoreError, Result};
