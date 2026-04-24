//! Desmos domain logic.
//!
//! Hosts bonding strategies, session management, configuration, logger,
//! server, p2p, and authentication. Depends on `desmos-proto` and
//! `desmos-rt` for the cross-platform I/O core; the only direct syscall
//! exposure is inside `net/` (host interface enumeration and link
//! state watching), where there is no sensible reason to route through
//! the runtime crate.

pub mod auth;
pub mod bonding;
pub mod broadcast;
pub mod config;
pub mod errors;
pub mod log;
pub mod net;
pub mod p2p;
pub mod server;
pub mod session;

pub mod daemon;
pub mod pipeline;

pub use errors::{CoreError, Result};
