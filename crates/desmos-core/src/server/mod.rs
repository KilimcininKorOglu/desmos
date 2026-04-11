//! Multi-client server support.
//!
//! Phase 4's first task exposes the pieces the eventual daemon
//! runner needs to accept concurrent clients on a single UDP
//! listener: a [`ClientRegistry`] that owns the Task 17
//! `SessionTable`, a monotonic `SessionId` allocator, and a
//! [`handshake_responder`](ClientRegistry::accept_client_msg1)
//! entry point that drives the Noise IK responder side and parks
//! the resulting `Session<Established>` in the table keyed by its
//! freshly-minted id.
//!
//! Sockets and the actual reactor loop live elsewhere — this
//! module is pure logic so it can be exercised in `cargo test`
//! without any kernel state.

pub mod clients;
pub mod nat;

pub use clients::ClientRegistry;
pub use clients::ServerError;
pub use nat::IptablesRunner;
pub use nat::NatConfig;
pub use nat::NatController;
pub use nat::NatError;
pub use nat::Runner as NatRunner;
