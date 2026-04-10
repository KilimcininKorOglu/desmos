//! Desmos wire protocol, crypto primitives, and handshake state machine.
//!
//! This crate is I/O-free and compiles without platform syscalls.

pub mod errors;
pub mod flags;
pub mod types;
pub mod wire;

pub use errors::WireError;
pub use flags::Flags;
pub use types::InterfaceId;
pub use types::Seq;
pub use types::SessionId;
pub use types::TimestampUs;
pub use wire::Header;
pub use wire::PacketType;
pub use wire::AEAD_TAG_LEN;
pub use wire::HEADER_LEN;
pub use wire::WIRE_VERSION;
