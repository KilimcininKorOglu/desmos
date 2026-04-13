//! WebSocket support (RFC 6455).
//!
//! - [`handshake`] — Upgrade handshake (101 Switching Protocols).
//! - [`frame`] — Frame encoder/decoder (text, binary, close, ping, pong).
//!
//! The server-side flow:
//! 1. Router detects a WebSocket route.
//! 2. Middleware runs (e.g. Basic Auth).
//! 3. [`handshake::try_upgrade`] validates headers and returns 101.
//! 4. The connection switches to frame-based I/O.
//! 5. Server sends/receives frames via [`frame::encode_frame`] /
//!    [`frame::decode_frame`].
//! 6. Ping/pong keep-alive; close on > 60 s idle.

pub mod frame;
pub mod handshake;

pub use frame::decode_frame;
pub use frame::encode_frame;
pub use frame::Frame;
pub use frame::Opcode;
pub use handshake::try_upgrade;
