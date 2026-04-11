//! Peer-to-peer NAT traversal.
//!
//! Task 37 ships [`crate::net::stun`] for public-address
//! discovery. Task 38 builds on it with UDP hole punching:
//! given both peers' STUN-reflected `(ip, port)` pairs and a
//! shared UDP socket, hole punch until the pair has a
//! confirmed bidirectional flow.
//!
//! The module is logic-only — signalling (how peers exchange
//! their reflected addresses before punching) is out of scope
//! and assumed to be handled by whatever rendezvous layer the
//! daemon eventually carries (typically a small HTTP or
//! WebSocket helper against a Desmos server). Task 39 will add
//! a relay fallback that re-uses the same shared socket when
//! punching fails outright.

pub mod holepunch;

pub use holepunch::hole_punch;
pub use holepunch::HolePunchConfig;
pub use holepunch::P2pError;
pub use holepunch::ProbeKind;
pub use holepunch::PROBE_LEN;
