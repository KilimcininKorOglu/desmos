//! Peer-to-peer NAT traversal.
//!
//! [`crate::net::stun`] handles public-address discovery. UDP
//! hole punching builds on it: given both peers' STUN-reflected
//! `(ip, port)` pairs and a shared UDP socket, hole punch until
//! the pair has a confirmed bidirectional flow.
//!
//! A relay fallback is also available: when hole punching fails on
//! all candidate addresses, the peer registers with one of
//! the configured `[p2p].relay_servers` and routes traffic
//! through the relay transparently.
//!
//! The module is logic-only — signalling (how peers exchange
//! their reflected addresses before punching) is out of scope
//! and assumed to be handled by whatever rendezvous layer the
//! daemon eventually carries (typically a small HTTP or
//! WebSocket helper against a Desmos server).

pub mod holepunch;
pub mod relay;

pub use holepunch::hole_punch;
pub use holepunch::HolePunchConfig;
pub use holepunch::P2pError;
pub use holepunch::ProbeKind;
pub use holepunch::PROBE_LEN;
pub use relay::try_direct_then_relay;
pub use relay::P2pConnectConfig;
pub use relay::P2pOutcome;
pub use relay::RelayCmd;
pub use relay::RelayError;
pub use relay::RelaySession;
