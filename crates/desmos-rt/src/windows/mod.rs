//! Windows platform backends.
//!
//! [`reactor::IocpReactor`] implements the [`crate::reactor::Reactor`]
//! trait via IOCP. [`tun::WintunTun`] wraps the Wintun DLL session
//! API behind the [`crate::tun::Tun`] trait.

pub mod reactor;
pub mod tun;

pub use reactor::IocpReactor;
pub use tun::WintunTun;
