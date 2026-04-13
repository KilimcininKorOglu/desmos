//! BSD platform backends (macOS, FreeBSD).
//!
//! [`reactor::KqueueReactor`] sits behind the same
//! [`crate::reactor::Reactor`] trait as the Linux epoll backend.
//! [`macos_tun::MacosTun`] and [`freebsd_tun::FreeBsdTun`] provide
//! per-OS TUN adapters. All use hand-declared `extern "C"` bindings
//! — no `libc` crate.

pub mod reactor;

#[cfg(target_os = "macos")]
pub mod macos_tun;

#[cfg(target_os = "freebsd")]
pub mod freebsd_tun;

pub use reactor::KqueueReactor;

#[cfg(target_os = "macos")]
pub use macos_tun::MacosTun;

#[cfg(target_os = "freebsd")]
pub use freebsd_tun::FreeBsdTun;
