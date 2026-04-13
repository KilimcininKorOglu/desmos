//! BSD platform backends (macOS, FreeBSD).
//!
//! [`reactor::KqueueReactor`] sits behind the same
//! [`crate::reactor::Reactor`] trait as the Linux epoll backend.
//! [`macos_tun::MacosTun`] provides the macOS utun TUN adapter.
//! Both use hand-declared `extern "C"` bindings — no `libc` crate.

pub mod reactor;

#[cfg(target_os = "macos")]
pub mod macos_tun;

pub use reactor::KqueueReactor;

#[cfg(target_os = "macos")]
pub use macos_tun::MacosTun;
