//! BSD kqueue reactor backend (macOS, FreeBSD).
//!
//! Mirror of the Linux [`super::linux::EpollReactor`] sitting behind
//! the same [`crate::reactor::Reactor`] trait. Uses `kqueue()` and
//! `kevent()` with hand-declared `extern "C"` bindings — no `libc`
//! crate, matching the rest of `desmos-rt`.

pub mod reactor;

pub use reactor::KqueueReactor;
