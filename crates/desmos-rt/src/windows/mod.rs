//! Windows IOCP reactor backend.
//!
//! Implements the [`crate::reactor::Reactor`] trait via Windows I/O
//! Completion Ports. Uses hand-declared `extern "system"` bindings
//! for `CreateIoCompletionPort`, `GetQueuedCompletionStatusEx`,
//! `WSARecv`, `WSASend`, and friends — no `windows-sys` or `winapi`
//! crate, matching the rest of `desmos-rt`.

pub mod reactor;

pub use reactor::IocpReactor;
