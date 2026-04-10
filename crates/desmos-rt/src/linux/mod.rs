//! Linux-specific runtime code. Only compiled when `target_os = "linux"`.

#![cfg(target_os = "linux")]

pub mod reactor;

pub use reactor::EpollReactor;
