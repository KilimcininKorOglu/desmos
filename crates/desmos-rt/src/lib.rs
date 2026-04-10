//! Desmos hand-rolled async runtime.
//!
//! The only crate with `unsafe` syscall FFI. Provides platform-specific
//! reactors (epoll/kqueue/IOCP), TUN adapters, UDP sockets, timer wheel,
//! SPSC ring buffers, and the buffer pool.

pub mod event;
pub mod pool;
pub mod ring;

#[cfg(unix)]
pub mod reactor;

#[cfg(target_os = "linux")]
pub mod linux;

pub use event::Event;
pub use event::Interest;
pub use event::Tag;
pub use event::Token;
pub use pool::PacketPool;
pub use pool::PoolStats;
pub use ring::Consumer;
pub use ring::Producer;
pub use ring::SpscRing;

#[cfg(unix)]
pub use reactor::RawSource;
#[cfg(unix)]
pub use reactor::Reactor;

#[cfg(target_os = "linux")]
pub use linux::EpollReactor;
