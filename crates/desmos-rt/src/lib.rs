//! Desmos hand-rolled async runtime.
//!
//! The only crate with `unsafe` syscall FFI. Provides platform-specific
//! reactors (epoll/kqueue/IOCP), TUN adapters, UDP sockets, timer wheel,
//! SPSC ring buffers, and the buffer pool.

pub mod pool;

pub use pool::PacketPool;
pub use pool::PoolStats;
