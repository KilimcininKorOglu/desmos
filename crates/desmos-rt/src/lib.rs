//! Desmos hand-rolled async runtime.
//!
//! The only crate with `unsafe` syscall FFI. Provides platform-specific
//! reactors (epoll/kqueue/IOCP), TUN adapters, UDP sockets, timer wheel,
//! SPSC ring buffers, and the buffer pool.

pub mod event;
pub mod pool;
pub mod ring;
pub mod timer;

#[cfg(unix)]
pub mod reactor;

#[cfg(unix)]
pub mod socket;

#[cfg(unix)]
pub mod tun;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod bsd;

pub use event::Event;
pub use event::Interest;
pub use event::Tag;
pub use event::Token;
pub use pool::PacketPool;
pub use pool::PoolStats;
pub use ring::Consumer;
pub use ring::Producer;
pub use ring::SpscRing;
pub use timer::FiredTimer;
pub use timer::TimerId;
pub use timer::TimerWheel;

#[cfg(unix)]
pub use reactor::RawSource;
#[cfg(unix)]
pub use reactor::Reactor;
#[cfg(unix)]
pub use socket::UdpSocket;
#[cfg(unix)]
pub use tun::Tun;

#[cfg(target_os = "linux")]
pub use linux::EpollReactor;
#[cfg(target_os = "linux")]
pub use linux::LinuxTun;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use bsd::KqueueReactor;

#[cfg(target_os = "macos")]
pub use bsd::MacosTun;
