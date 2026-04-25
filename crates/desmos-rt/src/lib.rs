//! Desmos hand-rolled async runtime.
//!
//! The only crate with `unsafe` syscall FFI. Provides platform-specific
//! reactors (epoll/kqueue/IOCP), TUN adapters, UDP sockets, timer wheel,
//! SPSC ring buffers, and the buffer pool.

pub mod event;
pub mod pool;
pub mod ring;
pub mod timer;

pub mod reactor;

pub mod signal;
pub mod socket;

pub mod tun;

#[cfg(unix)]
pub mod priv_drop;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod bsd;

#[cfg(target_os = "windows")]
pub mod windows;

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

pub use reactor::RawSource;
pub use reactor::Reactor;
pub use socket::UdpSocket;
pub use tun::Tun;

#[cfg(unix)]
pub use priv_drop::DropConfig;
#[cfg(unix)]
pub use priv_drop::Privileged;
#[cfg(unix)]
pub use priv_drop::Unprivileged;

#[cfg(target_os = "linux")]
pub use linux::EpollReactor;
#[cfg(target_os = "linux")]
pub use linux::LinuxTun;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use bsd::KqueueReactor;

#[cfg(target_os = "macos")]
pub use bsd::MacosTun;

#[cfg(target_os = "freebsd")]
pub use bsd::FreeBsdTun;

#[cfg(target_os = "windows")]
pub use windows::IocpReactor;
#[cfg(target_os = "windows")]
pub use windows::WintunTun;
