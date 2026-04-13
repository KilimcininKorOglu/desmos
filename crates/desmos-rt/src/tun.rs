//! Cross-platform TUN adapter trait.
//!
//! Concrete implementations live in per-OS submodules:
//! - `linux::LinuxTun` — `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`
//! - `bsd::macos_tun::MacosTun` — macOS utun via `PF_SYSTEM`
//! - `windows::tun::WintunTun` — Wintun DLL session API
//!
//! Upper layers consume only this trait so the domain code never has to
//! ask what kernel it is talking to.

use std::io;

#[cfg(unix)]
use std::os::fd::AsRawFd;

/// A layer-3 tunnel interface (no Ethernet framing). Implementations send
/// and receive raw IP packets.
///
/// On Unix the trait requires [`AsRawFd`] so the fd can be registered
/// with the reactor (epoll / kqueue). On Windows Wintun handles its
/// own readiness internally, so the bound is relaxed to just [`Send`].
#[cfg(unix)]
pub trait Tun: Send + AsRawFd {
    /// Kernel-assigned interface name (e.g. `desmos0`).
    fn name(&self) -> &str;

    /// Read one IP packet from the kernel into `buf`. The return value
    /// is the number of bytes written into `buf`. `WouldBlock` means no
    /// packet is ready yet; the reactor will wake us when one arrives.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one IP packet to the kernel. Short writes are not possible
    /// on a TUN device: either the entire packet is accepted or `Err` is
    /// returned.
    fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
}

/// Windows variant — no `AsRawFd` bound. Wintun manages its own
/// internal ring buffer and wake-up mechanism.
#[cfg(windows)]
pub trait Tun: Send {
    /// Adapter name (e.g. `Desmos Tunnel`).
    fn name(&self) -> &str;

    /// Read one IP packet from the Wintun session into `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one IP packet to the Wintun session.
    fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
}
