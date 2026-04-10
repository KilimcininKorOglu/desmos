//! Cross-platform TUN adapter trait.
//!
//! Concrete implementations live in per-OS submodules
//! (`linux::LinuxTun`, future `macos::UtunTun`, future `windows::WintunTun`).
//! Upper layers consume only this trait so the domain code never has to
//! ask what kernel it is talking to.

use std::io;

#[cfg(unix)]
use std::os::fd::AsRawFd;

/// A layer-3 tunnel interface (no Ethernet framing). Implementations send
/// and receive raw IPv4 packets (IPv6 may arrive once v1.1 lands).
#[cfg(unix)]
pub trait Tun: Send + AsRawFd {
    /// Kernel-assigned interface name (e.g. `desmos0`).
    fn name(&self) -> &str;

    /// Read one IPv4 packet from the kernel into `buf`. The return value
    /// is the number of bytes written into `buf`. `WouldBlock` means no
    /// packet is ready yet; the reactor will wake us when one arrives.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one IPv4 packet to the kernel. Short writes are not possible
    /// on a TUN device: either the entire packet is accepted or `Err` is
    /// returned.
    fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
}
