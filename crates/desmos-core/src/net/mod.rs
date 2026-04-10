//! Network interface discovery and monitoring.
//!
//! `list()` enumerates every host interface with name, MAC address,
//! IPv4 / IPv6 addresses, and link flags. `watch()` (Linux-only for
//! now) opens a netlink socket and emits events on link up / down.
//!
//! Linux-first: list() uses a hybrid of `/sys/class/net` (for names,
//! MAC, operstate, flags — no FFI needed) and a hand-declared
//! `getifaddrs` FFI for per-interface IP addresses. Non-Linux Unix
//! platforms fall back to `getifaddrs`-only and skip MAC; Windows
//! returns `NotImplemented` until the cross-platform phase (Task 41+).

pub mod iface;

#[cfg(target_os = "linux")]
pub mod watcher;

pub use iface::list;
pub use iface::IfaceError;
pub use iface::IfaceFlags;
pub use iface::NetworkInterface;

#[cfg(target_os = "linux")]
pub use watcher::watch;
#[cfg(target_os = "linux")]
pub use watcher::InterfaceEvent;
#[cfg(target_os = "linux")]
pub use watcher::NetlinkWatcher;
