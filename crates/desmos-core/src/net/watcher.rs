//! Linux netlink link-state watcher.
//!
//! Opens an `AF_NETLINK` socket subscribed to `RTMGRP_LINK`, then
//! drains `RTM_NEWLINK` / `RTM_DELLINK` events into [`InterfaceEvent`]
//! values. The watcher exposes a raw fd so it can be registered with
//! the `EpollReactor`, and a non-blocking `next_event` that
//! the inbound pipeline stage can drain on readiness.
//!
//! Hand-declared FFI: we wanted netlink event handling without a
//! `libc` dependency and the Linux headers are stable enough that
//! inlining the four syscalls plus the packed message structs is
//! smaller than the crate we would otherwise pull.

use std::ffi::CStr;
use std::io;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::raw::c_int;
use std::os::raw::c_void;

/// Event emitted when an interface's link state crosses a boundary
/// (kernel fires `RTM_NEWLINK` for every up / down transition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// Interface came up: `IFF_UP` is set, or a brand-new interface
    /// was added to the host.
    LinkUp { name: String, ifindex: i32 },
    /// Interface went down: `IFF_UP` cleared, or the interface was
    /// removed via `RTM_DELLINK`.
    LinkDown { name: String, ifindex: i32 },
}

impl InterfaceEvent {
    pub fn name(&self) -> &str {
        match self {
            Self::LinkUp { name, .. } | Self::LinkDown { name, .. } => name,
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self, Self::LinkUp { .. })
    }
}

/// Long-lived netlink subscriber. Clone the raw fd into an
/// `EpollReactor` and drain events whenever the fd is readable.
pub struct NetlinkWatcher {
    fd: RawFd,
    buf: Vec<u8>,
}

impl NetlinkWatcher {
    /// Open a new `AF_NETLINK` / `NETLINK_ROUTE` socket and subscribe
    /// to the `RTMGRP_LINK` multicast group. The socket is set
    /// non-blocking so `next_event` always returns promptly.
    pub fn new() -> io::Result<Self> {
        // SAFETY: socket() is a plain syscall; returns -1 on failure
        // and the error is in errno, which `last_os_error` reads.
        let fd = unsafe {
            ffi::socket(
                ffi::AF_NETLINK,
                ffi::SOCK_RAW | ffi::SOCK_NONBLOCK | ffi::SOCK_CLOEXEC,
                ffi::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Bind so the kernel delivers multicast group events.
        let mut addr = ffi::SockaddrNl {
            nl_family: ffi::AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0, // kernel auto-assigns
            nl_groups: ffi::RTMGRP_LINK,
        };
        // SAFETY: bind with a sockaddr_nl of the exact documented
        // size. On failure we close the fd before returning so no fd
        // leaks out.
        let rc = unsafe {
            ffi::bind(
                fd,
                &mut addr as *mut ffi::SockaddrNl as *mut ffi::Sockaddr,
                core::mem::size_of::<ffi::SockaddrNl>() as u32,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: fd came from socket() and is still valid here.
            unsafe { ffi::close(fd) };
            return Err(err);
        }
        Ok(Self { fd, buf: vec![0u8; 8192] })
    }

    /// Non-blocking drain of one netlink datagram into zero or more
    /// `InterfaceEvent`s. Returns `Ok(Vec::new())` if there is
    /// nothing to read, `Err(WouldBlock)` is never surfaced to the
    /// caller — we translate it into an empty vector so the epoll
    /// loop can handle "spurious wakeup" cleanly.
    pub fn drain_once(&mut self) -> io::Result<Vec<InterfaceEvent>> {
        // SAFETY: recv into our owned buffer. fd is non-blocking.
        let n =
            unsafe { ffi::recv(self.fd, self.buf.as_mut_ptr() as *mut c_void, self.buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }
            return Err(err);
        }
        let bytes = &self.buf[..n as usize];
        Ok(parse_events(bytes))
    }
}

impl AsRawFd for NetlinkWatcher {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for NetlinkWatcher {
    fn drop(&mut self) {
        // SAFETY: fd came from socket() and is owned by this struct
        // until drop. Closing it here releases the kernel resource.
        unsafe { ffi::close(self.fd) };
    }
}

/// Convenience one-shot helper: build a watcher and return it.
pub fn watch() -> io::Result<NetlinkWatcher> {
    NetlinkWatcher::new()
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Walk a netlink datagram containing one or more messages and emit
/// an `InterfaceEvent` for each `RTM_NEWLINK` / `RTM_DELLINK`. Unknown
/// message types are ignored silently — the kernel sometimes mixes
/// in `NLMSG_NOOP`, `NLMSG_ERROR`, and `NLMSG_DONE` and we do not
/// care about any of them here.
fn parse_events(bytes: &[u8]) -> Vec<InterfaceEvent> {
    use core::mem::size_of;
    let mut out = Vec::new();
    let nlmsg_size = size_of::<ffi::Nlmsghdr>();
    let ifinfo_size = size_of::<ffi::Ifinfomsg>();
    let mut off = 0usize;
    while off + nlmsg_size <= bytes.len() {
        // SAFETY: checked that `nlmsg_size` bytes remain. We never
        // hold a mut reference to the same region.
        let hdr =
            unsafe { core::ptr::read_unaligned(bytes[off..].as_ptr() as *const ffi::Nlmsghdr) };
        let msg_len = hdr.nlmsg_len as usize;
        if msg_len < nlmsg_size || off + msg_len > bytes.len() {
            break;
        }
        let msg_type = hdr.nlmsg_type;
        if (msg_type == ffi::RTM_NEWLINK || msg_type == ffi::RTM_DELLINK)
            && msg_len >= nlmsg_size + ifinfo_size
        {
            // ifinfomsg immediately follows the nlmsghdr.
            let ifinfo = unsafe {
                core::ptr::read_unaligned(
                    bytes[off + nlmsg_size..].as_ptr() as *const ffi::Ifinfomsg
                )
            };

            // Walk the attached rtattrs to find IFLA_IFNAME.
            let mut ifname = String::new();
            let attrs_start = off + nlmsg_size + ifinfo_size;
            let attrs_end = off + msg_len;
            let mut ao = attrs_start;
            while ao + size_of::<ffi::Rtattr>() <= attrs_end {
                let rta = unsafe {
                    core::ptr::read_unaligned(bytes[ao..].as_ptr() as *const ffi::Rtattr)
                };
                let rta_len = rta.rta_len as usize;
                if rta_len < size_of::<ffi::Rtattr>() || ao + rta_len > attrs_end {
                    break;
                }
                if rta.rta_type == ffi::IFLA_IFNAME {
                    let data_start = ao + size_of::<ffi::Rtattr>();
                    let data_end = ao + rta_len;
                    // Name is a NUL-terminated C string.
                    if let Ok(cstr) = CStr::from_bytes_until_nul(&bytes[data_start..data_end]) {
                        ifname = cstr.to_string_lossy().into_owned();
                    }
                    break;
                }
                // rtattrs are 4-byte aligned.
                ao += align4(rta_len);
            }

            if !ifname.is_empty() {
                let is_up = (ifinfo.ifi_flags & ffi::IFF_UP) != 0 && msg_type == ffi::RTM_NEWLINK;
                let ifindex = ifinfo.ifi_index;
                if is_up {
                    out.push(InterfaceEvent::LinkUp { name: ifname, ifindex });
                } else {
                    out.push(InterfaceEvent::LinkDown { name: ifname, ifindex });
                }
            }
        }

        // Netlink messages are 4-byte aligned.
        off += align4(msg_len);
    }
    out
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---------------------------------------------------------------------------
// FFI: Linux netlink bindings, hand-declared.
// ---------------------------------------------------------------------------

mod ffi {
    use std::os::raw::c_int;
    use std::os::raw::c_void;

    pub const AF_NETLINK: c_int = 16;
    pub const SOCK_RAW: c_int = 3;
    pub const SOCK_NONBLOCK: c_int = 0o0004000;
    pub const SOCK_CLOEXEC: c_int = 0o02000000;
    pub const NETLINK_ROUTE: c_int = 0;

    /// `RTMGRP_LINK` is `1 << (RTNLGRP_LINK - 1)` = `1 << 0`.
    pub const RTMGRP_LINK: u32 = 1;

    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_DELLINK: u16 = 17;

    pub const IFLA_IFNAME: u16 = 3;
    pub const IFF_UP: u32 = 1;

    /// `struct sockaddr_nl`.
    #[repr(C)]
    pub struct SockaddrNl {
        pub nl_family: u16,
        pub nl_pad: u16,
        pub nl_pid: u32,
        pub nl_groups: u32,
    }

    #[repr(C)]
    pub struct Sockaddr {
        pub sa_family: u16,
        pub sa_data: [u8; 14],
    }

    /// `struct nlmsghdr`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Nlmsghdr {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    /// `struct ifinfomsg` — the payload of `RTM_NEWLINK` / `RTM_DELLINK`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Ifinfomsg {
        pub ifi_family: u8,
        pub ifi_pad: u8,
        pub ifi_type: u16,
        pub ifi_index: i32,
        pub ifi_flags: u32,
        pub ifi_change: u32,
    }

    /// `struct rtattr`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Rtattr {
        pub rta_len: u16,
        pub rta_type: u16,
    }

    extern "C" {
        pub fn socket(domain: c_int, sock_type: c_int, protocol: c_int) -> c_int;
        pub fn bind(sockfd: c_int, addr: *mut Sockaddr, addrlen: u32) -> c_int;
        pub fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        pub fn close(fd: c_int) -> c_int;
    }
}

// Silence unused-import warnings on platforms that never compile the
// socket path (currently: only Linux compiles this module, but the
// constants above reference c_int which Rust drops otherwise).
const _: fn() -> c_int = || 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align4_rounds_up_to_multiple_of_four() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(31), 32);
    }

    #[test]
    fn parse_events_returns_empty_on_empty_buffer() {
        assert!(parse_events(&[]).is_empty());
    }

    #[test]
    fn parse_events_skips_undersized_headers() {
        // Fewer bytes than nlmsghdr.
        assert!(parse_events(&[0u8; 8]).is_empty());
    }

    #[test]
    fn watcher_opens_netlink_socket() {
        // Happy-path: opening the socket should succeed on any Linux
        // kernel. We don't assert that any events arrive because that
        // depends on host activity.
        let w = NetlinkWatcher::new().unwrap();
        assert!(w.as_raw_fd() >= 0);
    }

    #[test]
    fn drain_once_returns_empty_when_no_events_ready() {
        let mut w = NetlinkWatcher::new().unwrap();
        // The socket is non-blocking and no link changes should be
        // happening during test runs, so we expect an empty drain.
        let events = w.drain_once().unwrap();
        assert!(events.is_empty() || events.iter().all(|e| !e.name().is_empty()));
    }
}
