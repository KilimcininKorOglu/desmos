//! Thin wrapper around `SO_BINDTODEVICE` for Linux.
//!
//! `socket2::Socket::bind_device` already does the syscall; this module
//! exists to keep the Linux-specific call site out of `src/socket.rs` so
//! later phases can add macOS `IP_BOUND_IF` and Windows `SIO_SET_INTERFACE`
//! variants without touching the common code.
//!
//! Note: `SO_BINDTODEVICE` requires `CAP_NET_RAW` (or root) on every
//! interface except `lo`. Errors surface verbatim via `io::Error`.

use std::io;

use socket2::Socket;

pub fn bind_to_device(sock: &Socket, interface: &str) -> io::Result<()> {
    if interface.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bind_to_device: interface name is empty",
        ));
    }
    if interface.as_bytes().len() >= 16 {
        // IFNAMSIZ - 1. Kernel rejects longer names with ENODEV.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bind_to_device: interface name longer than IFNAMSIZ - 1",
        ));
    }
    sock.bind_device(Some(interface.as_bytes()))
}
