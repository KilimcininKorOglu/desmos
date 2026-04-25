//! Per-interface egress binding on macOS via `IP_BOUND_IF`.
//!
//! Restricts a UDP socket's outbound traffic to a specific network
//! interface by setting the `IP_BOUND_IF` socket option with the
//! interface's index (obtained via `if_nametoindex`).

use std::io;

const IPPROTO_IP: i32 = 0;
const IP_BOUND_IF: i32 = 25;

extern "C" {
    fn if_nametoindex(ifname: *const u8) -> u32;
    fn setsockopt(sockfd: i32, level: i32, optname: i32, optval: *const u8, optlen: u32) -> i32;
}

pub fn bind_to_interface(fd: i32, interface: &str) -> io::Result<()> {
    if interface.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty interface name"));
    }

    let mut name_buf = [0u8; 64];
    if interface.len() >= name_buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
    }
    name_buf[..interface.len()].copy_from_slice(interface.as_bytes());

    let idx = unsafe { if_nametoindex(name_buf.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface not found: {interface}"),
        ));
    }

    let idx_bytes = idx.to_ne_bytes();
    let rc = unsafe {
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, idx_bytes.as_ptr(), idx_bytes.len() as u32)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_interface_errors() {
        let err = bind_to_interface(0, "").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn too_long_interface_errors() {
        let long = "a".repeat(100);
        let err = bind_to_interface(0, &long).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
