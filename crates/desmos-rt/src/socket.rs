//! Non-blocking UDP socket with optional per-interface egress binding.
//!
//! Wraps `socket2::Socket` so the rest of the runtime never has to reach
//! for platform-specific setsockopts. `bind_on_interface` is Linux-only
//! for now (via `SO_BINDTODEVICE`); macOS / BSD `IP_BOUND_IF` and
//! Windows `SIO_SET_INTERFACE` land in Phase 6.

use std::io;
use std::net::SocketAddr;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::RawFd;

use socket2::Domain;
use socket2::Protocol;
use socket2::Socket as Sock2Socket;
use socket2::Type;

#[derive(Debug)]
pub struct UdpSocket {
    inner: std::net::UdpSocket,
    bound_device: Option<String>,
}

impl UdpSocket {
    /// Bind a non-blocking UDP socket to `addr`. Sets `SO_REUSEADDR` so
    /// restarts do not have to wait for `TIME_WAIT` to expire.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let sock = new_socket(addr)?;
        sock.bind(&addr.into())?;
        Ok(Self { inner: sock.into(), bound_device: None })
    }

    /// Bind a UDP socket and restrict its egress to `interface`
    /// (Linux `SO_BINDTODEVICE`). The socket itself is bound to
    /// `0.0.0.0:0` so the kernel picks an ephemeral port.
    ///
    /// Requires `CAP_NET_RAW` on interfaces other than `lo`.
    #[cfg(target_os = "linux")]
    pub fn bind_on_interface(interface: &str) -> io::Result<Self> {
        let addr: SocketAddr = "0.0.0.0:0".parse().expect("valid literal");
        let sock = new_socket(addr)?;
        crate::linux::bind_device::bind_to_device(&sock, interface)?;
        sock.bind(&addr.into())?;
        Ok(Self { inner: sock.into(), bound_device: Some(interface.to_string()) })
    }

    /// Local address the kernel assigned to this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Interface name this socket was bound to (Linux only), or `None`.
    pub fn bound_device(&self) -> Option<&str> {
        self.bound_device.as_deref()
    }

    /// Non-blocking receive. Returns `WouldBlock` when no packet is ready.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    /// Non-blocking send.
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, addr)
    }

    /// Hand out a borrow of the underlying `std::net::UdpSocket` so tests
    /// and the few call sites that already speak that API can avoid a
    /// round-trip through the wrapper.
    pub fn as_std(&self) -> &std::net::UdpSocket {
        &self.inner
    }
}

#[cfg(unix)]
impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

fn new_socket(addr: SocketAddr) -> io::Result<Sock2Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Sock2Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    #[cfg(target_os = "windows")]
    disable_udp_connreset_raw(std::os::windows::io::AsRawSocket::as_raw_socket(&sock))?;
    Ok(sock)
}

/// Disable the Windows `SIO_UDP_CONNRESET` behavior on a bound UDP
/// socket. On Windows, a UDP `send_to` targeting a closed peer port
/// triggers an ICMP "port unreachable", and the next `recv_from`
/// returns `WSAECONNRESET` (`os error 10054`, "An existing connection
/// was forcibly closed"). Unix silently drops the ICMP and `recv_from`
/// continues to block until a real packet arrives or a timeout fires.
///
/// This function makes Windows match Unix by turning the ioctl off.
/// It is safe to call on any UDP socket on any platform — on non-Windows
/// it is a no-op.
///
/// Idempotent; callers that cannot prove the socket was created via
/// [`UdpSocket::bind`] (e.g. p2p helpers that accept
/// `std::net::UdpSocket` from external code) should call this at entry
/// to ensure consistent behavior.
pub fn disable_udp_connreset(sock: &std::net::UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        disable_udp_connreset_raw(sock.as_raw_socket())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = sock;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn disable_udp_connreset_raw(raw: std::os::windows::io::RawSocket) -> io::Result<()> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr;

    // IOC_IN | IOC_VENDOR | 12
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    // SOCKET is `uintptr_t` in winsock2.h; `RawSocket` is `u64` on 64-bit
    // Windows and `u32` on 32-bit. Casting through `usize` matches the
    // platform pointer width.
    #[allow(non_snake_case)]
    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const c_void,
            cbInBuffer: u32,
            lpvOutBuffer: *mut c_void,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut c_void,
            lpCompletionRoutine: *mut c_void,
        ) -> i32;
    }

    let new_value: u32 = 0; // FALSE = disable
    let mut bytes_returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            raw as usize,
            SIO_UDP_CONNRESET,
            &new_value as *const u32 as *const c_void,
            size_of::<u32>() as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_for_readable(sock: &std::net::UdpSocket, timeout_ms: u64) -> io::Result<()> {
        use std::io::ErrorKind;
        use std::time::Duration;
        use std::time::Instant;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut probe = [0u8; 1];
        loop {
            match sock.peek(&mut probe) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(ErrorKind::TimedOut, "not readable"));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[test]
    fn bind_loopback_assigns_ephemeral_port() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let s = UdpSocket::bind(addr).unwrap();
        let local = s.local_addr().unwrap();
        assert_eq!(local.ip(), addr.ip());
        assert_ne!(local.port(), 0, "kernel should have picked a port");
        assert!(s.bound_device().is_none());
    }

    #[test]
    fn send_to_and_recv_from_round_trip_on_loopback() {
        let a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let b_addr = b.local_addr().unwrap();
        let sent = a.send_to(b"ping", b_addr).unwrap();
        assert_eq!(sent, 4);
        wait_for_readable(b.as_std(), 500).expect("b should become readable");
        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.local_addr().unwrap());
    }

    #[test]
    fn bind_defaults_to_non_blocking() {
        let s = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let err = s.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_on_lo_reports_device() {
        // `lo` does not require CAP_NET_RAW, so this exercises the
        // SO_BINDTODEVICE path in unprivileged CI.
        let s = match UdpSocket::bind_on_interface("lo") {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("unexpected error: {e}"),
        };
        assert_eq!(s.bound_device(), Some("lo"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_on_empty_interface_errors() {
        let err = UdpSocket::bind_on_interface("").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
