//! macOS utun TUN adapter.
//!
//! Opens a `utun` kernel control socket via `PF_SYSTEM` /
//! `SYSPROTO_CONTROL` and the `com.apple.net.utun_control`
//! control name. Each read/write carries a 4-byte address-family
//! header prepended by the kernel (`AF_INET = 2`, `AF_INET6 = 30`
//! on macOS), which this adapter strips on `recv` and prepends on
//! `send` so upper layers see raw IP packets — the same contract
//! the Linux `IFF_TUN | IFF_NO_PI` adapter provides.
//!
//! The interface is created in non-blocking mode (`O_NONBLOCK`
//! via `fcntl`) and `FD_CLOEXEC` so child processes do not
//! inherit it. Dropping the `MacosTun` closes the socket, which
//! tears down the kernel interface automatically (non-persist).
//!
//! # Privilege
//!
//! Creating a utun device requires root or the
//! `com.apple.networking.tun` entitlement. Tests that call
//! `MacosTun::create` are gated behind `#[ignore]` and run only
//! in a privileged CI environment.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::tun::Tun;

// ---- Constants -------------------------------------------------------------

/// `PF_SYSTEM` / `AF_SYSTEM` (macOS-specific).
const PF_SYSTEM: i32 = 32;
/// Datagram socket type.
const SOCK_DGRAM: i32 = 2;
/// System protocol for kernel control sockets.
const SYSPROTO_CONTROL: i32 = 2;

/// ioctl request: get control info by name.
/// `CTLIOCGINFO` on macOS = `_IOWR('N', 3, struct ctl_info)`.
/// Computed: direction=3 (RW), group='N'=0x4E, nr=3, size=100.
/// = `0xC064_4E03`.
const CTLIOCGINFO: u64 = 0xC064_4E03;

/// Maximum length of a kernel control name.
const MAX_KCTL_NAME: usize = 96;

/// `AF_INET` on macOS.
const AF_INET: u32 = 2;
/// `AF_INET6` on macOS.
const AF_INET6: u32 = 30;

/// Size of the address-family header the kernel prepends/expects.
const AF_HEADER_LEN: usize = 4;

/// `F_SETFL` for fcntl.
const F_SETFL: i32 = 4;
/// `F_GETFL` for fcntl.
const F_GETFL: i32 = 3;
/// `O_NONBLOCK` on macOS.
const O_NONBLOCK: i32 = 0x0004;
/// `F_SETFD` for fcntl.
const F_SETFD: i32 = 2;
/// `FD_CLOEXEC`.
const FD_CLOEXEC: i32 = 1;

/// `UTUN_CONTROL_NAME`.
const UTUN_CONTROL_NAME: &[u8; 26] = b"com.apple.net.utun_control";

// ---- FFI types -------------------------------------------------------------

/// Mirror of `struct ctl_info` from `<sys/kern_control.h>`.
/// 4-byte id + 96-byte name = 100 bytes.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; MAX_KCTL_NAME],
}

impl CtlInfo {
    fn for_utun() -> Self {
        let mut info = Self { ctl_id: 0, ctl_name: [0u8; MAX_KCTL_NAME] };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
        info
    }
}

/// Mirror of `struct sockaddr_ctl` from `<sys/kern_control.h>`.
///
/// ```text
/// u_char      sc_len;       /*  1 byte  */
/// u_char      sc_family;    /*  1 byte  */
/// u_int16_t   ss_sysaddr;   /*  2 bytes */
/// u_int32_t   sc_id;        /*  4 bytes */
/// u_int32_t   sc_unit;      /*  4 bytes */
/// u_int32_t   sc_reserved[5]; /* 20 bytes */
/// ```
///
/// Total: 32 bytes.
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

impl SockaddrCtl {
    fn new(ctl_id: u32, unit: u32) -> Self {
        Self {
            sc_len: core::mem::size_of::<Self>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: 2, // AF_SYS_CONTROL
            sc_id: ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        }
    }
}

// ---- FFI declarations ------------------------------------------------------

// SAFETY: standard POSIX / macOS syscall wrappers. Every call site
// checks return values and maps errors via `io::Error::last_os_error()`.
extern "C" {
    fn socket(domain: i32, socktype: i32, protocol: i32) -> i32;
    fn connect(fd: i32, addr: *const SockaddrCtl, addrlen: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn ioctl(fd: i32, request: u64, info: *mut CtlInfo) -> i32;
}

/// `SYSPROTO_CONTROL` level for getsockopt.
const SYSPROTO_CONTROL_LEVEL: i32 = 2;
/// `UTUN_OPT_IFNAME` option to retrieve the kernel-assigned name.
const UTUN_OPT_IFNAME: i32 = 2;

// ---- MacosTun --------------------------------------------------------------

/// macOS utun TUN adapter.
pub struct MacosTun {
    fd: RawFd,
    name: String,
}

impl MacosTun {
    /// Create a new utun device. `unit` selects the interface
    /// number: `0` → `utun0`, `1` → `utun1`, etc. The kernel
    /// increments the unit by one internally, so we pass
    /// `unit + 1` in `sc_unit` (unit=0 means "let the kernel
    /// pick" in some documentation, but `sc_unit = N` yields
    /// `utunN-1`).
    ///
    /// Requires root or the `com.apple.networking.tun` entitlement.
    pub fn create(unit: u32) -> io::Result<Self> {
        // Step 1: open a PF_SYSTEM control socket.
        // SAFETY: standard socket() call.
        let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // From here, any error must close fd.
        let result = Self::init(fd, unit);
        if result.is_err() {
            unsafe { close(fd) };
        }
        result
    }

    fn init(fd: RawFd, unit: u32) -> io::Result<Self> {
        // Step 2: look up the control ID for "com.apple.net.utun_control".
        let mut info = CtlInfo::for_utun();
        // SAFETY: ioctl with a valid CtlInfo pointer.
        let rc = unsafe { ioctl(fd, CTLIOCGINFO, &mut info) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Step 3: connect to the control with the desired unit.
        // sc_unit = unit + 1 because the kernel subtracts 1
        // internally (sc_unit=0 means "auto-assign").
        let addr = SockaddrCtl::new(info.ctl_id, unit + 1);
        // SAFETY: connect with a valid SockaddrCtl pointer.
        let rc = unsafe {
            connect(fd, &addr as *const SockaddrCtl, core::mem::size_of::<SockaddrCtl>() as u32)
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Step 4: retrieve the kernel-assigned interface name.
        let name = Self::get_ifname(fd)?;

        // Step 5: set non-blocking + CLOEXEC.
        let flags = unsafe { fcntl(fd, F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, name })
    }

    fn get_ifname(fd: RawFd) -> io::Result<String> {
        let mut name_buf = [0u8; 32];
        let mut name_len = name_buf.len() as u32;
        // SAFETY: getsockopt with valid buffer + length pointers.
        let rc = unsafe {
            getsockopt(
                fd,
                SYSPROTO_CONTROL_LEVEL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr(),
                &mut name_len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // name_len includes the NUL terminator.
        let len = name_len as usize;
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "empty utun name"));
        }
        // Strip trailing NUL if present.
        let end = if name_buf[len - 1] == 0 { len - 1 } else { len };
        let s = std::str::from_utf8(&name_buf[..end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utun name not utf-8"))?;
        Ok(s.to_string())
    }

    /// Detect the address family from the first byte of an IP
    /// packet: version nibble 4 → AF_INET, 6 → AF_INET6.
    fn af_from_packet(pkt: &[u8]) -> u32 {
        if pkt.is_empty() {
            return AF_INET;
        }
        match pkt[0] >> 4 {
            6 => AF_INET6,
            _ => AF_INET,
        }
    }
}

impl Drop for MacosTun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own this fd and it is valid.
            unsafe { close(self.fd) };
        }
    }
}

impl AsRawFd for MacosTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Tun for MacosTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Read into a temporary buffer that includes the 4-byte AF
        // header the kernel prepends.
        let total_len = buf.len() + AF_HEADER_LEN;
        let mut tmp = vec![0u8; total_len];
        // SAFETY: tmp is a valid buffer of total_len bytes.
        let n = unsafe { read(self.fd, tmp.as_mut_ptr(), total_len) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n <= AF_HEADER_LEN {
            // Packet too short to contain anything after the AF header.
            return Ok(0);
        }
        let payload_len = n - AF_HEADER_LEN;
        buf[..payload_len].copy_from_slice(&tmp[AF_HEADER_LEN..n]);
        Ok(payload_len)
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Prepend the 4-byte AF header.
        let af = Self::af_from_packet(buf);
        let total_len = AF_HEADER_LEN + buf.len();
        let mut tmp = vec![0u8; total_len];
        tmp[..AF_HEADER_LEN].copy_from_slice(&af.to_ne_bytes());
        tmp[AF_HEADER_LEN..].copy_from_slice(buf);
        // SAFETY: tmp is a valid buffer of total_len bytes.
        let n = unsafe { write(self.fd, tmp.as_ptr(), total_len) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n <= AF_HEADER_LEN {
            return Ok(0);
        }
        Ok(n - AF_HEADER_LEN)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctl_info_struct_is_100_bytes() {
        assert_eq!(core::mem::size_of::<CtlInfo>(), 100);
    }

    #[test]
    fn sockaddr_ctl_struct_is_32_bytes() {
        assert_eq!(core::mem::size_of::<SockaddrCtl>(), 32);
    }

    #[test]
    fn ctl_info_name_is_null_terminated() {
        let info = CtlInfo::for_utun();
        assert_eq!(&info.ctl_name[..26], UTUN_CONTROL_NAME);
        assert_eq!(info.ctl_name[26], 0);
    }

    #[test]
    fn sockaddr_ctl_fields() {
        let addr = SockaddrCtl::new(42, 3);
        assert_eq!(addr.sc_len, 32);
        assert_eq!(addr.sc_family, PF_SYSTEM as u8);
        assert_eq!(addr.ss_sysaddr, 2);
        assert_eq!(addr.sc_id, 42);
        assert_eq!(addr.sc_unit, 3);
    }

    #[test]
    fn af_detection_ipv4() {
        // IPv4 version nibble = 4 → 0x45 (version + IHL)
        assert_eq!(MacosTun::af_from_packet(&[0x45, 0, 0, 20]), AF_INET);
    }

    #[test]
    fn af_detection_ipv6() {
        // IPv6 version nibble = 6 → 0x60
        assert_eq!(MacosTun::af_from_packet(&[0x60, 0, 0, 0]), AF_INET6);
    }

    #[test]
    fn af_detection_empty_defaults_to_ipv4() {
        assert_eq!(MacosTun::af_from_packet(&[]), AF_INET);
    }

    #[test]
    fn af_detection_unknown_version_defaults_to_ipv4() {
        assert_eq!(MacosTun::af_from_packet(&[0x00]), AF_INET);
    }

    // ---- Integration tests (require root) --------------------------------

    #[test]
    #[ignore = "needs root or com.apple.networking.tun entitlement"]
    fn create_utun_and_read_name() {
        // Use a high unit number to avoid collisions with
        // existing utun interfaces (VPN clients, etc.).
        let tun = MacosTun::create(99).unwrap();
        assert!(tun.name().starts_with("utun"), "expected utunN, got: {}", tun.name());
        assert!(tun.as_raw_fd() >= 0);
    }

    #[test]
    #[ignore = "needs root or com.apple.networking.tun entitlement"]
    fn create_utun_is_non_blocking() {
        let tun = MacosTun::create(98).unwrap();
        let flags = unsafe { fcntl(tun.as_raw_fd(), F_GETFL, 0) };
        assert!(flags & O_NONBLOCK != 0, "expected O_NONBLOCK set");
    }
}
