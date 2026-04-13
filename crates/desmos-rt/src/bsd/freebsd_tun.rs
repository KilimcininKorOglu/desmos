//! FreeBSD TUN adapter via `/dev/tunN`.
//!
//! Opens a FreeBSD tun device directly via the cloning `/dev/tunN`
//! path. The resulting interface is point-to-point mode by default
//! (no `TUNSIFHEAD`), so reads and writes carry raw IP packets
//! without any address-family header — the same contract the Linux
//! `IFF_TUN | IFF_NO_PI` adapter provides.
//!
//! The interface is created in non-blocking mode (`O_NONBLOCK` via
//! `fcntl`) with `FD_CLOEXEC`. Dropping the `FreeBsdTun` closes
//! the fd, which tears down the kernel interface (non-persist mode).
//!
//! # Privilege
//!
//! Opening `/dev/tunN` requires root or membership in the `wheel`
//! group (with appropriate devfs rules). Integration tests are
//! gated behind `#[ignore]`.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use crate::tun::Tun;

// ---- Constants (POSIX / FreeBSD) -------------------------------------------

/// `O_RDWR` — same on all BSDs and Linux.
const O_RDWR: i32 = 2;
/// `O_NONBLOCK` on FreeBSD / macOS.
const O_NONBLOCK: i32 = 0x0004;
/// `F_GETFL` for fcntl.
const F_GETFL: i32 = 3;
/// `F_SETFL` for fcntl.
const F_SETFL: i32 = 4;
/// `F_SETFD` for fcntl.
const F_SETFD: i32 = 2;
/// `FD_CLOEXEC`.
const FD_CLOEXEC: i32 = 1;

/// Maximum device path length: `/dev/tun` + up to 10 digits + NUL.
const MAX_PATH_LEN: usize = 32;

// ---- FFI declarations ------------------------------------------------------

// SAFETY: standard POSIX syscall wrappers. Every call site checks
// return values and maps errors via `io::Error::last_os_error()`.
extern "C" {
    fn open(path: *const u8, flags: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

// ---- FreeBsdTun ------------------------------------------------------------

/// FreeBSD `/dev/tunN` TUN adapter.
pub struct FreeBsdTun {
    fd: RawFd,
    name: String,
}

impl FreeBsdTun {
    /// Create a new TUN device by opening `/dev/tun{unit}`.
    ///
    /// `unit` selects the interface number: `0` → `tun0`, `1` →
    /// `tun1`, etc. The kernel creates the interface on open and
    /// destroys it when the fd is closed.
    ///
    /// Requires root or appropriate devfs permissions.
    pub fn create(unit: u32) -> io::Result<Self> {
        let mut path_buf = [0u8; MAX_PATH_LEN];
        let path_len = write_dev_path(&mut path_buf, unit)?;
        let path_ptr = path_buf[..path_len].as_ptr();

        // Step 1: open the device.
        // SAFETY: path_ptr points to a valid NUL-terminated C string.
        let fd = unsafe { open(path_ptr, O_RDWR) };
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
        // Step 2: set non-blocking.
        let flags = unsafe { fcntl(fd, F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Step 3: set CLOEXEC.
        if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let name = format!("tun{unit}");
        Ok(Self { fd, name })
    }
}

impl Drop for FreeBsdTun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own this fd and it is valid.
            unsafe { close(self.fd) };
        }
    }
}

impl AsRawFd for FreeBsdTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Tun for FreeBsdTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // FreeBSD tun in point-to-point mode (no TUNSIFHEAD)
        // delivers raw IP packets directly — no header to strip.
        // SAFETY: buf is a valid mutable slice.
        let n = unsafe { read(self.fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Raw IP packet — no header to prepend.
        // SAFETY: buf is a valid slice.
        let n = unsafe { write(self.fd, buf.as_ptr(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

// ---- Helpers ---------------------------------------------------------------

/// Write `/dev/tun{unit}\0` into `buf`. Returns the total length
/// including the NUL terminator.
fn write_dev_path(buf: &mut [u8; MAX_PATH_LEN], unit: u32) -> io::Result<usize> {
    let prefix = b"/dev/tun";
    let mut pos = prefix.len();
    buf[..pos].copy_from_slice(prefix);

    // Write the unit number as decimal digits.
    if unit == 0 {
        if pos >= MAX_PATH_LEN - 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path overflow"));
        }
        buf[pos] = b'0';
        pos += 1;
    } else {
        // Extract digits in reverse, then reverse them.
        let start = pos;
        let mut n = unit;
        while n > 0 {
            if pos >= MAX_PATH_LEN - 1 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "path overflow"));
            }
            buf[pos] = b'0' + (n % 10) as u8;
            pos += 1;
            n /= 10;
        }
        buf[start..pos].reverse();
    }

    // NUL terminator.
    buf[pos] = 0;
    pos += 1;
    Ok(pos)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_path_unit_zero() {
        let mut buf = [0u8; MAX_PATH_LEN];
        let len = write_dev_path(&mut buf, 0).unwrap();
        assert_eq!(&buf[..len], b"/dev/tun0\0");
    }

    #[test]
    fn dev_path_unit_single_digit() {
        let mut buf = [0u8; MAX_PATH_LEN];
        let len = write_dev_path(&mut buf, 7).unwrap();
        assert_eq!(&buf[..len], b"/dev/tun7\0");
    }

    #[test]
    fn dev_path_unit_multi_digit() {
        let mut buf = [0u8; MAX_PATH_LEN];
        let len = write_dev_path(&mut buf, 42).unwrap();
        assert_eq!(&buf[..len], b"/dev/tun42\0");
    }

    #[test]
    fn dev_path_unit_large() {
        let mut buf = [0u8; MAX_PATH_LEN];
        let len = write_dev_path(&mut buf, 12345).unwrap();
        assert_eq!(&buf[..len], b"/dev/tun12345\0");
    }

    #[test]
    fn dev_path_max_u32() {
        let mut buf = [0u8; MAX_PATH_LEN];
        let len = write_dev_path(&mut buf, u32::MAX).unwrap();
        // /dev/tun4294967295\0 = 19 chars + NUL = 20
        assert_eq!(&buf[..len], b"/dev/tun4294967295\0");
    }

    // ---- Integration tests (require root + FreeBSD) --------------------

    #[test]
    #[ignore = "needs root on FreeBSD"]
    #[cfg(target_os = "freebsd")]
    fn create_tun_and_read_name() {
        let tun = FreeBsdTun::create(99).unwrap();
        assert_eq!(tun.name(), "tun99");
        assert!(tun.as_raw_fd() >= 0);
    }

    #[test]
    #[ignore = "needs root on FreeBSD"]
    #[cfg(target_os = "freebsd")]
    fn create_tun_is_non_blocking() {
        let tun = FreeBsdTun::create(98).unwrap();
        let flags = unsafe { fcntl(tun.as_raw_fd(), F_GETFL, 0) };
        assert!(flags & O_NONBLOCK != 0, "expected O_NONBLOCK set");
    }
}
