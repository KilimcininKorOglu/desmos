//! Linux TUN device adapter.
//!
//! Opens `/dev/net/tun`, issues `ioctl(TUNSETIFF)` with `IFF_TUN |
//! IFF_NO_PI`, and wraps the returned file descriptor as a non-blocking
//! layer-3 tunnel. Pure hand-declared `extern "C"` bindings: no `libc`
//! crate.
//!
//! # Safety audit
//!
//! Every unsafe block has a SAFETY comment describing the argument
//! contract and the invariants that make the call sound.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use crate::tun::Tun;

// ---- syscall constants (Linux) ---------------------------------------------

const O_RDWR: i32 = 0o2;
const O_NONBLOCK: i32 = 0o4_000;
const O_CLOEXEC: i32 = 0o2_000_000;

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// `_IOW('T', 202, int)` — the kernel magic for TUNSETIFF. Architecture
/// independent on Linux.
const TUNSETIFF: u64 = 0x4004_54ca;

const IFNAMSIZ: usize = 16;

// ---- ifreq layout ----------------------------------------------------------

/// Rust mirror of `struct ifreq`. Total size is 40 bytes on every Linux
/// architecture: a 16-byte name field followed by a 24-byte union. We
/// only touch the first two bytes of the union (the flags) for TUNSETIFF.
#[repr(C)]
#[derive(Debug)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    union_bytes: [u8; 24],
}

impl Ifreq {
    fn with_flags(name: &str, flags: u16) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun: interface name too long",
            ));
        }
        if bytes.iter().any(|&b| b == 0 || b == b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun: interface name must not contain NUL or '/'",
            ));
        }
        let mut ifr = Self { name: [0; IFNAMSIZ], union_bytes: [0; 24] };
        ifr.name[..bytes.len()].copy_from_slice(bytes);
        // Flags live at offset 0 of the union as a native-endian u16.
        let flag_bytes = flags.to_ne_bytes();
        ifr.union_bytes[0] = flag_bytes[0];
        ifr.union_bytes[1] = flag_bytes[1];
        Ok(ifr)
    }
}

// ---- extern bindings -------------------------------------------------------

extern "C" {
    fn open(path: *const u8, flags: i32) -> i32;
    fn ioctl(fd: i32, request: u64, argp: *mut Ifreq) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

// ---- LinuxTun --------------------------------------------------------------

pub struct LinuxTun {
    fd: RawFd,
    name: String,
}

impl LinuxTun {
    /// Create a non-blocking TUN interface. The supplied `requested_name`
    /// is passed to the kernel; the actual assigned name (which may be
    /// truncated or auto-numbered) is read back from the ifreq after the
    /// ioctl and surfaced via [`LinuxTun::name`].
    ///
    /// Requires `CAP_NET_ADMIN` in the calling thread's namespace.
    pub fn create(requested_name: &str) -> io::Result<Self> {
        const TUN_DEV: &[u8] = b"/dev/net/tun\0";
        // SAFETY: TUN_DEV is a NUL-terminated byte literal. Flags are valid
        // Linux open flags. On failure we return immediately without
        // touching the returned value.
        let fd = unsafe { open(TUN_DEV.as_ptr(), O_RDWR | O_NONBLOCK | O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr = match Ifreq::with_flags(requested_name, IFF_TUN | IFF_NO_PI) {
            Ok(ifr) => ifr,
            Err(e) => {
                // SAFETY: we own the fd; releasing it to satisfy the error path.
                unsafe { close(fd) };
                return Err(e);
            }
        };

        // SAFETY: `fd` is the fd we just opened; `&mut ifr` points at a
        // stack-allocated Ifreq large enough for the kernel to read and
        // write back.
        let rc = unsafe { ioctl(fd, TUNSETIFF, &mut ifr as *mut Ifreq) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: we still own the fd; release before returning.
            unsafe { close(fd) };
            return Err(err);
        }

        let assigned = cstr_name(&ifr.name);
        Ok(Self { fd, name: assigned })
    }
}

fn cstr_name(buf: &[u8; IFNAMSIZ]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

impl Drop for LinuxTun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own the fd. The kernel removes the interface
            // automatically when the last fd is closed (non-persist mode).
            unsafe {
                close(self.fd);
            }
        }
    }
}

impl AsRawFd for LinuxTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Tun for LinuxTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: `buf` is a valid mutable slice; we pass its base pointer
        // and length so the kernel writes at most `buf.len()` bytes.
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
        // SAFETY: `buf` is a valid read-only slice; we pass its base pointer
        // and length so the kernel reads at most `buf.len()` bytes.
        let n = unsafe { write(self.fd, buf.as_ptr(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_rejects_long_name() {
        let too_long = "a".repeat(16);
        let err = Ifreq::with_flags(&too_long, IFF_TUN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ifreq_rejects_nul_or_slash() {
        assert!(Ifreq::with_flags("de/sm", IFF_TUN).is_err());
        assert!(Ifreq::with_flags("desm\0", IFF_TUN).is_err());
    }

    #[test]
    fn ifreq_name_round_trip() {
        let ifr = Ifreq::with_flags("desmos0", IFF_TUN | IFF_NO_PI).unwrap();
        assert_eq!(cstr_name(&ifr.name), "desmos0");
        // Flags bytes
        assert_eq!(ifr.union_bytes[0], (IFF_TUN | IFF_NO_PI) as u8);
        assert_eq!(ifr.union_bytes[1], ((IFF_TUN | IFF_NO_PI) >> 8) as u8);
    }

    #[test]
    fn ifreq_struct_is_forty_bytes() {
        assert_eq!(core::mem::size_of::<Ifreq>(), 40);
    }
}
