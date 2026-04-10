//! Linux epoll reactor implementation.
//!
//! No `libc` crate: the four required system calls are declared as
//! `extern "C"` bindings directly against the platform libc, and the
//! `epoll_event` struct layout is reproduced from `<sys/epoll.h>`. This
//! keeps us within the 5-crate runtime budget.
//!
//! # Safety audit
//!
//! Every syscall is wrapped in a safe method. Internal `unsafe` blocks
//! carry a SAFETY comment describing the argument contract and the
//! invariants that make the call sound.

use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

use crate::event::Event;
use crate::event::Interest;
use crate::event::Token;
use crate::reactor::Reactor;

// ---- syscall constants (from <sys/epoll.h>) ---------------------------------

const EPOLL_CLOEXEC: i32 = 0o2_000_000;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

// ---- epoll_event struct layout ---------------------------------------------
//
// The struct is `__attribute__((packed))` on x86_64 so the kernel sees a
// 12-byte frame (u32 events | u64 data). Every other Linux architecture
// keeps natural alignment, yielding 16 bytes with 4 bytes of padding.

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    _pad: u32,
    data: u64,
}

impl EpollEvent {
    fn new(events: u32, data: u64) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self { events, data }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { events, _pad: 0, data }
        }
    }
}

// ---- extern bindings --------------------------------------------------------

extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
    fn close(fd: i32) -> i32;
}

// ---- EpollReactor -----------------------------------------------------------

pub struct EpollReactor {
    epfd: RawFd,
    event_buf: Vec<EpollEvent>,
}

impl EpollReactor {
    /// Create a new epoll instance with `EPOLL_CLOEXEC`.
    pub fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 accepts an integer flag mask and returns
        // a file descriptor on success or -1 on failure.
        let epfd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { epfd, event_buf: Vec::with_capacity(64) })
    }

    /// Raw file descriptor of the epoll instance. Exposed for callers that
    /// need to compose it with another reactor (e.g. signal-fd integration).
    pub fn as_raw_fd(&self) -> RawFd {
        self.epfd
    }

    fn ctl(&self, op: i32, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        let mut ev = EpollEvent::new(interest_to_epoll_mask(interest), token.0);
        // SAFETY: `self.epfd` is a live epoll fd. `fd` is supplied by the
        // caller; any invalid fd or duplicate registration is surfaced as an
        // errno. `&mut ev` points at a stack-allocated EpollEvent whose
        // lifetime extends past the syscall.
        let rc = unsafe { epoll_ctl(self.epfd, op, fd, &mut ev) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for EpollReactor {
    fn drop(&mut self) {
        if self.epfd >= 0 {
            // SAFETY: we own the fd exclusively and are releasing it now.
            unsafe {
                close(self.epfd);
            }
        }
    }
}

impl Reactor for EpollReactor {
    fn register(&mut self, source: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        self.ctl(EPOLL_CTL_ADD, source, token, interest)
    }

    fn reregister(&mut self, source: RawFd, token: Token, interest: Interest) -> io::Result<()> {
        self.ctl(EPOLL_CTL_MOD, source, token, interest)
    }

    fn deregister(&mut self, source: RawFd) -> io::Result<()> {
        // EPOLL_CTL_DEL still expects a non-null event pointer on older
        // kernels (< 2.6.9). We pass a zeroed event to stay compatible.
        let mut ev = EpollEvent::new(0, 0);
        // SAFETY: same contract as ctl; we do not read `ev` back.
        let rc = unsafe { epoll_ctl(self.epfd, EPOLL_CTL_DEL, source, &mut ev) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<usize> {
        let timeout_ms = match timeout {
            None => -1i32,
            Some(d) => d.as_millis().min(i32::MAX as u128) as i32,
        };

        if self.event_buf.capacity() < 64 {
            self.event_buf.reserve(64);
        }
        let cap = self.event_buf.capacity();

        // SAFETY: `event_buf.as_mut_ptr()` points at a live allocation with
        // capacity for at least `cap` EpollEvent entries. The kernel fills
        // the first `n` (where n is the return value) and we `set_len(n)`
        // only on success so no uninitialised memory is observed.
        let n =
            unsafe { epoll_wait(self.epfd, self.event_buf.as_mut_ptr(), cap as i32, timeout_ms) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        // SAFETY: the kernel returned `n` initialised EpollEvent structs at
        // the head of `event_buf`. They are plain old data so no drop glue
        // runs on the previous (uninitialised) tail.
        unsafe {
            self.event_buf.set_len(n as usize);
        }

        events.clear();
        events.reserve(n as usize);
        for ev in &self.event_buf {
            // SAFETY (x86_64): `ev` may be unaligned because EpollEvent is
            // `#[repr(packed)]` on this arch. `read_unaligned` is the only
            // sound way to copy the fields out.
            let (events_bits, data) = unsafe {
                let events_bits = core::ptr::addr_of!(ev.events).read_unaligned();
                let data = core::ptr::addr_of!(ev.data).read_unaligned();
                (events_bits, data)
            };
            events
                .push(Event { token: Token(data), readiness: epoll_mask_to_interest(events_bits) });
        }
        Ok(events.len())
    }
}

fn interest_to_epoll_mask(interest: Interest) -> u32 {
    let mut m = 0u32;
    if interest.is_readable() {
        m |= EPOLLIN | EPOLLRDHUP;
    }
    if interest.is_writable() {
        m |= EPOLLOUT;
    }
    m
}

fn epoll_mask_to_interest(mask: u32) -> Interest {
    let mut i = Interest::EMPTY;
    if mask & (EPOLLIN | EPOLLRDHUP) != 0 {
        i |= Interest::READABLE;
    }
    if mask & EPOLLOUT != 0 {
        i |= Interest::WRITABLE;
    }
    if mask & (EPOLLERR | EPOLLHUP) != 0 {
        // Surface hangups as readable so the consumer reads EOF or errno.
        i |= Interest::READABLE;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interest_mask_roundtrip() {
        let m = interest_to_epoll_mask(Interest::READABLE | Interest::WRITABLE);
        assert!(m & EPOLLIN != 0);
        assert!(m & EPOLLOUT != 0);
        let back = epoll_mask_to_interest(m);
        assert!(back.is_readable());
        assert!(back.is_writable());
    }

    #[test]
    fn hangup_maps_to_readable() {
        let i = epoll_mask_to_interest(EPOLLHUP);
        assert!(i.is_readable());
    }
}
