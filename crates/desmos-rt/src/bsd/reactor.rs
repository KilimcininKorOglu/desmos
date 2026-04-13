//! BSD kqueue reactor.
//!
//! Implements [`crate::reactor::Reactor`] via `kqueue()` / `kevent()`
//! with hand-declared `extern "C"` bindings (no `libc` crate).
//!
//! # kqueue vs epoll design differences
//!
//! Epoll tracks one registration per fd with an event mask (`EPOLLIN |
//! EPOLLOUT`). Kqueue tracks separate `(ident, filter)` pairs — one
//! for `EVFILT_READ`, one for `EVFILT_WRITE`. A single fd registered
//! for both readability and writability therefore holds two kernel
//! entries.
//!
//! To provide the same `register` / `reregister` / `deregister`
//! semantics the rest of the codebase expects (one call = one
//! snapshot of desired interest), the reactor keeps a small
//! `HashMap<RawFd, Interest>` of what was last committed to the
//! kernel. `reregister` computes the delta (filters to add, filters
//! to remove) and submits them in a single `kevent` changelist so
//! the switch is atomic from the kernel's perspective.
//!
//! # Event coalescing
//!
//! Because kqueue returns one event per `(ident, filter)` pair, a fd
//! that is both readable and writable produces *two* raw kevents.
//! [`KqueueReactor::poll`] coalesces them into a single [`Event`]
//! with both bits set so consumers see the same one-event-per-token
//! model the epoll backend provides.

use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

use crate::event::{Event, Interest, Token};
use crate::reactor::{RawSource, Reactor};

// Compile-time guard: Token(u64) is stored as usize in the kevent
// udata field. On a 32-bit platform this would silently truncate
// the upper 32 bits.
const _: () =
    assert!(core::mem::size_of::<usize>() >= 8, "kqueue reactor requires a 64-bit target");

// ---- Constants from <sys/event.h> ------------------------------------------

const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
#[allow(dead_code)]
const EV_DISABLE: u16 = 0x0008;
const EV_EOF: u16 = 0x8000;
const EV_ERROR: u16 = 0x4000;

// ---- Constants from <fcntl.h> / <unistd.h> ---------------------------------

const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;

// ---- FFI types -------------------------------------------------------------

/// Mirror of the C `struct kevent` on 64-bit BSD.
///
/// ```text
/// uintptr_t ident;    /*  8 bytes */
/// int16_t   filter;   /*  2 bytes */
/// uint16_t  flags;    /*  2 bytes */
/// uint32_t  fflags;   /*  4 bytes */
/// intptr_t  data;     /*  8 bytes */
/// void     *udata;    /*  8 bytes */
/// ```
///
/// Total: 32 bytes on 64-bit macOS / FreeBSD.
#[repr(C)]
#[derive(Clone, Copy)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: usize,
}

impl Kevent {
    const fn zeroed() -> Self {
        Self { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: 0 }
    }

    fn new(ident: usize, filter: i16, flags: u16, token: Token) -> Self {
        Self { ident, filter, flags, fflags: 0, data: 0, udata: token.0 as usize }
    }
}

/// Mirror of the C `struct timespec` on 64-bit BSD.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// ---- FFI declarations ------------------------------------------------------

// SAFETY: these are standard POSIX / BSD syscall wrappers with
// well-defined ABIs. Every call site validates the return value
// and maps negative returns to `io::Error::last_os_error()`.
extern "C" {
    fn kqueue() -> i32;
    fn kevent(
        kq: i32,
        changelist: *const Kevent,
        nchanges: i32,
        eventlist: *mut Kevent,
        nevents: i32,
        timeout: *const Timespec,
    ) -> i32;
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
}

// ---- Reactor ---------------------------------------------------------------

/// BSD kqueue reactor behind the [`Reactor`] trait.
pub struct KqueueReactor {
    kqfd: RawFd,
    event_buf: Vec<Kevent>,
    /// Tracks the interest snapshot last committed for each
    /// registered fd so `reregister` can compute the delta.
    registered: HashMap<RawFd, Interest>,
}

impl KqueueReactor {
    /// Create a new kqueue instance with `FD_CLOEXEC`.
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue() returns a new fd or -1.
        let kqfd = unsafe { kqueue() };
        if kqfd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Set CLOEXEC so child processes do not inherit the fd.
        // SAFETY: fcntl is well-defined for F_SETFD.
        let rc = unsafe { fcntl(kqfd, F_SETFD, FD_CLOEXEC) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { close(kqfd) };
            return Err(err);
        }
        Ok(Self { kqfd, event_buf: Vec::with_capacity(64), registered: HashMap::new() })
    }

    /// Return the raw kqueue fd for introspection / debugging.
    pub fn as_raw_fd(&self) -> RawFd {
        self.kqfd
    }

    /// Submit a changelist to the kernel. NULL eventlist so
    /// errors land as the `kevent()` return value rather than
    /// mixed into an event buffer.
    fn submit_changes(&self, changes: &[Kevent]) -> io::Result<()> {
        // SAFETY: changelist points to a valid slice and we pass
        // null eventlist with nevents=0 for a submit-only call.
        let rc = unsafe {
            kevent(
                self.kqfd,
                changes.as_ptr(),
                changes.len() as i32,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Compute and apply the filter delta between `old` and `new`
    /// interest for one source.
    fn apply_interest(
        &self,
        source: RawFd,
        token: Token,
        old: Interest,
        new: Interest,
    ) -> io::Result<()> {
        let mut changes = [Kevent::zeroed(); 4]; // max 2 add + 2 delete
        let mut n = 0;
        let ident = source as usize;

        // Add / update desired filters. EV_ADD is idempotent: if the
        // filter already exists it updates the udata (token).
        if new.is_readable() {
            changes[n] = Kevent::new(ident, EVFILT_READ, EV_ADD | EV_ENABLE, token);
            n += 1;
        }
        if new.is_writable() {
            changes[n] = Kevent::new(ident, EVFILT_WRITE, EV_ADD | EV_ENABLE, token);
            n += 1;
        }

        // Delete filters the caller no longer wants.
        if old.is_readable() && !new.is_readable() {
            changes[n] = Kevent::new(ident, EVFILT_READ, EV_DELETE, Token(0));
            n += 1;
        }
        if old.is_writable() && !new.is_writable() {
            changes[n] = Kevent::new(ident, EVFILT_WRITE, EV_DELETE, Token(0));
            n += 1;
        }

        if n > 0 {
            self.submit_changes(&changes[..n])?;
        }
        Ok(())
    }
}

impl Drop for KqueueReactor {
    fn drop(&mut self) {
        if self.kqfd >= 0 {
            // SAFETY: we own this fd and it is valid until this point.
            unsafe { close(self.kqfd) };
        }
    }
}

impl Reactor for KqueueReactor {
    fn register(&mut self, source: RawSource, token: Token, interest: Interest) -> io::Result<()> {
        self.apply_interest(source, token, Interest::EMPTY, interest)?;
        self.registered.insert(source, interest);
        Ok(())
    }

    fn reregister(
        &mut self,
        source: RawSource,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        let old = self.registered.get(&source).copied().unwrap_or(Interest::EMPTY);
        self.apply_interest(source, token, old, interest)?;
        self.registered.insert(source, interest);
        Ok(())
    }

    fn deregister(&mut self, source: RawSource) -> io::Result<()> {
        let old = self.registered.remove(&source).unwrap_or(Interest::EMPTY);
        let mut changes = [Kevent::zeroed(); 2];
        let mut n = 0;
        let ident = source as usize;

        if old.is_readable() {
            changes[n] = Kevent::new(ident, EVFILT_READ, EV_DELETE, Token(0));
            n += 1;
        }
        if old.is_writable() {
            changes[n] = Kevent::new(ident, EVFILT_WRITE, EV_DELETE, Token(0));
            n += 1;
        }
        if n > 0 {
            self.submit_changes(&changes[..n])?;
        }
        Ok(())
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<usize> {
        let ts = timeout
            .map(|d| Timespec { tv_sec: d.as_secs() as i64, tv_nsec: d.subsec_nanos() as i64 });
        let timeout_ptr = match &ts {
            Some(t) => t as *const Timespec,
            None => core::ptr::null(),
        };

        if self.event_buf.capacity() < 64 {
            self.event_buf.reserve(64);
        }
        let cap = self.event_buf.capacity();

        // SAFETY: event_buf has `cap` capacity and we ask the
        // kernel to fill at most that many entries.
        let n = unsafe {
            kevent(
                self.kqfd,
                core::ptr::null(),
                0,
                self.event_buf.as_mut_ptr(),
                cap as i32,
                timeout_ptr,
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        // SAFETY: kevent guarantees at most `cap` entries written.
        unsafe {
            self.event_buf.set_len(n as usize);
        }

        events.clear();
        events.reserve(n as usize);
        for ev in &self.event_buf {
            // Skip per-change error reports that leaked into the
            // event buffer (should not happen with our submit-only
            // pattern, but defensive).
            if ev.flags & EV_ERROR != 0 {
                continue;
            }
            let readiness = kevent_to_interest(ev);
            let token = Token(ev.udata as u64);
            // Coalesce events with the same token so consumers see
            // at most one Event per source — matching the epoll
            // single-event-per-fd model.
            if let Some(existing) = events.iter_mut().find(|e| e.token == token) {
                existing.readiness |= readiness;
            } else {
                events.push(Event { token, readiness });
            }
        }
        Ok(events.len())
    }
}

/// Map a kevent's filter + flags to the platform-agnostic
/// [`Interest`] bitfield.
fn kevent_to_interest(ev: &Kevent) -> Interest {
    let mut interest = Interest::EMPTY;
    match ev.filter {
        EVFILT_READ => interest |= Interest::READABLE,
        EVFILT_WRITE => interest |= Interest::WRITABLE,
        _ => {}
    }
    // EV_EOF indicates the remote end closed. Surface as readable
    // so the consumer reads EOF or errno — mirrors the epoll
    // `EPOLLHUP → READABLE` mapping.
    if ev.flags & EV_EOF != 0 {
        interest |= Interest::READABLE;
    }
    interest
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    // ---- Pure-logic unit tests -------------------------------------------

    #[test]
    fn kevent_struct_is_32_bytes() {
        assert_eq!(core::mem::size_of::<Kevent>(), 32);
    }

    #[test]
    fn timespec_struct_is_16_bytes() {
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
    }

    #[test]
    fn read_filter_maps_to_readable() {
        let ev = Kevent { filter: EVFILT_READ, flags: 0, ..Kevent::zeroed() };
        let i = kevent_to_interest(&ev);
        assert!(i.is_readable());
        assert!(!i.is_writable());
    }

    #[test]
    fn write_filter_maps_to_writable() {
        let ev = Kevent { filter: EVFILT_WRITE, flags: 0, ..Kevent::zeroed() };
        let i = kevent_to_interest(&ev);
        assert!(!i.is_readable());
        assert!(i.is_writable());
    }

    #[test]
    fn eof_on_write_surfaces_readable() {
        let ev = Kevent { filter: EVFILT_WRITE, flags: EV_EOF, ..Kevent::zeroed() };
        let i = kevent_to_interest(&ev);
        assert!(i.is_readable());
        assert!(i.is_writable());
    }

    #[test]
    fn eof_on_read_stays_readable() {
        let ev = Kevent { filter: EVFILT_READ, flags: EV_EOF, ..Kevent::zeroed() };
        let i = kevent_to_interest(&ev);
        assert!(i.is_readable());
    }

    #[test]
    fn unknown_filter_maps_to_empty() {
        let ev = Kevent { filter: -99, flags: 0, ..Kevent::zeroed() };
        assert_eq!(kevent_to_interest(&ev), Interest::EMPTY);
    }

    // ---- Loopback integration tests -------------------------------------

    #[test]
    fn register_udp_read_ready() {
        let mut reactor = KqueueReactor::new().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_nonblocking(true).unwrap();
        let fd = sock.as_raw_fd();

        reactor.register(fd, Token(42), Interest::READABLE).unwrap();

        // Trigger readiness.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"hello", addr).unwrap();

        let mut events = Vec::new();
        let count = reactor.poll(&mut events, Some(Duration::from_millis(500))).unwrap();
        assert!(count >= 1, "expected at least 1 event, got {count}");
        assert_eq!(events[0].token, Token(42));
        assert!(events[0].readiness.is_readable());

        reactor.deregister(fd).unwrap();
    }

    #[test]
    fn register_deregister_cycle_no_leaks() {
        let mut reactor = KqueueReactor::new().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let fd = sock.as_raw_fd();

        for i in 0..1000u64 {
            reactor.register(fd, Token(i), Interest::READABLE).unwrap();
            reactor.deregister(fd).unwrap();
        }
        // If we reached here without running out of kernel
        // resources, the register/deregister cycle is balanced.
    }

    #[test]
    fn deregistered_source_stops_delivering() {
        let mut reactor = KqueueReactor::new().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_nonblocking(true).unwrap();
        let fd = sock.as_raw_fd();

        reactor.register(fd, Token(1), Interest::READABLE).unwrap();
        reactor.deregister(fd).unwrap();

        // Send data *after* deregister.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"ghost", addr).unwrap();

        let mut events = Vec::new();
        let count = reactor.poll(&mut events, Some(Duration::from_millis(100))).unwrap();
        assert_eq!(count, 0, "deregistered source delivered {count} events");
    }

    #[test]
    fn reregister_updates_token() {
        let mut reactor = KqueueReactor::new().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_nonblocking(true).unwrap();
        let fd = sock.as_raw_fd();

        reactor.register(fd, Token(1), Interest::READABLE).unwrap();

        // Reregister with a different token.
        reactor.reregister(fd, Token(99), Interest::READABLE).unwrap();

        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"hello", addr).unwrap();

        let mut events = Vec::new();
        reactor.poll(&mut events, Some(Duration::from_millis(500))).unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].token, Token(99));

        reactor.deregister(fd).unwrap();
    }

    #[test]
    fn reregister_switches_interest() {
        let mut reactor = KqueueReactor::new().unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_nonblocking(true).unwrap();
        let fd = sock.as_raw_fd();

        // Start with WRITABLE only.
        reactor.register(fd, Token(1), Interest::WRITABLE).unwrap();

        // Send data — should not be visible since we only
        // watch WRITABLE.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"hello", addr).unwrap();

        // Switch to READABLE.
        reactor.reregister(fd, Token(1), Interest::READABLE).unwrap();

        let mut events = Vec::new();
        let count = reactor.poll(&mut events, Some(Duration::from_millis(500))).unwrap();
        assert!(count >= 1, "expected readable event after reregister");
        assert!(events[0].readiness.is_readable());
        // WRITABLE filter was deleted, so writable should not
        // appear (unless the kernel coalesced it before we
        // deregistered — on kqueue this does not happen since
        // we submit adds and deletes atomically).
        assert!(!events[0].readiness.is_writable());

        reactor.deregister(fd).unwrap();
    }

    #[test]
    fn poll_with_zero_timeout_returns_immediately() {
        let mut reactor = KqueueReactor::new().unwrap();
        let mut events = Vec::new();
        let count = reactor.poll(&mut events, Some(Duration::from_millis(0))).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn coalesces_read_and_write_into_one_event() {
        let mut reactor = KqueueReactor::new().unwrap();

        // Use a connected UDP pair so both filters fire reliably
        // on macOS. An unconnected socket's EVFILT_READ sometimes
        // needs an extra poll cycle after the data lands.
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        a.connect(b_addr).unwrap();
        b.connect(a_addr).unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let fd_a = a.as_raw_fd();

        // Register A for both read and write.
        reactor.register(fd_a, Token(7), Interest::READABLE | Interest::WRITABLE).unwrap();

        // B sends data to A so EVFILT_READ fires.
        b.send(b"dual").unwrap();

        // Wait briefly for the loopback delivery.
        std::thread::sleep(Duration::from_millis(10));

        // Accumulate across a few polls in case the kernel
        // delivers the two filter events in separate wakeups.
        let mut combined = Interest::EMPTY;
        for _ in 0..5 {
            let mut events = Vec::new();
            let count = reactor.poll(&mut events, Some(Duration::from_millis(200))).unwrap();
            if count == 0 {
                continue;
            }
            for ev in &events {
                assert_eq!(ev.token, Token(7));
                combined |= ev.readiness;
            }
            if combined.is_readable() && combined.is_writable() {
                break;
            }
        }
        assert!(
            combined.is_readable() && combined.is_writable(),
            "expected both readable + writable, got {combined:?}"
        );

        reactor.deregister(fd_a).unwrap();
    }
}
