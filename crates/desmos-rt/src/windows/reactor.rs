//! Windows IOCP reactor.
//!
//! Wraps I/O Completion Ports behind the [`crate::reactor::Reactor`]
//! trait with hand-declared `extern "system"` FFI bindings (no
//! `windows-sys` or `winapi` crate).
//!
//! # IOCP readiness simulation
//!
//! IOCP is a completion-based model: the application submits a
//! buffer, the kernel fills it, and a completion packet arrives.
//! The [`Reactor`] trait expects a readiness model (epoll / kqueue
//! style): "this fd is readable, go ahead and `recv` on it."
//!
//! The standard bridge is the **zero-byte overlapped recv** trick:
//! submit a `WSARecv` with an empty buffer. The kernel completes
//! it immediately once at least one byte is available in the socket
//! receive buffer — essentially a readiness notification delivered
//! through the IOCP completion queue. The same trick works for
//! write readiness via a zero-byte `WSASend`.
//!
//! [`IocpReactor::register`] associates the socket with the IOCP
//! handle and kicks off the zero-byte probes for whatever interest
//! bits the caller requested. [`IocpReactor::poll`] dequeues
//! completions, maps them to [`Event`]s, and re-arms the probe so
//! the next `poll` sees fresh readiness.
//!
//! # Limitations
//!
//! - Only `SOCKET` handles (UDP / TCP). TUN handles go through
//!   `ReadFile` / `WriteFile` overlapped I/O (Task 43).
//! - Thread-safety: `IocpReactor` is `!Send` by design — the
//!   daemon reactor loop runs on one thread, matching the epoll
//!   and kqueue backends.

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use crate::event::{Event, Interest, Token};
use crate::reactor::{RawSource, Reactor};

// ---- Windows type aliases --------------------------------------------------

/// `HANDLE` on Windows is a pointer-sized value.
type Handle = isize;
/// `SOCKET` on Windows is `usize` (UINT_PTR).
type Socket = usize;

const INVALID_HANDLE: Handle = -1;
const INVALID_SOCKET: Socket = !0;

// ---- OVERLAPPED ------------------------------------------------------------

/// Minimal mirror of `OVERLAPPED`. We only need the structure as
/// a tag for the kernel — no offset or event fields are used.
#[repr(C)]
#[derive(Clone)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

impl Overlapped {
    const fn zeroed() -> Self {
        Self { internal: 0, internal_high: 0, offset: 0, offset_high: 0, event: 0 }
    }
}

/// Mirrors `OVERLAPPED_ENTRY` returned by
/// `GetQueuedCompletionStatusEx`.
#[repr(C)]
#[derive(Clone)]
struct OverlappedEntry {
    completion_key: usize,
    overlapped: *mut Overlapped,
    internal: usize,
    bytes_transferred: u32,
}

impl OverlappedEntry {
    const fn zeroed() -> Self {
        Self {
            completion_key: 0,
            overlapped: core::ptr::null_mut(),
            internal: 0,
            bytes_transferred: 0,
        }
    }
}

// ---- WSABUF ----------------------------------------------------------------

/// Mirror of `WSABUF` — pointer + length pair.
#[repr(C)]
struct WsaBuf {
    len: u32,
    buf: *mut u8,
}

// ---- Completion key encoding -----------------------------------------------

/// We pack the user Token (u64) into the IOCP completion key.
/// The OVERLAPPED pointer distinguishes read from write probes
/// for the same socket — each registered socket gets two
/// Overlapped allocations (one for read, one for write), and we
/// identify which probe completed by matching the pointer.

/// Per-socket tracking state.
struct SocketState {
    token: Token,
    interest: Interest,
    /// Overlapped for the zero-byte read probe.
    read_ovl: Box<Overlapped>,
    /// Overlapped for the zero-byte write probe.
    write_ovl: Box<Overlapped>,
    /// Whether a read probe is currently in-flight.
    read_pending: bool,
    /// Whether a write probe is currently in-flight.
    write_pending: bool,
}

// ---- FFI constants ---------------------------------------------------------

const WSA_IO_PENDING: i32 = 997;
const WAIT_TIMEOUT: u32 = 258;
// CompletionKey value we use for user-posted wake-ups (not used yet).
#[allow(dead_code)]
const WAKE_TOKEN: usize = usize::MAX;

// ---- FFI declarations ------------------------------------------------------

// SAFETY: standard Win32 / WinSock2 API calls. Every call site
// checks return values.
#[cfg(target_os = "windows")]
extern "system" {
    fn CreateIoCompletionPort(
        file_handle: Handle,
        existing_completion_port: Handle,
        completion_key: usize,
        number_of_concurrent_threads: u32,
    ) -> Handle;

    fn GetQueuedCompletionStatusEx(
        completion_port: Handle,
        completion_port_entries: *mut OverlappedEntry,
        count: u32,
        num_entries_removed: *mut u32,
        milliseconds: u32,
        alertable: i32,
    ) -> i32;

    fn CloseHandle(handle: Handle) -> i32;

    fn WSARecv(
        socket: Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_received: *mut u32,
        flags: *mut u32,
        overlapped: *mut Overlapped,
        completion_routine: usize,
    ) -> i32;

    fn WSASend(
        socket: Socket,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        bytes_sent: *mut u32,
        flags: u32,
        overlapped: *mut Overlapped,
        completion_routine: usize,
    ) -> i32;

    fn WSAGetLastError() -> i32;
}

// ---- Stub FFI for non-Windows compilation ----------------------------------

// When compiling on non-Windows (e.g. macOS CI cross-check), the
// extern "system" block above is cfg-gated out. We provide stub
// functions so the module compiles but panics if ever called.
#[cfg(not(target_os = "windows"))]
mod ffi_stubs {
    use super::*;

    pub unsafe fn CreateIoCompletionPort(_fh: Handle, _ep: Handle, _ck: usize, _ct: u32) -> Handle {
        panic!("IOCP FFI called on non-Windows")
    }

    pub unsafe fn GetQueuedCompletionStatusEx(
        _cp: Handle,
        _entries: *mut OverlappedEntry,
        _count: u32,
        _removed: *mut u32,
        _ms: u32,
        _alert: i32,
    ) -> i32 {
        panic!("IOCP FFI called on non-Windows")
    }

    pub unsafe fn CloseHandle(_h: Handle) -> i32 {
        panic!("IOCP FFI called on non-Windows")
    }

    pub unsafe fn WSARecv(
        _s: Socket,
        _b: *mut WsaBuf,
        _bc: u32,
        _br: *mut u32,
        _f: *mut u32,
        _o: *mut Overlapped,
        _cr: usize,
    ) -> i32 {
        panic!("IOCP FFI called on non-Windows")
    }

    pub unsafe fn WSASend(
        _s: Socket,
        _b: *mut WsaBuf,
        _bc: u32,
        _bs: *mut u32,
        _f: u32,
        _o: *mut Overlapped,
        _cr: usize,
    ) -> i32 {
        panic!("IOCP FFI called on non-Windows")
    }

    pub unsafe fn WSAGetLastError() -> i32 {
        panic!("IOCP FFI called on non-Windows")
    }
}

#[cfg(not(target_os = "windows"))]
use ffi_stubs::*;

// ---- IocpReactor -----------------------------------------------------------

/// Windows IOCP reactor behind the [`Reactor`] trait.
pub struct IocpReactor {
    iocp: Handle,
    /// Dequeue buffer reused across `poll` calls.
    entry_buf: Vec<OverlappedEntry>,
    /// Per-socket state keyed by `RawSocket as usize`.
    sockets: HashMap<Socket, SocketState>,
}

impl IocpReactor {
    /// Create a new IOCP handle with a single concurrent thread
    /// (the reactor loop).
    pub fn new() -> io::Result<Self> {
        let iocp = unsafe { CreateIoCompletionPort(INVALID_HANDLE, 0, 0, 1) };
        if iocp == 0 || iocp == INVALID_HANDLE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { iocp, entry_buf: Vec::with_capacity(64), sockets: HashMap::new() })
    }

    /// Associate `socket` with the IOCP and submit zero-byte
    /// probes for the requested interest bits.
    fn associate_and_arm(
        &mut self,
        socket: Socket,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        // Associate socket with IOCP. The completion key is the
        // socket value so we can look up the SocketState on
        // completion.
        let h = unsafe { CreateIoCompletionPort(socket as Handle, self.iocp, socket, 0) };
        if h == 0 || h == INVALID_HANDLE {
            return Err(io::Error::last_os_error());
        }

        let mut state = SocketState {
            token,
            interest,
            read_ovl: Box::new(Overlapped::zeroed()),
            write_ovl: Box::new(Overlapped::zeroed()),
            read_pending: false,
            write_pending: false,
        };

        if interest.is_readable() {
            Self::arm_read(socket, &mut state)?;
        }
        if interest.is_writable() {
            Self::arm_write(socket, &mut state)?;
        }

        self.sockets.insert(socket, state);
        Ok(())
    }

    /// Submit a zero-byte `WSARecv` as a read-readiness probe.
    fn arm_read(socket: Socket, state: &mut SocketState) -> io::Result<()> {
        if state.read_pending {
            return Ok(());
        }
        let mut buf = WsaBuf { len: 0, buf: core::ptr::null_mut() };
        let mut flags = 0u32;
        let mut bytes = 0u32;
        // Reset the overlapped for reuse.
        *state.read_ovl = Overlapped::zeroed();
        let rc = unsafe {
            WSARecv(socket, &mut buf, 1, &mut bytes, &mut flags, &mut *state.read_ovl, 0)
        };
        if rc != 0 {
            let err = unsafe { WSAGetLastError() };
            if err != WSA_IO_PENDING {
                return Err(io::Error::from_raw_os_error(err));
            }
        }
        state.read_pending = true;
        Ok(())
    }

    /// Submit a zero-byte `WSASend` as a write-readiness probe.
    fn arm_write(socket: Socket, state: &mut SocketState) -> io::Result<()> {
        if state.write_pending {
            return Ok(());
        }
        let mut buf = WsaBuf { len: 0, buf: core::ptr::null_mut() };
        let mut bytes = 0u32;
        *state.write_ovl = Overlapped::zeroed();
        let rc = unsafe { WSASend(socket, &mut buf, 1, &mut bytes, 0, &mut *state.write_ovl, 0) };
        if rc != 0 {
            let err = unsafe { WSAGetLastError() };
            if err != WSA_IO_PENDING {
                return Err(io::Error::from_raw_os_error(err));
            }
        }
        state.write_pending = true;
        Ok(())
    }
}

impl Drop for IocpReactor {
    fn drop(&mut self) {
        if self.iocp != 0 && self.iocp != INVALID_HANDLE {
            unsafe { CloseHandle(self.iocp) };
        }
    }
}

impl Reactor for IocpReactor {
    fn register(&mut self, source: RawSource, token: Token, interest: Interest) -> io::Result<()> {
        let socket = source as Socket;
        if socket == INVALID_SOCKET {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket"));
        }
        self.associate_and_arm(socket, token, interest)
    }

    fn reregister(
        &mut self,
        source: RawSource,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        let socket = source as Socket;
        let state = self
            .sockets
            .get_mut(&socket)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "socket not registered"))?;

        state.token = token;
        let old = state.interest;
        state.interest = interest;

        // Arm newly requested probes.
        if interest.is_readable() && !old.is_readable() {
            Self::arm_read(socket, state)?;
        }
        if interest.is_writable() && !old.is_writable() {
            Self::arm_write(socket, state)?;
        }
        // Probes for dropped interest will complete and be
        // ignored in poll() since the interest bit is cleared.
        Ok(())
    }

    fn deregister(&mut self, source: RawSource) -> io::Result<()> {
        let socket = source as Socket;
        // Remove tracking. Any in-flight overlapped completions
        // will arrive but be ignored (socket not in HashMap).
        // The IOCP association cannot be removed from a socket
        // without closing it — this matches epoll's behaviour
        // where the kernel cleans up on fd close.
        self.sockets.remove(&socket);
        Ok(())
    }

    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<usize> {
        let timeout_ms = match timeout {
            None => u32::MAX, // INFINITE
            Some(d) => d.as_millis().min(u32::MAX as u128 - 1) as u32,
        };

        let cap = self.entry_buf.capacity().max(64);
        if self.entry_buf.capacity() < cap {
            self.entry_buf.reserve(cap - self.entry_buf.len());
        }

        let mut removed = 0u32;
        let rc = unsafe {
            GetQueuedCompletionStatusEx(
                self.iocp,
                self.entry_buf.as_mut_ptr(),
                cap as u32,
                &mut removed,
                timeout_ms,
                0, // not alertable
            )
        };

        if rc == 0 {
            let err = io::Error::last_os_error();
            // WAIT_TIMEOUT is not a real error — just no events.
            if err.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                events.clear();
                return Ok(0);
            }
            return Err(err);
        }

        unsafe {
            self.entry_buf.set_len(removed as usize);
        }

        events.clear();
        events.reserve(removed as usize);

        for entry in &self.entry_buf {
            let socket = entry.completion_key as Socket;

            let Some(state) = self.sockets.get_mut(&socket) else {
                // Socket was deregistered while the completion
                // was in-flight. Discard.
                continue;
            };

            // Determine which probe completed by comparing the
            // overlapped pointer to the read and write probes.
            let ovl_ptr = entry.overlapped;
            let is_read = core::ptr::eq(ovl_ptr, &*state.read_ovl as *const Overlapped);
            let is_write = core::ptr::eq(ovl_ptr, &*state.write_ovl as *const Overlapped);

            let mut readiness = Interest::EMPTY;
            if is_read {
                state.read_pending = false;
                if state.interest.is_readable() {
                    readiness |= Interest::READABLE;
                    // Re-arm for next poll.
                    let _ = Self::arm_read(socket, state);
                }
            }
            if is_write {
                state.write_pending = false;
                if state.interest.is_writable() {
                    readiness |= Interest::WRITABLE;
                    let _ = Self::arm_write(socket, state);
                }
            }

            if readiness == Interest::EMPTY {
                continue;
            }

            let token = state.token;
            // Coalesce with any existing event for same token.
            if let Some(existing) = events.iter_mut().find(|e| e.token == token) {
                existing.readiness |= readiness;
            } else {
                events.push(Event { token, readiness });
            }
        }

        Ok(events.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Pure-logic unit tests (run on any platform) --------------------

    #[test]
    fn overlapped_struct_layout() {
        // OVERLAPPED is 5 pointer-sized fields on 64-bit = 32 bytes
        // on 32-bit = 20 bytes. We just check it's non-zero.
        let size = core::mem::size_of::<Overlapped>();
        assert!(size > 0);
        // On 64-bit: 5 * 8 - event is Handle(isize) not usize
        // Actually: usize + usize + u32 + u32 + isize
        // = 8 + 8 + 4 + 4 + 8 = 32 on 64-bit
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size, 32);
    }

    #[test]
    fn overlapped_entry_layout() {
        let size = core::mem::size_of::<OverlappedEntry>();
        assert!(size > 0);
        // usize + *mut + usize + u32 + padding
        // = 8 + 8 + 8 + 4 (+4 pad) = 32 on 64-bit
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size, 32);
    }

    #[test]
    fn wsabuf_layout() {
        let size = core::mem::size_of::<WsaBuf>();
        assert!(size > 0);
        // u32 + padding + *mut u8 = 4 + 4 + 8 = 16 on 64-bit
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size, 16);
    }

    #[test]
    fn socket_state_tracks_interest() {
        let state = SocketState {
            token: Token(42),
            interest: Interest::READABLE | Interest::WRITABLE,
            read_ovl: Box::new(Overlapped::zeroed()),
            write_ovl: Box::new(Overlapped::zeroed()),
            read_pending: false,
            write_pending: false,
        };
        assert!(state.interest.is_readable());
        assert!(state.interest.is_writable());
        assert_eq!(state.token, Token(42));
    }

    #[test]
    fn read_write_overlapped_are_distinct() {
        let state = SocketState {
            token: Token(1),
            interest: Interest::READABLE,
            read_ovl: Box::new(Overlapped::zeroed()),
            write_ovl: Box::new(Overlapped::zeroed()),
            read_pending: false,
            write_pending: false,
        };
        // The two overlapped allocations must have distinct
        // addresses so poll() can tell them apart.
        let r_ptr = &*state.read_ovl as *const Overlapped;
        let w_ptr = &*state.write_ovl as *const Overlapped;
        assert!(!core::ptr::eq(r_ptr, w_ptr));
    }

    #[test]
    fn invalid_constants() {
        assert_eq!(INVALID_HANDLE, -1isize);
        assert_eq!(INVALID_SOCKET, usize::MAX);
    }

    // ---- Windows-only integration tests --------------------------------

    #[cfg(target_os = "windows")]
    mod windows_integration {
        use super::*;
        use std::net;

        #[test]
        fn create_iocp_reactor() {
            let reactor = IocpReactor::new().unwrap();
            assert_ne!(reactor.iocp, 0);
            assert_ne!(reactor.iocp, INVALID_HANDLE);
        }

        #[test]
        fn register_udp_read_ready() {
            use std::os::windows::io::AsRawSocket;
            let mut reactor = IocpReactor::new().unwrap();
            let sock = net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = sock.local_addr().unwrap();
            let raw = sock.as_raw_socket();

            reactor.register(raw, Token(10), Interest::READABLE).unwrap();

            // Trigger readiness.
            let sender = net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(b"hello", addr).unwrap();

            let mut events = Vec::new();
            let count = reactor.poll(&mut events, Some(Duration::from_millis(1_000))).unwrap();
            assert!(count >= 1, "expected at least 1 event, got {count}");
            assert_eq!(events[0].token, Token(10));
            assert!(events[0].readiness.is_readable());

            reactor.deregister(raw).unwrap();
        }

        #[test]
        fn register_deregister_cycle() {
            use std::os::windows::io::AsRawSocket;
            let mut reactor = IocpReactor::new().unwrap();
            // Each cycle needs a fresh socket because IOCP
            // association is permanent per socket handle.
            for i in 0..100u64 {
                let sock = net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let raw = sock.as_raw_socket();
                reactor.register(raw, Token(i), Interest::READABLE).unwrap();
                reactor.deregister(raw).unwrap();
            }
        }

        #[test]
        fn poll_timeout_returns_zero() {
            let mut reactor = IocpReactor::new().unwrap();
            let mut events = Vec::new();
            let count = reactor.poll(&mut events, Some(Duration::from_millis(0))).unwrap();
            assert_eq!(count, 0);
        }
    }
}
