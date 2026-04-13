//! Cross-platform reactor trait. Each platform ships one implementation
//! that hides the underlying mechanism (`epoll` on Linux, `kqueue` on
//! macOS / FreeBSD, IOCP on Windows). Upper layers speak only to this
//! trait so the domain code never has to ask what kernel it is running on.

use std::io;
use std::time::Duration;

use crate::event::Event;
use crate::event::Interest;
use crate::event::Token;

/// On Unix, the reactor identifies I/O sources by their raw file
/// descriptor. On Windows it uses `RawSocket` (a `SOCKET` handle).
#[cfg(unix)]
pub type RawSource = std::os::fd::RawFd;

#[cfg(windows)]
pub type RawSource = std::os::windows::io::RawSocket;

pub trait Reactor {
    /// Add `source` to the reactor under `token`, watching for `interest`.
    fn register(&mut self, source: RawSource, token: Token, interest: Interest) -> io::Result<()>;

    /// Change the watched interest or token for an already registered source.
    fn reregister(&mut self, source: RawSource, token: Token, interest: Interest)
        -> io::Result<()>;

    /// Remove `source` from the reactor. Subsequent readiness events for
    /// the source are suppressed, but the fd itself is NOT closed.
    fn deregister(&mut self, source: RawSource) -> io::Result<()>;

    /// Block for up to `timeout` waiting for readiness events. Fills
    /// `events` with every ready source and returns the count. A timeout of
    /// `None` means wait indefinitely.
    fn poll(&mut self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<usize>;
}
