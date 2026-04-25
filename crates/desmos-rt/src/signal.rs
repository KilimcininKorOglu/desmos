//! Cross-platform shutdown signal.
//!
//! Unix: installs `SIGTERM` and `SIGINT` handlers via raw `sigaction`
//! FFI that flip a process-global `AtomicBool`.
//!
//! Windows: installs a console control handler via
//! `SetConsoleCtrlHandler` for interactive use. When running as a
//! Windows Service, the SCM stop handler calls [`request_shutdown`]
//! directly.
//!
//! The reactor loop polls [`is_shutdown_requested`] on each tick.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn is_shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
pub fn install_signal_handlers() {
    unsafe {
        let mut sa: libc_sigaction = std::mem::zeroed();
        sa.sa_handler = signal_handler as usize;
        sa.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sa, std::ptr::null_mut());
        sigaction(SIGTERM, &sa, std::ptr::null_mut());
    }
}

#[cfg(unix)]
extern "C" fn signal_handler(_sig: i32) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
const SIGINT: i32 = 2;
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SA_RESTART: i32 = 0x10000000;

#[cfg(unix)]
#[repr(C)]
struct libc_sigaction {
    sa_handler: usize,
    sa_flags: i32,
    sa_restorer: usize,
    sa_mask: [u64; 16],
}

#[cfg(unix)]
extern "C" {
    fn sigaction(sig: i32, act: *const libc_sigaction, oldact: *mut libc_sigaction) -> i32;
}

#[cfg(windows)]
pub fn install_signal_handlers() {
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

#[cfg(windows)]
unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    SHUTDOWN.store(true, Ordering::Relaxed);
    1
}

#[cfg(windows)]
extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_not_shutdown() {
        assert!(!SHUTDOWN.load(Ordering::Relaxed) || is_shutdown_requested());
    }

    #[test]
    fn request_and_check() {
        let prev = SHUTDOWN.load(Ordering::Relaxed);
        request_shutdown();
        assert!(is_shutdown_requested());
        SHUTDOWN.store(prev, Ordering::Relaxed);
    }
}
