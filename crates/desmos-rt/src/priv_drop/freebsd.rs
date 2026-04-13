//! FreeBSD privilege drop: uid/gid + Capsicum capability mode.
//!
//! After switching to the unprivileged user the process enters
//! Capsicum capability mode via `cap_enter()`.  In this mode the
//! kernel blocks **all** global namespace operations — `open()`,
//! `socket()`, `execve()`, etc.  Only pre-existing file descriptors
//! (and their capabilities) remain usable.
//!
//! This is the strongest sandbox available on FreeBSD: once entered,
//! there is no way to leave capability mode.  All TUN devices and
//! sockets must be opened *before* the drop.
//!
//! Note: the task description mentions pledge/unveil — those are
//! OpenBSD-specific.  The FreeBSD equivalent is Capsicum.

use std::io;

use super::posix_drop_ids;

// ---- FFI --------------------------------------------------------------------

extern "C" {
    /// Enter Capsicum capability mode.
    ///
    /// After `cap_enter()` succeeds the process can no longer access
    /// global namespaces (filesystem, PID space, etc.).  Returns 0 on
    /// success, -1 on failure.
    fn cap_enter() -> i32;
}

// ---- Public entry point -----------------------------------------------------

/// Drop uid/gid and enter Capsicum capability mode.
pub(crate) fn drop_and_sandbox(uid: u32, gid: u32) -> io::Result<()> {
    // Step 1: drop uid/gid.
    posix_drop_ids(uid, gid)?;

    // Step 2: enter capability mode — blocks all global namespace ops.
    if unsafe { cap_enter() } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Capsicum is only available on FreeBSD. This test just
        // confirms the module compiles correctly.
    }

    #[test]
    #[ignore = "needs root on FreeBSD"]
    #[cfg(target_os = "freebsd")]
    fn drop_and_sandbox_enters_capability_mode() {
        use super::*;

        drop_and_sandbox(65534, 65534).unwrap();
        // After cap_enter, open should fail with ECAPMODE.
        let result = std::fs::File::open("/dev/null");
        assert!(result.is_err());
    }
}
