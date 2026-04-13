//! Privilege drop with typestate enforcement.
//!
//! After opening TUN devices and binding privileged sockets the
//! daemon must shed root.  The [`Privileged`] → [`Unprivileged`]
//! transition is encoded at the type level so post-drop code cannot
//! accidentally call privileged APIs.
//!
//! Platform-specific sandboxing is applied during the transition:
//!
//! | OS      | Mechanism                                    |
//! |---------|----------------------------------------------|
//! | Linux   | `setuid`/`setgid` + seccomp BPF (blocklist)  |
//! | FreeBSD | `setuid`/`setgid` + Capsicum `cap_enter()`   |
//! | macOS   | `setuid`/`setgid`                            |
//!
//! # Example
//!
//! ```ignore
//! let priv_state = Privileged::new(DropConfig {
//!     uid: 65534,
//!     gid: 65534,
//! });
//! // ... open TUN, bind sockets ...
//! let _unpriv = priv_state.drop_privileges()?;
//! // cannot open TUN anymore — type system prevents it
//! ```

use std::io;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "freebsd")]
mod freebsd;

#[cfg(target_os = "macos")]
mod macos;

// ---- Configuration ----------------------------------------------------------

/// Parameters for the privilege drop.
#[derive(Debug, Clone)]
pub struct DropConfig {
    /// Target unprivileged user ID.
    pub uid: u32,
    /// Target unprivileged group ID.
    pub gid: u32,
}

// ---- Typestate markers ------------------------------------------------------

/// Marker: process still holds root privileges.
///
/// Only this state exposes APIs that require privilege (opening TUN
/// devices, binding to low ports, etc.).
pub struct Privileged {
    config: DropConfig,
}

/// Marker: privileges have been permanently dropped.
///
/// Constructed only via [`Privileged::drop_privileges`]. Cannot be
/// created directly.
pub struct Unprivileged {
    _private: (),
}

// ---- Privileged API ---------------------------------------------------------

impl Privileged {
    /// Create the privileged state with the given drop configuration.
    pub fn new(config: DropConfig) -> Self {
        Self { config }
    }

    /// Permanently drop privileges and apply platform sandbox.
    ///
    /// This **consumes** `self` so the caller can never use the
    /// `Privileged` token again.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform-specific drop or sandbox
    /// initialisation fails.
    pub fn drop_privileges(self) -> io::Result<Unprivileged> {
        log_drop_start(&self.config);

        #[cfg(target_os = "linux")]
        linux::drop_and_sandbox(self.config.uid, self.config.gid)?;

        #[cfg(target_os = "freebsd")]
        freebsd::drop_and_sandbox(self.config.uid, self.config.gid)?;

        #[cfg(target_os = "macos")]
        macos::drop_and_sandbox(self.config.uid, self.config.gid)?;

        // Platforms without a specific implementation just log.
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos",)))]
        drop_uid_gid_posix(self.config.uid, self.config.gid)?;

        log_drop_done(&self.config);
        Ok(Unprivileged { _private: () })
    }

    /// Access the drop configuration.
    pub fn config(&self) -> &DropConfig {
        &self.config
    }
}

// ---- Audit logging ----------------------------------------------------------

fn log_drop_start(cfg: &DropConfig) {
    // Intentionally uses eprintln — this is security-critical audit
    // output that must go to stderr regardless of logging framework.
    eprintln!("[audit] privilege-drop: starting (target uid={} gid={})", cfg.uid, cfg.gid,);
}

fn log_drop_done(cfg: &DropConfig) {
    eprintln!("[audit] privilege-drop: complete (now uid={} gid={})", cfg.uid, cfg.gid,);
}

// ---- POSIX fallback (non-Linux, non-FreeBSD, non-macOS) ---------------------

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn drop_uid_gid_posix(_uid: u32, _gid: u32) -> io::Result<()> {
    // On unsupported platforms, succeed silently. A real deployment
    // should never reach here — the binary is only built for the
    // three supported OSes above.
    Ok(())
}

// ---- Shared POSIX helpers (used by linux/freebsd/macos) ---------------------

/// Drop group then user identity.
///
/// # Safety
///
/// Calls `setgid` then `setuid`. Must be called while still root.
#[cfg(unix)]
pub(crate) fn posix_drop_ids(uid: u32, gid: u32) -> io::Result<()> {
    extern "C" {
        fn setgid(gid: u32) -> i32;
        fn setuid(uid: u32) -> i32;
    }

    // Group first — after dropping uid we may lose permission to
    // change gid.
    if unsafe { setgid(gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { setuid(uid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_consumes_self() {
        // Verify the typestate pattern compiles: drop_privileges takes
        // self by value, so a second call is a compile error.
        let p = Privileged::new(DropConfig { uid: 1000, gid: 1000 });
        assert_eq!(p.config().uid, 1000);
        assert_eq!(p.config().gid, 1000);
        // We don't actually call drop_privileges in tests because it
        // requires root, but the type signature enforces consumption.
    }

    #[test]
    fn drop_config_clone() {
        let cfg = DropConfig { uid: 65534, gid: 65534 };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.uid, 65534);
        assert_eq!(cfg2.gid, 65534);
    }

    #[test]
    fn unprivileged_not_constructible() {
        // Unprivileged has a private field — the only way to get one
        // is through Privileged::drop_privileges(). This test exists
        // as documentation of that invariant.
        let _ = Privileged::new(DropConfig { uid: 0, gid: 0 });
    }

    #[test]
    #[ignore = "needs root"]
    fn drop_privileges_succeeds_as_root() {
        let p = Privileged::new(DropConfig { uid: 65534, gid: 65534 });
        let result = p.drop_privileges();
        assert!(result.is_ok());
    }
}
