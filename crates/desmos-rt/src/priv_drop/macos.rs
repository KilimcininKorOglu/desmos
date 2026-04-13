//! macOS privilege drop: uid/gid only.
//!
//! macOS does not expose a useful runtime sandboxing API for CLI
//! daemons.  `sandbox_init(3)` is deprecated and the modern
//! App Sandbox requires an entitlements plist compiled into the
//! binary via codesign — impractical for a portable CLI tool.
//!
//! The drop therefore only switches uid/gid.  This still prevents
//! re-opening TUN devices (utun requires root) and binding to
//! privileged ports.

use std::io;

use super::posix_drop_ids;

// ---- Public entry point -----------------------------------------------------

/// Drop uid/gid on macOS.
///
/// No additional sandboxing beyond the identity switch.
pub(crate) fn drop_and_sandbox(uid: u32, gid: u32) -> io::Result<()> {
    posix_drop_ids(uid, gid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Actual uid drop requires root. This test confirms the
        // module structure is correct.
    }

    #[test]
    #[ignore = "needs root on macOS"]
    #[cfg(target_os = "macos")]
    fn drop_prevents_tun_reopen() {
        use super::*;

        drop_and_sandbox(65534, 65534).unwrap();
        // After dropping to nobody, utun creation should fail.
        let result = crate::bsd::MacosTun::create(99);
        assert!(result.is_err());
    }
}
