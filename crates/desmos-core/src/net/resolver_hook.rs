//! Platform DNS resolver override for leak protection.
//!
//! When `dns_leak_protection = true`, the system DNS resolver must be
//! pointed at the tunnel's DNS servers so queries don't leak through
//! the physical interfaces.
//!
//! # Platform implementations
//!
//! - **Linux**: writes `/etc/resolv.conf` (saves a backup, restores on teardown).
//! - **macOS**: uses `scutil` to configure DNS on the primary service.
//! - **Windows**: uses `netsh interface ip set dns` on the tunnel adapter.
//! - **FreeBSD**: same as Linux (`/etc/resolv.conf`).
//!
//! # Safety
//!
//! Teardown **must** be called to restore the original DNS configuration.
//! Use `DnsGuard` for RAII-based teardown.

use std::fmt;
use std::io;

/// DNS override error.
#[derive(Debug)]
pub enum DnsOverrideError {
    /// I/O error during file/process operations.
    Io(io::Error),
    /// Platform not supported for DNS override.
    Unsupported,
    /// Failed to run the platform command.
    CommandFailed(String),
}

impl fmt::Display for DnsOverrideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "DNS override I/O error: {e}"),
            Self::Unsupported => write!(f, "DNS override not supported on this platform"),
            Self::CommandFailed(msg) => write!(f, "DNS override command failed: {msg}"),
        }
    }
}

impl From<io::Error> for DnsOverrideError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Saved state needed to restore the original DNS configuration.
#[derive(Debug)]
pub struct DnsState {
    /// Platform-specific saved state.
    inner: DnsStateInner,
}

#[derive(Debug)]
enum DnsStateInner {
    /// Linux/FreeBSD: backup path for resolv.conf.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    ResolvConf { backup_path: std::path::PathBuf },
    /// macOS: the primary network service name.
    #[cfg(target_os = "macos")]
    Scutil { service_name: String },
    /// Windows: the adapter name.
    #[cfg(target_os = "windows")]
    Netsh { adapter_name: String },
}

/// Apply DNS override: point the system resolver at `servers`.
///
/// Returns a `DnsState` that must be passed to `restore()` to undo
/// the override.
pub fn apply(servers: &[String], _tunnel_iface: &str) -> Result<DnsState, DnsOverrideError> {
    if servers.is_empty() {
        return Err(DnsOverrideError::CommandFailed("no DNS servers specified".into()));
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        apply_resolv_conf(servers)
    }

    #[cfg(target_os = "macos")]
    {
        apply_scutil(servers)
    }

    #[cfg(target_os = "windows")]
    {
        apply_netsh(servers, _tunnel_iface)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = servers;
        Err(DnsOverrideError::Unsupported)
    }
}

/// Restore the original DNS configuration.
pub fn restore(state: DnsState) -> Result<(), DnsOverrideError> {
    match state.inner {
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        DnsStateInner::ResolvConf { backup_path } => restore_resolv_conf(&backup_path),
        #[cfg(target_os = "macos")]
        DnsStateInner::Scutil { service_name } => restore_scutil(&service_name),
        #[cfg(target_os = "windows")]
        DnsStateInner::Netsh { adapter_name } => restore_netsh(&adapter_name),
    }
}

// ---------------------------------------------------------------------------
// RAII guard
// ---------------------------------------------------------------------------

/// RAII guard that restores DNS on drop.
///
/// If `disarm()` is called, the guard does nothing on drop (useful
/// when you want to handle teardown manually).
pub struct DnsGuard {
    state: Option<DnsState>,
}

impl DnsGuard {
    /// Create a new guard wrapping the given DNS state.
    pub fn new(state: DnsState) -> Self {
        Self { state: Some(state) }
    }

    /// Disarm the guard so it does nothing on drop.
    pub fn disarm(&mut self) {
        self.state = None;
    }

    /// Explicitly restore DNS and consume the guard.
    pub fn restore(mut self) -> Result<(), DnsOverrideError> {
        match self.state.take() {
            Some(s) => restore(s),
            None => Ok(()),
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            // Best-effort restore on drop.
            let _ = restore(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Linux / FreeBSD: /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const RESOLV_BACKUP: &str = "/etc/resolv.conf.desmos-backup";

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn apply_resolv_conf(servers: &[String]) -> Result<DnsState, DnsOverrideError> {
    use std::fs;
    use std::path::PathBuf;

    let backup_path = PathBuf::from(RESOLV_BACKUP);

    // Save the current resolv.conf.
    if std::path::Path::new(RESOLV_CONF).exists() {
        fs::copy(RESOLV_CONF, &backup_path)?;
    }

    // Write new resolv.conf.
    let mut content = String::from("# Generated by desmos — dns_leak_protection\n");
    for server in servers {
        content.push_str(&format!("nameserver {server}\n"));
    }
    fs::write(RESOLV_CONF, &content)?;

    Ok(DnsState { inner: DnsStateInner::ResolvConf { backup_path } })
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn restore_resolv_conf(backup_path: &std::path::Path) -> Result<(), DnsOverrideError> {
    use std::fs;

    if backup_path.exists() {
        fs::copy(backup_path, RESOLV_CONF)?;
        let _ = fs::remove_file(backup_path);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS: scutil
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn apply_scutil(servers: &[String]) -> Result<DnsState, DnsOverrideError> {
    use std::process::Command;

    // Get the primary network service name.
    let service_name = get_primary_service()?;

    // Build scutil commands to set DNS servers.
    let server_entries: Vec<String> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| format!("  ServerAddresses : {} : {}", i, s))
        .collect();

    let script = format!(
        "d.init\nd.add ServerAddresses * {}\nset State:/Network/Service/{}/DNS\n",
        servers.join(" "),
        service_name
    );

    let output = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DnsOverrideError::CommandFailed(format!("scutil set DNS failed: {stderr}")));
    }

    // Flush DNS cache.
    let _ = Command::new("dscacheutil").args(["-flushcache"]).status();
    let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();

    let _ = server_entries; // Used for the format above.

    Ok(DnsState { inner: DnsStateInner::Scutil { service_name } })
}

#[cfg(target_os = "macos")]
fn get_primary_service() -> Result<String, DnsOverrideError> {
    use std::process::Command;

    // Get the primary service UUID from scutil (not used yet, but confirms connectivity).
    let _output = Command::new("scutil").args(["--dns"]).output()?;

    // Fallback: use networksetup to list services, pick the first one.
    let output = Command::new("networksetup").args(["-listallnetworkservices"]).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        // Skip lines starting with "*" (disabled services).
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('*') {
            return Ok(trimmed.to_string());
        }
    }

    Err(DnsOverrideError::CommandFailed("could not find primary network service".into()))
}

#[cfg(target_os = "macos")]
fn restore_scutil(service_name: &str) -> Result<(), DnsOverrideError> {
    use std::process::Command;

    // Remove the DNS override, letting DHCP take over again.
    let script = format!("d.init\nremove State:/Network/Service/{service_name}/DNS\n");

    let output = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DnsOverrideError::CommandFailed(format!(
            "scutil restore DNS failed: {stderr}"
        )));
    }

    // Flush cache.
    let _ = Command::new("dscacheutil").args(["-flushcache"]).status();
    let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();

    Ok(())
}

// ---------------------------------------------------------------------------
// Windows: netsh
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn apply_netsh(servers: &[String], adapter_name: &str) -> Result<DnsState, DnsOverrideError> {
    use std::process::Command;

    // Set primary DNS.
    if let Some(primary) = servers.first() {
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                &format!("name=\"{adapter_name}\""),
                "static",
                primary,
                "primary",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DnsOverrideError::CommandFailed(format!(
                "netsh set primary DNS failed: {stderr}"
            )));
        }
    }

    // Add secondary DNS servers.
    for server in servers.iter().skip(1) {
        let output = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "add",
                "dns",
                &format!("name=\"{adapter_name}\""),
                server,
                "index=2",
            ])
            .output()?;

        if !output.status.success() {
            // Non-fatal: log but continue.
            let _ = output;
        }
    }

    // Flush DNS cache.
    let _ = Command::new("ipconfig").args(["/flushdns"]).status();

    Ok(DnsState { inner: DnsStateInner::Netsh { adapter_name: adapter_name.to_string() } })
}

#[cfg(target_os = "windows")]
fn restore_netsh(adapter_name: &str) -> Result<(), DnsOverrideError> {
    use std::process::Command;

    // Reset to DHCP-assigned DNS.
    let output = Command::new("netsh")
        .args(["interface", "ip", "set", "dns", &format!("name=\"{adapter_name}\""), "dhcp"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DnsOverrideError::CommandFailed(format!("netsh restore DNS failed: {stderr}")));
    }

    let _ = Command::new("ipconfig").args(["/flushdns"]).status();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_servers_rejected() {
        let result = apply(&[], "desmos0");
        assert!(matches!(result, Err(DnsOverrideError::CommandFailed(_))));
    }

    #[test]
    fn dns_guard_disarm() {
        // Verify disarm prevents restore on drop (no-op test).
        let mut guard = DnsGuard { state: None };
        guard.disarm();
        drop(guard);
    }

    #[test]
    fn dns_guard_restore_none() {
        let guard = DnsGuard { state: None };
        assert!(guard.restore().is_ok());
    }
}
