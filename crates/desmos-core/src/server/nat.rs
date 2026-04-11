//! Linux iptables wrapper for server-side NAT / masquerade.
//!
//! The server daemon brings its TUN up on `tunnel_iface` (e.g.
//! `desmos0`) with a private CIDR (e.g. `10.200.0.0/24`). For
//! clients behind the tunnel to reach the internet through the
//! server's `egress_iface` (e.g. `eth0`), the server kernel needs
//! two iptables rules:
//!
//! 1. `POSTROUTING MASQUERADE` on the egress interface, so return
//!    traffic gets the server's public address.
//! 2. `FORWARD ACCEPT` for traffic between `tunnel_iface` and the
//!    egress interface in both directions, so the default
//!    `FORWARD` DROP policy on most distros does not black-hole
//!    tunnel packets.
//!
//! This module is the thin wrapper that installs both rules at
//! startup, tracks exactly what it installed, and removes them on
//! shutdown. Everything goes through a [`Runner`] trait so the
//! unit tests can swap in a capture-only fake instead of shelling
//! out to real `iptables`. The production runner is
//! [`IptablesRunner`], a `std::process::Command` driver.
//!
//! The module compiles on every platform but only
//! [`IptablesRunner`] actually executes kernel state; non-Linux
//! builds can still unit-test the rule-shaping logic via the
//! fake runner. The server daemon will gate the real
//! [`NatController::install`] call on `cfg(target_os = "linux")`.

use std::fmt;
use std::io;

/// Runner abstraction: every call is a single iptables invocation
/// expressed as the argv the production runner would pass to
/// `iptables` (without the binary name itself). The tests use this
/// to record the rule set without actually touching the kernel.
pub trait Runner: Send + Sync {
    /// Execute one iptables invocation. Returns `Ok(())` on success
    /// and a descriptive [`io::Error`] on failure. The production
    /// runner maps a non-zero exit status to `ErrorKind::Other`
    /// with the combined stdout/stderr in the message.
    fn run(&self, argv: &[&str]) -> io::Result<()>;
}

/// Production runner that shells out to `iptables`. One-shot
/// invocation per rule; no long-lived session, no threading
/// surprises.
pub struct IptablesRunner {
    /// Path or name of the iptables binary. Defaults to
    /// `"iptables"` so the standard PATH lookup kicks in.
    binary: String,
}

impl IptablesRunner {
    pub fn new() -> Self {
        Self { binary: "iptables".to_string() }
    }

    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self { binary: binary.into() }
    }
}

impl Default for IptablesRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for IptablesRunner {
    fn run(&self, argv: &[&str]) -> io::Result<()> {
        let output = std::process::Command::new(&self.binary).args(argv).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "iptables {} exited with {}: {stdout}{stderr}",
                    argv.join(" "),
                    output.status,
                ),
            ));
        }
        Ok(())
    }
}

/// Immutable NAT configuration. Every field is the caller's
/// responsibility to validate against the running kernel — this
/// module does not introspect interfaces, it just applies what it
/// is told.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Tunnel interface name, e.g. `desmos0`. Must be up before
    /// [`NatController::install`] runs or the kernel will reject
    /// the FORWARD rules.
    pub tunnel_iface: String,
    /// Egress interface name on the server's public side, e.g.
    /// `eth0`. Must be reachable from the outside network.
    pub egress_iface: String,
    /// CIDR assigned to the tunnel subnet, e.g. `"10.200.0.0/24"`.
    /// Narrows the MASQUERADE rule to traffic that actually
    /// originated from the tunnel so a misconfigured host does
    /// not accidentally masquerade its own LAN traffic.
    pub tunnel_cidr: String,
}

impl NatConfig {
    /// Validate the config for obvious shape errors before any
    /// iptables work starts.
    pub fn validate(&self) -> Result<(), NatError> {
        if self.tunnel_iface.is_empty() {
            return Err(NatError::InvalidConfig("tunnel_iface is empty"));
        }
        if self.egress_iface.is_empty() {
            return Err(NatError::InvalidConfig("egress_iface is empty"));
        }
        if !self.tunnel_cidr.contains('/') {
            return Err(NatError::InvalidConfig("tunnel_cidr missing '/'"));
        }
        Ok(())
    }
}

/// NAT-related errors.
#[derive(Debug)]
pub enum NatError {
    InvalidConfig(&'static str),
    /// Iptables invocation failed. The inner message carries the
    /// runner's combined stdout/stderr.
    Iptables(io::Error),
    /// Install was called twice without an intervening remove.
    AlreadyInstalled,
    /// Remove was called before install.
    NotInstalled,
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "nat: invalid config: {reason}"),
            Self::Iptables(e) => write!(f, "nat: iptables failed: {e}"),
            Self::AlreadyInstalled => f.write_str("nat: install called twice"),
            Self::NotInstalled => f.write_str("nat: remove called before install"),
        }
    }
}

impl std::error::Error for NatError {}

impl From<io::Error> for NatError {
    fn from(e: io::Error) -> Self {
        Self::Iptables(e)
    }
}

/// A single rule paired with the iptables flags needed to install
/// (`-A`) or remove (`-D`) it. `argv` is the chain + match part;
/// the controller prepends the operator.
#[derive(Debug, Clone)]
struct Rule {
    /// Iptables table: `nat` or `filter`.
    table: &'static str,
    /// Chain inside that table: `POSTROUTING` or `FORWARD`.
    chain: &'static str,
    /// Match + target flags. `-A`/`-D` are added by the controller.
    body: Vec<String>,
}

impl Rule {
    fn install_argv(&self) -> Vec<String> {
        let mut v = vec!["-t".to_string(), self.table.to_string()];
        v.push("-A".to_string());
        v.push(self.chain.to_string());
        v.extend(self.body.iter().cloned());
        v
    }

    fn remove_argv(&self) -> Vec<String> {
        let mut v = vec!["-t".to_string(), self.table.to_string()];
        v.push("-D".to_string());
        v.push(self.chain.to_string());
        v.extend(self.body.iter().cloned());
        v
    }
}

/// Server-side NAT lifecycle controller.
pub struct NatController {
    config: NatConfig,
    runner: Box<dyn Runner>,
    installed: Option<Vec<Rule>>,
}

impl NatController {
    /// Construct with the default `iptables` binary runner.
    pub fn new(config: NatConfig) -> Self {
        Self { config, runner: Box::new(IptablesRunner::new()), installed: None }
    }

    /// Construct with a caller-supplied runner. Tests use this to
    /// inject a capture-only fake.
    pub fn with_runner(config: NatConfig, runner: Box<dyn Runner>) -> Self {
        Self { config, runner, installed: None }
    }

    /// `true` once [`install`](Self::install) has succeeded and
    /// [`remove`](Self::remove) has not yet been called.
    pub fn is_installed(&self) -> bool {
        self.installed.is_some()
    }

    /// Install the NAT / forward rules. Idempotent at the
    /// controller level — a second call without a matching
    /// `remove` returns `NatError::AlreadyInstalled` rather than
    /// double-installing. Returns [`NatError::Iptables`] if any
    /// individual iptables invocation fails; on partial failure
    /// the function rolls back every rule it had installed so far
    /// before returning so the kernel state stays clean.
    pub fn install(&mut self) -> Result<(), NatError> {
        if self.installed.is_some() {
            return Err(NatError::AlreadyInstalled);
        }
        self.config.validate()?;
        let rules = self.rules();

        let mut committed: Vec<Rule> = Vec::with_capacity(rules.len());
        for rule in &rules {
            let argv = rule.install_argv();
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            if let Err(e) = self.runner.run(&argv_refs) {
                // Roll back every rule we did manage to install.
                for prev in committed.iter().rev() {
                    let argv = prev.remove_argv();
                    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                    let _ = self.runner.run(&argv_refs);
                }
                return Err(NatError::Iptables(e));
            }
            committed.push(rule.clone());
        }
        self.installed = Some(committed);
        Ok(())
    }

    /// Remove exactly the rules [`install`](Self::install)
    /// previously installed, in reverse order. Called from the
    /// daemon's signal handler on shutdown.
    pub fn remove(&mut self) -> Result<(), NatError> {
        let rules = self.installed.take().ok_or(NatError::NotInstalled)?;
        let mut last_err: Option<io::Error> = None;
        for rule in rules.iter().rev() {
            let argv = rule.remove_argv();
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            if let Err(e) = self.runner.run(&argv_refs) {
                // Keep going — we want to remove as much as
                // possible even if one rule has already been
                // torn down by hand.
                last_err = Some(e);
            }
        }
        if let Some(e) = last_err {
            Err(NatError::Iptables(e))
        } else {
            Ok(())
        }
    }

    /// Build the rule set from the current config. Exposed for
    /// tests so they can assert on the shape without touching the
    /// runner.
    fn rules(&self) -> Vec<Rule> {
        let s = |v: &str| v.to_string();
        vec![
            // POSTROUTING MASQUERADE for tunnel traffic on egress.
            Rule {
                table: "nat",
                chain: "POSTROUTING",
                body: vec![
                    s("-s"),
                    self.config.tunnel_cidr.clone(),
                    s("-o"),
                    self.config.egress_iface.clone(),
                    s("-j"),
                    s("MASQUERADE"),
                ],
            },
            // FORWARD ACCEPT from tunnel to egress.
            Rule {
                table: "filter",
                chain: "FORWARD",
                body: vec![
                    s("-i"),
                    self.config.tunnel_iface.clone(),
                    s("-o"),
                    self.config.egress_iface.clone(),
                    s("-j"),
                    s("ACCEPT"),
                ],
            },
            // FORWARD ACCEPT for return traffic (established + related).
            Rule {
                table: "filter",
                chain: "FORWARD",
                body: vec![
                    s("-i"),
                    self.config.egress_iface.clone(),
                    s("-o"),
                    self.config.tunnel_iface.clone(),
                    s("-m"),
                    s("state"),
                    s("--state"),
                    s("RELATED,ESTABLISHED"),
                    s("-j"),
                    s("ACCEPT"),
                ],
            },
        ]
    }
}

impl fmt::Debug for NatController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatController")
            .field("config", &self.config)
            .field("installed", &self.is_installed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Capture-only runner that records every argv invocation and
    /// optionally fails at a specific call index.
    struct CaptureRunner {
        calls: Mutex<Vec<Vec<String>>>,
        fail_at: Option<usize>,
    }

    impl CaptureRunner {
        fn new() -> Self {
            Self { calls: Mutex::new(Vec::new()), fail_at: None }
        }

        fn failing_at(idx: usize) -> Self {
            Self { calls: Mutex::new(Vec::new()), fail_at: Some(idx) }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for CaptureRunner {
        fn run(&self, argv: &[&str]) -> io::Result<()> {
            let mut calls = self.calls.lock().unwrap();
            let idx = calls.len();
            calls.push(argv.iter().map(|s| s.to_string()).collect());
            if Some(idx) == self.fail_at {
                Err(io::Error::new(io::ErrorKind::Other, "simulated iptables failure"))
            } else {
                Ok(())
            }
        }
    }

    fn sample_config() -> NatConfig {
        NatConfig {
            tunnel_iface: "desmos0".to_string(),
            egress_iface: "eth0".to_string(),
            tunnel_cidr: "10.200.0.0/24".to_string(),
        }
    }

    #[test]
    fn config_validate_rejects_empty_tunnel_iface() {
        let mut cfg = sample_config();
        cfg.tunnel_iface.clear();
        assert!(matches!(cfg.validate(), Err(NatError::InvalidConfig(_))));
    }

    #[test]
    fn config_validate_rejects_empty_egress_iface() {
        let mut cfg = sample_config();
        cfg.egress_iface.clear();
        assert!(matches!(cfg.validate(), Err(NatError::InvalidConfig(_))));
    }

    #[test]
    fn config_validate_rejects_cidr_missing_slash() {
        let mut cfg = sample_config();
        cfg.tunnel_cidr = "10.200.0.0".to_string();
        assert!(matches!(cfg.validate(), Err(NatError::InvalidConfig(_))));
    }

    #[test]
    fn rules_shape_is_three_rules_in_expected_order() {
        let ctrl = NatController::new(sample_config());
        let rules = ctrl.rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].table, "nat");
        assert_eq!(rules[0].chain, "POSTROUTING");
        assert_eq!(rules[1].table, "filter");
        assert_eq!(rules[1].chain, "FORWARD");
        assert_eq!(rules[2].table, "filter");
        assert_eq!(rules[2].chain, "FORWARD");
    }

    /// Arc-wrapped capture runner so the test can inspect the call
    /// log after moving ownership into the controller.
    #[derive(Clone)]
    struct SharedRunner(std::sync::Arc<CaptureRunner>);

    impl Runner for SharedRunner {
        fn run(&self, argv: &[&str]) -> io::Result<()> {
            self.0.run(argv)
        }
    }

    #[test]
    fn install_calls_iptables_three_times_with_append() {
        let inner = std::sync::Arc::new(CaptureRunner::new());
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        ctrl.install().unwrap();
        let calls = inner.calls();
        assert_eq!(calls.len(), 3);
        for call in &calls {
            // Every call passes `-t <table>` and uses `-A` to
            // append on install.
            assert_eq!(call[0], "-t");
            assert_eq!(call[2], "-A");
        }
        // First call is the MASQUERADE rule.
        assert!(calls[0].iter().any(|a| a == "MASQUERADE"));
        assert!(calls[0].iter().any(|a| a == "10.200.0.0/24"));
        assert!(calls[0].iter().any(|a| a == "eth0"));
        // Second and third calls are FORWARD ACCEPT.
        assert!(calls[1].iter().any(|a| a == "FORWARD"));
        assert!(calls[2].iter().any(|a| a == "RELATED,ESTABLISHED"));
    }

    #[test]
    fn install_records_installed_state() {
        let inner = std::sync::Arc::new(CaptureRunner::new());
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        assert!(!ctrl.is_installed());
        ctrl.install().unwrap();
        assert!(ctrl.is_installed());
    }

    #[test]
    fn install_twice_returns_already_installed() {
        let inner = std::sync::Arc::new(CaptureRunner::new());
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        ctrl.install().unwrap();
        let err = ctrl.install().unwrap_err();
        assert!(matches!(err, NatError::AlreadyInstalled), "got {err:?}");
    }

    #[test]
    fn remove_before_install_returns_not_installed() {
        let inner = std::sync::Arc::new(CaptureRunner::new());
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        let err = ctrl.remove().unwrap_err();
        assert!(matches!(err, NatError::NotInstalled), "got {err:?}");
    }

    #[test]
    fn remove_issues_delete_calls_in_reverse_order() {
        let inner = std::sync::Arc::new(CaptureRunner::new());
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        ctrl.install().unwrap();
        ctrl.remove().unwrap();
        let calls = inner.calls();
        // 3 install + 3 remove = 6.
        assert_eq!(calls.len(), 6);
        // Install calls used `-A`.
        assert_eq!(calls[0][2], "-A");
        assert_eq!(calls[1][2], "-A");
        assert_eq!(calls[2][2], "-A");
        // Remove calls used `-D` and ran in reverse install order.
        assert_eq!(calls[3][2], "-D");
        assert_eq!(calls[4][2], "-D");
        assert_eq!(calls[5][2], "-D");
        // Reverse order check: the first remove (calls[3]) matches
        // the third install (calls[2]) by body.
        assert_eq!(&calls[3][3..], &calls[2][3..]);
        assert_eq!(&calls[4][3..], &calls[1][3..]);
        assert_eq!(&calls[5][3..], &calls[0][3..]);
        assert!(!ctrl.is_installed());
    }

    #[test]
    fn install_rolls_back_on_middle_failure() {
        // Fail on the second call; the first rule must be
        // removed and `is_installed` must stay false.
        let inner = std::sync::Arc::new(CaptureRunner::failing_at(1));
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        let err = ctrl.install().unwrap_err();
        assert!(matches!(err, NatError::Iptables(_)));
        assert!(!ctrl.is_installed());

        let calls = inner.calls();
        // 1 successful install + 1 failed install + 1 rollback = 3.
        assert_eq!(calls.len(), 3);
        // Third call is a rollback `-D` of the first rule.
        assert_eq!(calls[0][2], "-A");
        assert_eq!(calls[1][2], "-A");
        assert_eq!(calls[2][2], "-D");
        assert_eq!(&calls[2][3..], &calls[0][3..]);
    }

    #[test]
    fn install_rolls_back_on_first_call_failure() {
        // Failure on the very first call — nothing to roll back.
        let inner = std::sync::Arc::new(CaptureRunner::failing_at(0));
        let mut ctrl =
            NatController::with_runner(sample_config(), Box::new(SharedRunner(inner.clone())));
        assert!(ctrl.install().is_err());
        assert_eq!(inner.calls().len(), 1);
        assert!(!ctrl.is_installed());
    }

    #[test]
    fn runner_trait_is_object_safe() {
        let _: Box<dyn Runner> = Box::new(IptablesRunner::new());
    }
}
