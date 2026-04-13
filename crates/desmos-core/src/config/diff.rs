//! Configuration hot-reload diff logic.
//!
//! Compares an old and new [`Config`] and classifies every changed
//! field as either **reload-safe** (can be applied without restarting
//! the tunnel) or **requires-restart** (must reject the update with a
//! typed error).
//!
//! # Reload-unsafe fields
//!
//! These fields affect the listening socket, identity keys, or
//! operating mode.  Changing them at runtime would require tearing
//! down and rebuilding the tunnel, so the API rejects them:
//!
//! - `general.mode`
//! - `server.listen`
//! - `server.private_key_file`
//! - `server.public_key`
//! - `client.server`
//! - `client.private_key_file`
//! - `client.server_public_key`
//!
//! Everything else is reload-safe: bonding strategy, interface
//! weights, MTU, log level, Web UI settings, P2P endpoints, DNS
//! servers, auth method, etc.

use super::validate::{
    BondingStrategy, ClientConfig, Config, GeneralConfig, Mode, P2pConfig, ServerConfig,
    WebuiConfig,
};

/// A field that changed between two configs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedField {
    /// Dotted path like `"client.bonding_strategy"`.
    pub path: String,
    /// Whether this change can be applied at runtime.
    pub safe: bool,
}

/// Result of diffing two configs.
#[derive(Debug, Clone)]
pub struct ConfigDiff {
    /// All fields that differ between old and new.
    pub changes: Vec<ChangedField>,
}

impl ConfigDiff {
    /// Whether all changes are reload-safe.
    pub fn is_safe(&self) -> bool {
        self.changes.iter().all(|c| c.safe)
    }

    /// Whether there are no changes at all.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Return paths of unsafe changes.
    pub fn unsafe_fields(&self) -> Vec<&str> {
        self.changes.iter().filter(|c| !c.safe).map(|c| c.path.as_str()).collect()
    }

    /// Return paths of safe changes.
    pub fn safe_fields(&self) -> Vec<&str> {
        self.changes.iter().filter(|c| c.safe).map(|c| c.path.as_str()).collect()
    }
}

/// Compare two configs and classify every change.
pub fn diff(old: &Config, new: &Config) -> ConfigDiff {
    let mut changes = Vec::new();

    diff_general(&old.general, &new.general, &mut changes);
    diff_option_server(old.server.as_ref(), new.server.as_ref(), &mut changes);
    diff_option_client(old.client.as_ref(), new.client.as_ref(), &mut changes);
    diff_option_webui(old.webui.as_ref(), new.webui.as_ref(), &mut changes);
    diff_option_p2p(old.p2p.as_ref(), new.p2p.as_ref(), &mut changes);

    ConfigDiff { changes }
}

// ---- General ---------------------------------------------------------------

fn diff_general(old: &GeneralConfig, new: &GeneralConfig, out: &mut Vec<ChangedField>) {
    if old.mode != new.mode {
        out.push(ChangedField { path: "general.mode".into(), safe: false });
    }
    if old.log_level != new.log_level {
        out.push(ChangedField { path: "general.log_level".into(), safe: true });
    }
    if old.tunnel_mtu != new.tunnel_mtu {
        out.push(ChangedField { path: "general.tunnel_mtu".into(), safe: true });
    }
}

// ---- Server ----------------------------------------------------------------

fn diff_option_server(
    old: Option<&ServerConfig>,
    new: Option<&ServerConfig>,
    out: &mut Vec<ChangedField>,
) {
    match (old, new) {
        (Some(o), Some(n)) => diff_server(o, n, out),
        (None, Some(_)) => out.push(ChangedField { path: "server".into(), safe: false }),
        (Some(_), None) => out.push(ChangedField { path: "server".into(), safe: false }),
        (None, None) => {}
    }
}

fn diff_server(old: &ServerConfig, new: &ServerConfig, out: &mut Vec<ChangedField>) {
    if old.listen != new.listen {
        out.push(ChangedField { path: "server.listen".into(), safe: false });
    }
    if old.public_key != new.public_key {
        out.push(ChangedField { path: "server.public_key".into(), safe: false });
    }
    if old.private_key_file != new.private_key_file {
        out.push(ChangedField { path: "server.private_key_file".into(), safe: false });
    }
    if old.max_clients != new.max_clients {
        out.push(ChangedField { path: "server.max_clients".into(), safe: true });
    }
    if old.auth != new.auth {
        out.push(ChangedField { path: "server.auth".into(), safe: true });
    }
}

// ---- Client ----------------------------------------------------------------

fn diff_option_client(
    old: Option<&ClientConfig>,
    new: Option<&ClientConfig>,
    out: &mut Vec<ChangedField>,
) {
    match (old, new) {
        (Some(o), Some(n)) => diff_client(o, n, out),
        (None, Some(_)) => out.push(ChangedField { path: "client".into(), safe: false }),
        (Some(_), None) => out.push(ChangedField { path: "client".into(), safe: false }),
        (None, None) => {}
    }
}

fn diff_client(old: &ClientConfig, new: &ClientConfig, out: &mut Vec<ChangedField>) {
    if old.server != new.server {
        out.push(ChangedField { path: "client.server".into(), safe: false });
    }
    if old.server_public_key != new.server_public_key {
        out.push(ChangedField { path: "client.server_public_key".into(), safe: false });
    }
    if old.private_key_file != new.private_key_file {
        out.push(ChangedField { path: "client.private_key_file".into(), safe: false });
    }
    if old.bonding_strategy != new.bonding_strategy {
        out.push(ChangedField { path: "client.bonding_strategy".into(), safe: true });
    }
    if old.reorder_window_ms != new.reorder_window_ms {
        out.push(ChangedField { path: "client.reorder_window_ms".into(), safe: true });
    }
    if old.dns_leak_protection != new.dns_leak_protection {
        out.push(ChangedField { path: "client.dns_leak_protection".into(), safe: true });
    }
    if old.dns_servers != new.dns_servers {
        out.push(ChangedField { path: "client.dns_servers".into(), safe: true });
    }
    if old.interfaces != new.interfaces {
        out.push(ChangedField { path: "client.interfaces".into(), safe: true });
    }
}

// ---- Webui -----------------------------------------------------------------

fn diff_option_webui(
    old: Option<&WebuiConfig>,
    new: Option<&WebuiConfig>,
    out: &mut Vec<ChangedField>,
) {
    match (old, new) {
        (Some(o), Some(n)) => diff_webui(o, n, out),
        (None, Some(_)) => out.push(ChangedField { path: "webui".into(), safe: true }),
        (Some(_), None) => out.push(ChangedField { path: "webui".into(), safe: true }),
        (None, None) => {}
    }
}

fn diff_webui(old: &WebuiConfig, new: &WebuiConfig, out: &mut Vec<ChangedField>) {
    if old.enabled != new.enabled {
        out.push(ChangedField { path: "webui.enabled".into(), safe: true });
    }
    if old.listen != new.listen {
        out.push(ChangedField { path: "webui.listen".into(), safe: true });
    }
    if old.username != new.username {
        out.push(ChangedField { path: "webui.username".into(), safe: true });
    }
    if old.password_hash != new.password_hash {
        out.push(ChangedField { path: "webui.password_hash".into(), safe: true });
    }
}

// ---- P2P -------------------------------------------------------------------

fn diff_option_p2p(old: Option<&P2pConfig>, new: Option<&P2pConfig>, out: &mut Vec<ChangedField>) {
    match (old, new) {
        (Some(o), Some(n)) => diff_p2p(o, n, out),
        (None, Some(_)) => out.push(ChangedField { path: "p2p".into(), safe: true }),
        (Some(_), None) => out.push(ChangedField { path: "p2p".into(), safe: true }),
        (None, None) => {}
    }
}

fn diff_p2p(old: &P2pConfig, new: &P2pConfig, out: &mut Vec<ChangedField>) {
    if old.peer_public_key != new.peer_public_key {
        out.push(ChangedField { path: "p2p.peer_public_key".into(), safe: true });
    }
    if old.peer_endpoint != new.peer_endpoint {
        out.push(ChangedField { path: "p2p.peer_endpoint".into(), safe: true });
    }
    if old.stun_servers != new.stun_servers {
        out.push(ChangedField { path: "p2p.stun_servers".into(), safe: true });
    }
    if old.relay_servers != new.relay_servers {
        out.push(ChangedField { path: "p2p.relay_servers".into(), safe: true });
    }
}

// ---- BondingStrategy Display for API responses -----------------------------

impl BondingStrategy {
    /// Convert to the wire string used in the REST API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round-robin",
            Self::Weighted => "weighted",
            Self::LatencyAdaptive => "latency-adaptive",
            Self::Redundant => "redundant",
        }
    }

    /// Parse from a wire string.
    pub fn from_str_api(s: &str) -> Option<Self> {
        match s {
            "round-robin" => Some(Self::RoundRobin),
            "weighted" => Some(Self::Weighted),
            "latency-adaptive" => Some(Self::LatencyAdaptive),
            "redundant" => Some(Self::Redundant),
            _ => None,
        }
    }
}

impl Mode {
    /// Convert to the wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::P2p => "p2p",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::validate::*;
    use super::*;

    fn base_general() -> GeneralConfig {
        GeneralConfig { mode: Mode::Client, log_level: LogLevel::Info, tunnel_mtu: 1400 }
    }

    fn base_server() -> ServerConfig {
        ServerConfig {
            listen: "0.0.0.0:4789".into(),
            public_key: "pk1".into(),
            private_key_file: "/etc/desmos/key".into(),
            max_clients: 100,
            auth: AuthConfig {
                method: AuthMethod::Psk,
                psk: Some("secret".into()),
                authorized_keys_file: None,
                totp_secret: None,
                ca_cert_file: None,
            },
        }
    }

    fn base_client() -> ClientConfig {
        ClientConfig {
            server: "vpn.example.com:4789".into(),
            server_public_key: "spk".into(),
            private_key_file: "/etc/desmos/client.key".into(),
            bonding_strategy: BondingStrategy::LatencyAdaptive,
            reorder_window_ms: 50,
            dns_leak_protection: true,
            dns_servers: vec!["1.1.1.1".into()],
            interfaces: vec![InterfaceConfig { name: "eth0".into(), weight: 100, enabled: true }],
        }
    }

    fn base_config() -> Config {
        Config {
            general: base_general(),
            server: None,
            client: Some(base_client()),
            webui: None,
            p2p: None,
        }
    }

    #[test]
    fn identical_configs_produce_empty_diff() {
        let c = base_config();
        let d = diff(&c, &c);
        assert!(d.is_empty());
        assert!(d.is_safe());
    }

    #[test]
    fn mode_change_is_unsafe() {
        let old = base_config();
        let mut new = old.clone();
        new.general.mode = Mode::Server;
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert_eq!(d.unsafe_fields(), vec!["general.mode"]);
    }

    #[test]
    fn log_level_change_is_safe() {
        let old = base_config();
        let mut new = old.clone();
        new.general.log_level = LogLevel::Debug;
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["general.log_level"]);
    }

    #[test]
    fn mtu_change_is_safe() {
        let old = base_config();
        let mut new = old.clone();
        new.general.tunnel_mtu = 1500;
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["general.tunnel_mtu"]);
    }

    #[test]
    fn server_listen_change_is_unsafe() {
        let mut old = base_config();
        old.server = Some(base_server());
        let mut new = old.clone();
        new.server.as_mut().unwrap().listen = "0.0.0.0:5000".into();
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert!(d.unsafe_fields().contains(&"server.listen"));
    }

    #[test]
    fn server_max_clients_is_safe() {
        let mut old = base_config();
        old.server = Some(base_server());
        let mut new = old.clone();
        new.server.as_mut().unwrap().max_clients = 200;
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["server.max_clients"]);
    }

    #[test]
    fn client_server_change_is_unsafe() {
        let old = base_config();
        let mut new = old.clone();
        new.client.as_mut().unwrap().server = "other.example.com:4789".into();
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert!(d.unsafe_fields().contains(&"client.server"));
    }

    #[test]
    fn bonding_strategy_change_is_safe() {
        let old = base_config();
        let mut new = old.clone();
        new.client.as_mut().unwrap().bonding_strategy = BondingStrategy::Redundant;
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["client.bonding_strategy"]);
    }

    #[test]
    fn interface_weight_change_is_safe() {
        let old = base_config();
        let mut new = old.clone();
        new.client.as_mut().unwrap().interfaces[0].weight = 200;
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["client.interfaces"]);
    }

    #[test]
    fn adding_section_detected() {
        let old = base_config();
        let mut new = old.clone();
        new.webui = Some(WebuiConfig {
            enabled: true,
            listen: "127.0.0.1:8080".into(),
            username: "admin".into(),
            password_hash: "hash".into(),
        });
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["webui"]);
    }

    #[test]
    fn removing_server_section_is_unsafe() {
        let mut old = base_config();
        old.server = Some(base_server());
        let mut new = old.clone();
        new.server = None;
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert!(d.unsafe_fields().contains(&"server"));
    }

    #[test]
    fn multiple_changes_mixed_safety() {
        let old = base_config();
        let mut new = old.clone();
        new.general.log_level = LogLevel::Warn;
        new.general.mode = Mode::Server;
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert_eq!(d.changes.len(), 2);
        assert_eq!(d.unsafe_fields(), vec!["general.mode"]);
        assert_eq!(d.safe_fields(), vec!["general.log_level"]);
    }

    #[test]
    fn bonding_strategy_roundtrip() {
        for s in &["round-robin", "weighted", "latency-adaptive", "redundant"] {
            let bs = BondingStrategy::from_str_api(s).unwrap();
            assert_eq!(bs.as_str(), *s);
        }
        assert!(BondingStrategy::from_str_api("unknown").is_none());
    }

    #[test]
    fn mode_as_str() {
        assert_eq!(Mode::Client.as_str(), "client");
        assert_eq!(Mode::Server.as_str(), "server");
        assert_eq!(Mode::P2p.as_str(), "p2p");
    }

    #[test]
    fn private_key_file_change_is_unsafe() {
        let old = base_config();
        let mut new = old.clone();
        new.client.as_mut().unwrap().private_key_file = "/new/key".into();
        let d = diff(&old, &new);
        assert!(!d.is_safe());
        assert!(d.unsafe_fields().contains(&"client.private_key_file"));
    }

    #[test]
    fn p2p_section_changes_are_safe() {
        let mut old = base_config();
        old.p2p = Some(P2pConfig {
            peer_public_key: "pk".into(),
            peer_endpoint: "1.2.3.4:4789".into(),
            stun_servers: vec!["stun.example.com".into()],
            relay_servers: vec![],
        });
        let mut new = old.clone();
        new.p2p.as_mut().unwrap().stun_servers = vec!["stun2.example.com".into()];
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["p2p.stun_servers"]);
    }

    #[test]
    fn webui_field_changes_are_safe() {
        let mut old = base_config();
        old.webui = Some(WebuiConfig {
            enabled: true,
            listen: "0.0.0.0:8080".into(),
            username: "admin".into(),
            password_hash: "hash1".into(),
        });
        let mut new = old.clone();
        new.webui.as_mut().unwrap().password_hash = "hash2".into();
        let d = diff(&old, &new);
        assert!(d.is_safe());
        assert_eq!(d.safe_fields(), vec!["webui.password_hash"]);
    }
}
