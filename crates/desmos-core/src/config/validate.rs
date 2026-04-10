//! Schema validator. Turns a parsed [`Value`] tree into a strongly-typed
//! [`Config`], reporting the first problem with `<path>: <kind>`.
//!
//! The validator is the single place where free-form TOML becomes a
//! guarantee the rest of `desmos-core` can rely on. Every field that
//! downstream code dereferences must be checked here.

use std::collections::BTreeMap;

use super::ParseError;
use super::ParseErrorKind;
use super::Path;
use super::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub general: GeneralConfig,
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
    pub webui: Option<WebuiConfig>,
    pub p2p: Option<P2pConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeneralConfig {
    pub mode: Mode,
    pub log_level: LogLevel,
    pub tunnel_mtu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
    P2p,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerConfig {
    pub listen: String,
    pub public_key: String,
    pub private_key_file: String,
    pub max_clients: u32,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthConfig {
    pub method: AuthMethod,
    pub psk: Option<String>,
    pub authorized_keys_file: Option<String>,
    pub totp_secret: Option<String>,
    pub ca_cert_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Psk,
    Pubkey,
    Totp,
    Mtls,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientConfig {
    pub server: String,
    pub server_public_key: String,
    pub private_key_file: String,
    pub bonding_strategy: BondingStrategy,
    pub reorder_window_ms: u32,
    pub dns_leak_protection: bool,
    pub dns_servers: Vec<String>,
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondingStrategy {
    RoundRobin,
    Weighted,
    LatencyAdaptive,
    Redundant,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceConfig {
    pub name: String,
    pub weight: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WebuiConfig {
    pub enabled: bool,
    pub listen: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct P2pConfig {
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub stun_servers: Vec<String>,
    pub relay_servers: Vec<String>,
}

const ALLOWED_SECTIONS: &[&str] = &["general", "server", "client", "webui", "p2p"];
const MIN_MTU: u32 = 576;
const MAX_MTU: u32 = 9000;
const MAX_REORDER_WINDOW_MS: u32 = 10_000;
const MAX_WEIGHT: u32 = 1000;

impl Config {
    pub fn from_value(v: &Value) -> Result<Self, ParseError> {
        let root = as_table(v, &Path::new())?;
        for k in root.keys() {
            if !ALLOWED_SECTIONS.contains(&k.as_str()) {
                return Err(ParseError::new(ParseErrorKind::UnknownSection(k.clone()), 0, 0));
            }
        }

        let general = parse_general(root, Path::joined(&["general"]))?;
        let server = if root.contains_key("server") {
            Some(parse_server(root, Path::joined(&["server"]))?)
        } else {
            None
        };
        let client = if root.contains_key("client") {
            Some(parse_client(root, Path::joined(&["client"]))?)
        } else {
            None
        };
        let webui = if root.contains_key("webui") {
            Some(parse_webui(root, Path::joined(&["webui"]))?)
        } else {
            None
        };
        let p2p = if root.contains_key("p2p") {
            Some(parse_p2p(root, Path::joined(&["p2p"]))?)
        } else {
            None
        };

        match general.mode {
            Mode::Server if server.is_none() => {
                return Err(missing_field(Path::new(), "server"));
            }
            Mode::Client if client.is_none() => {
                return Err(missing_field(Path::new(), "client"));
            }
            Mode::P2p if p2p.is_none() => {
                return Err(missing_field(Path::new(), "p2p"));
            }
            _ => {}
        }

        Ok(Self { general, server, client, webui, p2p })
    }
}

fn parse_general(root: &BTreeMap<String, Value>, path: Path) -> Result<GeneralConfig, ParseError> {
    let t = require_table(root, &path, "general")?;
    let mode_str = require_string(t, &path, "mode")?;
    let mode = match mode_str.as_str() {
        "client" => Mode::Client,
        "server" => Mode::Server,
        "p2p" => Mode::P2p,
        _ => return Err(out_of_range(path.clone(), "mode")),
    };
    let log_level_str = optional_string(t, "log_level")?.unwrap_or_else(|| "info".to_string());
    let log_level = match log_level_str.as_str() {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => return Err(out_of_range(path.clone(), "log_level")),
    };
    let tunnel_mtu = optional_u32(t, "tunnel_mtu")?.unwrap_or(1400);
    if !(MIN_MTU..=MAX_MTU).contains(&tunnel_mtu) {
        return Err(out_of_range(path, "tunnel_mtu"));
    }
    Ok(GeneralConfig { mode, log_level, tunnel_mtu })
}

fn parse_server(root: &BTreeMap<String, Value>, path: Path) -> Result<ServerConfig, ParseError> {
    let t = require_table(root, &path, "server")?;
    let listen = require_string(t, &path, "listen")?;
    let public_key = require_string(t, &path, "public_key")?;
    let private_key_file = require_string(t, &path, "private_key_file")?;
    let max_clients = optional_u32(t, "max_clients")?.unwrap_or(100);
    if max_clients == 0 {
        return Err(out_of_range(path.clone(), "max_clients"));
    }

    let mut auth_path = path.clone();
    auth_path.push("auth");
    let auth = parse_auth(t, auth_path)?;

    Ok(ServerConfig { listen, public_key, private_key_file, max_clients, auth })
}

fn parse_auth(
    server_table: &BTreeMap<String, Value>,
    path: Path,
) -> Result<AuthConfig, ParseError> {
    let auth = require_table(server_table, &path, "auth")?;
    let method_str = require_string(auth, &path, "method")?;
    let method = match method_str.as_str() {
        "psk" => AuthMethod::Psk,
        "pubkey" => AuthMethod::Pubkey,
        "totp" => AuthMethod::Totp,
        "mtls" => AuthMethod::Mtls,
        _ => return Err(out_of_range(path.clone(), "method")),
    };
    let psk = optional_string(auth, "psk")?;
    let authorized_keys_file = optional_string(auth, "authorized_keys_file")?;
    let totp_secret = optional_string(auth, "totp_secret")?;
    let ca_cert_file = optional_string(auth, "ca_cert_file")?;

    match method {
        AuthMethod::Psk if psk.is_none() => {
            return Err(missing_field(path, "psk"));
        }
        AuthMethod::Pubkey if authorized_keys_file.is_none() => {
            return Err(missing_field(path, "authorized_keys_file"));
        }
        AuthMethod::Totp if totp_secret.is_none() => {
            return Err(missing_field(path, "totp_secret"));
        }
        AuthMethod::Mtls if ca_cert_file.is_none() => {
            return Err(missing_field(path, "ca_cert_file"));
        }
        _ => {}
    }

    Ok(AuthConfig { method, psk, authorized_keys_file, totp_secret, ca_cert_file })
}

fn parse_client(root: &BTreeMap<String, Value>, path: Path) -> Result<ClientConfig, ParseError> {
    let t = require_table(root, &path, "client")?;
    let server = require_string(t, &path, "server")?;
    let server_public_key = require_string(t, &path, "server_public_key")?;
    let private_key_file = require_string(t, &path, "private_key_file")?;

    let strategy_str =
        optional_string(t, "bonding_strategy")?.unwrap_or_else(|| "latency-adaptive".to_string());
    let bonding_strategy = match strategy_str.as_str() {
        "round-robin" => BondingStrategy::RoundRobin,
        "weighted" => BondingStrategy::Weighted,
        "latency-adaptive" => BondingStrategy::LatencyAdaptive,
        "redundant" => BondingStrategy::Redundant,
        _ => return Err(out_of_range(path.clone(), "bonding_strategy")),
    };

    let reorder_window_ms = optional_u32(t, "reorder_window_ms")?.unwrap_or(50);
    if reorder_window_ms > MAX_REORDER_WINDOW_MS {
        return Err(out_of_range(path.clone(), "reorder_window_ms"));
    }

    let dns_leak_protection = optional_bool(t, "dns_leak_protection")?.unwrap_or(true);
    let dns_servers = optional_string_array(t, "dns_servers")?.unwrap_or_default();

    let interfaces_value =
        t.get("interfaces").ok_or_else(|| missing_field(path.clone(), "interfaces"))?;
    let arr = interfaces_value.as_array().ok_or_else(|| {
        type_mismatch(path.clone(), "interfaces", "array", interfaces_value.type_name())
    })?;
    if arr.is_empty() {
        return Err(out_of_range(path.clone(), "interfaces"));
    }
    let mut interfaces = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let mut iface_path = path.clone();
        iface_path.push(format!("interfaces[{i}]"));
        interfaces.push(parse_interface(item, iface_path)?);
    }

    Ok(ClientConfig {
        server,
        server_public_key,
        private_key_file,
        bonding_strategy,
        reorder_window_ms,
        dns_leak_protection,
        dns_servers,
        interfaces,
    })
}

fn parse_interface(v: &Value, path: Path) -> Result<InterfaceConfig, ParseError> {
    let t = as_table(v, &path)?;
    let name = require_string(t, &path, "name")?;
    if name.is_empty() {
        return Err(out_of_range(path, "name"));
    }
    let weight = optional_u32(t, "weight")?.unwrap_or(100);
    if weight == 0 || weight > MAX_WEIGHT {
        return Err(out_of_range(path, "weight"));
    }
    let enabled = optional_bool(t, "enabled")?.unwrap_or(true);
    Ok(InterfaceConfig { name, weight, enabled })
}

fn parse_webui(root: &BTreeMap<String, Value>, path: Path) -> Result<WebuiConfig, ParseError> {
    let t = require_table(root, &path, "webui")?;
    let enabled = optional_bool(t, "enabled")?.unwrap_or(true);
    let listen = optional_string(t, "listen")?.unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let username = optional_string(t, "username")?.unwrap_or_else(|| "admin".to_string());
    let password_hash = require_string(t, &path, "password_hash")?;
    if !is_argon2id_phc(&password_hash) {
        return Err(ParseError::new(
            ParseErrorKind::TypeMismatch { expected: "argon2id PHC string", got: "invalid hash" },
            0,
            0,
        )
        .with_path({
            let mut p = path;
            p.push("password_hash");
            p
        }));
    }
    Ok(WebuiConfig { enabled, listen, username, password_hash })
}

fn parse_p2p(root: &BTreeMap<String, Value>, path: Path) -> Result<P2pConfig, ParseError> {
    let t = require_table(root, &path, "p2p")?;
    let peer_public_key = require_string(t, &path, "peer_public_key")?;
    let peer_endpoint = require_string(t, &path, "peer_endpoint")?;
    let stun_servers = optional_string_array(t, "stun_servers")?.unwrap_or_default();
    let relay_servers = optional_string_array(t, "relay_servers")?.unwrap_or_default();
    Ok(P2pConfig { peer_public_key, peer_endpoint, stun_servers, relay_servers })
}

// ---- helpers ----

fn as_table<'a>(v: &'a Value, path: &Path) -> Result<&'a BTreeMap<String, Value>, ParseError> {
    v.as_table().ok_or_else(|| {
        ParseError::new(
            ParseErrorKind::TypeMismatch { expected: "table", got: v.type_name() },
            0,
            0,
        )
        .with_path(path.clone())
    })
}

fn require_table<'a>(
    parent: &'a BTreeMap<String, Value>,
    parent_path: &Path,
    key: &'static str,
) -> Result<&'a BTreeMap<String, Value>, ParseError> {
    let val = parent.get(key).ok_or_else(|| missing_field(parent_path.clone(), key))?;
    val.as_table().ok_or_else(|| {
        let mut p = parent_path.clone();
        p.push(key);
        type_mismatch_at(p, "table", val.type_name())
    })
}

fn require_string(
    t: &BTreeMap<String, Value>,
    parent_path: &Path,
    key: &'static str,
) -> Result<String, ParseError> {
    let v = t.get(key).ok_or_else(|| missing_field(parent_path.clone(), key))?;
    v.as_string().map(str::to_string).ok_or_else(|| {
        let mut p = parent_path.clone();
        p.push(key);
        type_mismatch_at(p, "string", v.type_name())
    })
}

fn optional_string(
    t: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Option<String>, ParseError> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_string()
            .map(str::to_string)
            .map(Some)
            .ok_or_else(|| type_mismatch_at(Path::joined(&[key]), "string", v.type_name())),
    }
}

fn optional_u32(t: &BTreeMap<String, Value>, key: &'static str) -> Result<Option<u32>, ParseError> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => match v.as_integer() {
            Some(i) if (0..=u32::MAX as i64).contains(&i) => Ok(Some(i as u32)),
            Some(_) => Err(type_mismatch_at(Path::joined(&[key]), "u32", "integer")),
            None => Err(type_mismatch_at(Path::joined(&[key]), "integer", v.type_name())),
        },
    }
}

fn optional_bool(
    t: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Option<bool>, ParseError> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_boolean()
            .map(Some)
            .ok_or_else(|| type_mismatch_at(Path::joined(&[key]), "boolean", v.type_name())),
    }
}

fn optional_string_array(
    t: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Option<Vec<String>>, ParseError> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => {
            let arr = v
                .as_array()
                .ok_or_else(|| type_mismatch_at(Path::joined(&[key]), "array", v.type_name()))?;
            let mut out = Vec::with_capacity(arr.len());
            for (i, item) in arr.iter().enumerate() {
                let s = item.as_string().ok_or_else(|| {
                    type_mismatch_at(
                        Path::joined(&[key, &format!("[{i}]")]),
                        "string",
                        item.type_name(),
                    )
                })?;
                out.push(s.to_string());
            }
            Ok(Some(out))
        }
    }
}

fn missing_field(parent_path: Path, field: &str) -> ParseError {
    ParseError::new(ParseErrorKind::MissingField(field.to_string()), 0, 0).with_path(parent_path)
}

fn out_of_range(parent_path: Path, field: &str) -> ParseError {
    ParseError::new(ParseErrorKind::OutOfRange(field.to_string()), 0, 0).with_path(parent_path)
}

fn type_mismatch(
    parent_path: Path,
    field: &str,
    expected: &'static str,
    got: &'static str,
) -> ParseError {
    let mut p = parent_path;
    p.push(field);
    type_mismatch_at(p, expected, got)
}

fn type_mismatch_at(path: Path, expected: &'static str, got: &'static str) -> ParseError {
    ParseError::new(ParseErrorKind::TypeMismatch { expected, got }, 0, 0).with_path(path)
}

/// Syntactic check for an Argon2id PHC string:
/// `$argon2id$v=N$m=M,t=T,p=P$<salt_b64>$<hash_b64>`.
///
/// Runtime verification uses the `argon2` crate inside `desmos-http`; this
/// check just catches obviously malformed entries during config load.
pub fn is_argon2id_phc(s: &str) -> bool {
    if !s.starts_with("$argon2id$") {
        return false;
    }
    let segments: Vec<&str> = s.split('$').collect();
    // Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
    if segments.len() != 6 {
        return false;
    }
    if !segments[2].starts_with("v=") {
        return false;
    }
    if !segments[3].starts_with("m=")
        || !segments[3].contains(",t=")
        || !segments[3].contains(",p=")
    {
        return false;
    }
    !segments[4].is_empty() && !segments[5].is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    const VALID_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzYWx0$8C9wKcyKj9Yh3IKvQkVtGvSiwqZY9oQWxZ6jjaR9c2c";

    fn example_config(mode: &str, hash: &str) -> String {
        format!(
            r#"
[general]
mode = "{mode}"
log_level = "info"
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4900"
public_key = "pubkey-base64"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[server.auth]
method = "psk"
psk = "topsecret"

[client]
server = "vpn.example.com:4900"
server_public_key = "srv-pubkey-base64"
private_key_file = "/home/u/.config/desmos/client.key"
bonding_strategy = "latency-adaptive"
reorder_window_ms = 50
dns_leak_protection = true
dns_servers = ["1.1.1.1", "8.8.8.8"]

[[client.interfaces]]
name = "eth0"
weight = 100
enabled = true

[[client.interfaces]]
name = "wlan0"
weight = 80
enabled = true

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "{hash}"

[p2p]
peer_public_key = "peer-pub"
peer_endpoint = "peer.example.com:4900"
stun_servers = ["stun.l.google.com:19302"]
"#
        )
    }

    #[test]
    fn parses_full_client_config() {
        let src = example_config("client", VALID_HASH);
        let v = parse(&src).unwrap();
        let cfg = Config::from_value(&v).unwrap();
        assert_eq!(cfg.general.mode, Mode::Client);
        assert_eq!(cfg.general.log_level, LogLevel::Info);
        assert_eq!(cfg.general.tunnel_mtu, 1400);
        let client = cfg.client.as_ref().unwrap();
        assert_eq!(client.bonding_strategy, BondingStrategy::LatencyAdaptive);
        assert_eq!(client.interfaces.len(), 2);
        assert_eq!(client.interfaces[0].name, "eth0");
        assert!(cfg.webui.is_some());
        assert!(cfg.p2p.is_some());
    }

    #[test]
    fn parses_example_file_from_disk() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/desmos.toml.example");
        let bytes = std::fs::read_to_string(path).expect("example config missing");
        let v = parse(&bytes).unwrap();
        let cfg = Config::from_value(&v).unwrap();
        assert_eq!(cfg.general.mode, Mode::Client);
        assert!(cfg.client.is_some());
    }

    #[test]
    fn missing_required_field_reports_missing_field() {
        let src = r#"
[general]
log_level = "info"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        match err.kind {
            ParseErrorKind::MissingField(ref f) => assert_eq!(f, "mode"),
            other => panic!("expected MissingField, got {other:?}"),
        }
        assert!(err.to_string().contains("missing_field: general.mode"));
    }

    #[test]
    fn out_of_range_tunnel_mtu_errors() {
        let src = r#"
[general]
mode = "client"
tunnel_mtu = 100

[client]
server = "vpn.example.com:4900"
server_public_key = "x"
private_key_file = "/tmp/k"

[[client.interfaces]]
name = "eth0"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::OutOfRange(ref f) if f == "tunnel_mtu"));
        assert!(err.to_string().contains("out_of_range: general.tunnel_mtu"));
    }

    #[test]
    fn unknown_section_reports_unknown_section() {
        let src = r#"
[general]
mode = "client"

[weather]
forecast = "sunny"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::UnknownSection(ref s) if s == "weather"));
        assert!(err.to_string().contains("unknown_section: weather"));
    }

    #[test]
    fn mode_server_without_server_section_errors() {
        let src = r#"
[general]
mode = "server"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::MissingField(ref f) if f == "server"));
    }

    #[test]
    fn invalid_argon2_hash_errors() {
        let src = r#"
[general]
mode = "server"

[server]
listen = "0.0.0.0:4900"
public_key = "x"
private_key_file = "/tmp/k"
max_clients = 1

[server.auth]
method = "psk"
psk = "secret"

[webui]
password_hash = "not-a-valid-hash"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        assert!(matches!(
            err.kind,
            ParseErrorKind::TypeMismatch { expected: "argon2id PHC string", .. }
        ));
    }

    #[test]
    fn argon2_phc_recognizer_accepts_valid() {
        assert!(is_argon2id_phc(VALID_HASH));
    }

    #[test]
    fn argon2_phc_recognizer_rejects_garbage() {
        assert!(!is_argon2id_phc(""));
        assert!(!is_argon2id_phc("argon2id"));
        assert!(!is_argon2id_phc("$argon2i$v=19$m=1,t=1,p=1$abc$def"));
        assert!(!is_argon2id_phc("$argon2id$v=19$m=1,t=1,p=1$$def"));
        assert!(!is_argon2id_phc("$argon2id$v=19$m=1$abc$def"));
    }

    #[test]
    fn bad_bonding_strategy_is_out_of_range() {
        let src = r#"
[general]
mode = "client"

[client]
server = "x"
server_public_key = "y"
private_key_file = "z"
bonding_strategy = "telepathy"

[[client.interfaces]]
name = "eth0"
"#;
        let v = parse(src).unwrap();
        let err = Config::from_value(&v).unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::OutOfRange(ref f) if f == "bonding_strategy"));
    }
}
