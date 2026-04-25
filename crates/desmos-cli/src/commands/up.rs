//! `desmos up` subcommand. Default mode starts the encrypted daemon
//! (Noise IK handshake + bonding). `--mode plaintext` is a Linux-only
//! debug variant that wires TUN ↔ UDP without crypto.

use crate::dispatch::Command;
use crate::errors::CliError;
use crate::errors::CliResult;
use crate::output::Writer;
use crate::parser::GlobalFlags;

pub struct UpCommand;

impl Command for UpCommand {
    fn name(&self) -> &'static str {
        "up"
    }

    fn synopsis(&self) -> &'static str {
        "Bring the tunnel up"
    }

    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        let args = parse_up_args(subargs)?;
        match args.mode.as_deref() {
            Some("plaintext") => run_plaintext(&args, globals),
            Some(other) => Err(CliError::InvalidFlagValue {
                flag: "--mode".to_string(),
                value: other.to_string(),
                reason: "supported modes: plaintext",
            }),
            None => run_encrypted(&args, globals),
        }
    }
}

#[derive(Debug, Default)]
struct UpArgs {
    mode: Option<String>,
    config_path: Option<String>,
    tun_name: Option<String>,
    listen: Option<String>,
    peer: Option<String>,
}

fn parse_up_args(subargs: &[String]) -> Result<UpArgs, CliError> {
    let mut out = UpArgs::default();
    let mut iter = subargs.iter();
    while let Some(tok) = iter.next() {
        if let Some(value) = tok.strip_prefix("--mode=") {
            out.mode = Some(value.to_string());
        } else if let Some(value) = tok.strip_prefix("--tun=") {
            out.tun_name = Some(value.to_string());
        } else if let Some(value) = tok.strip_prefix("--listen=") {
            out.listen = Some(value.to_string());
        } else if let Some(value) = tok.strip_prefix("--peer=") {
            out.peer = Some(value.to_string());
        } else if let Some(value) = tok.strip_prefix("--config=") {
            out.config_path = Some(value.to_string());
        } else {
            match tok.as_str() {
                "--mode" => out.mode = Some(take_value("--mode", &mut iter)?),
                "--config" | "-c" => out.config_path = Some(take_value("--config", &mut iter)?),
                "--tun" => out.tun_name = Some(take_value("--tun", &mut iter)?),
                "--listen" => out.listen = Some(take_value("--listen", &mut iter)?),
                "--peer" => out.peer = Some(take_value("--peer", &mut iter)?),
                "--json" | "--no-color" => {}
                other if other.starts_with("--") => {
                    return Err(CliError::UnknownFlag(other.to_string()));
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

fn take_value(flag: &str, iter: &mut std::slice::Iter<'_, String>) -> Result<String, CliError> {
    iter.next().cloned().ok_or_else(|| CliError::MissingFlagValue(flag.to_string()))
}

fn run_encrypted(args: &UpArgs, globals: &GlobalFlags) -> CliResult {
    let config_path = args
        .config_path
        .clone()
        .or_else(|| globals.config_path.as_ref().map(|p| p.display().to_string()))
        .unwrap_or_else(|| "/etc/desmos/desmos.toml".to_string());

    let toml_str = std::fs::read_to_string(&config_path).map_err(|e| {
        CliError::SubcommandFailed(format!("cannot read config {config_path}: {e}"))
    })?;

    let value = desmos_core::config::parse(&toml_str)
        .map_err(|e| CliError::SubcommandFailed(format!("config parse error: {e}")))?;

    let config = desmos_core::config::validate::Config::from_value(&value)
        .map_err(|e| CliError::SubcommandFailed(format!("config validation error: {e}")))?;

    let w = Writer::from_globals(globals);
    w.success(&format!("desmos up: config={config_path} mode={}", config.general.mode.as_str()));

    desmos_core::daemon::runner::run_daemon(config)
        .map_err(|e| CliError::SubcommandFailed(format!("daemon: {e}")))?;

    Ok(0)
}

#[cfg(target_os = "linux")]
fn run_plaintext(args: &UpArgs, globals: &GlobalFlags) -> CliResult {
    use desmos_core::pipeline::run_plaintext_linux;
    use desmos_core::pipeline::PlaintextConfig;
    use desmos_proto::SessionId;

    let tun_name = args.tun_name.clone().unwrap_or_else(|| "desmos0".to_string());
    let listen = args.listen.clone().unwrap_or_else(|| "0.0.0.0:4900".to_string());
    let peer = args.peer.clone().ok_or_else(|| CliError::MissingFlagValue("--peer".to_string()))?;

    let listen = listen.parse().map_err(|_| CliError::InvalidFlagValue {
        flag: "--listen".to_string(),
        value: listen.clone(),
        reason: "expected HOST:PORT",
    })?;
    let peer_addr = peer.parse().map_err(|_| CliError::InvalidFlagValue {
        flag: "--peer".to_string(),
        value: peer.clone(),
        reason: "expected HOST:PORT",
    })?;

    let w = Writer::from_globals(globals);
    w.success(&format!(
        "desmos up: tun={tun_name} listen={listen} peer={peer_addr} mode=plaintext"
    ));

    let cfg =
        PlaintextConfig { tun_name, listen, peer: peer_addr, session_id: SessionId(1), mtu: 1400 };
    run_plaintext_linux(cfg).map_err(|e| CliError::SubcommandFailed(format!("up: {e}")))?;
    Ok(0)
}

#[cfg(not(target_os = "linux"))]
fn run_plaintext(_args: &UpArgs, globals: &GlobalFlags) -> CliResult {
    let w = Writer::from_globals(globals);
    w.error("desmos up --mode plaintext: only available on Linux. Use encrypted mode (no --mode flag) on other platforms.");
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_separate_mode_argument() {
        let a = parse_up_args(&argv(&["--mode", "plaintext"])).unwrap();
        assert_eq!(a.mode.as_deref(), Some("plaintext"));
    }

    #[test]
    fn parses_inline_mode_argument() {
        let a = parse_up_args(&argv(&["--mode=plaintext"])).unwrap();
        assert_eq!(a.mode.as_deref(), Some("plaintext"));
    }

    #[test]
    fn parses_all_recognised_flags() {
        let a = parse_up_args(&argv(&[
            "--mode",
            "plaintext",
            "--tun",
            "desmos0",
            "--listen",
            "0.0.0.0:4900",
            "--peer",
            "127.0.0.1:4901",
        ]))
        .unwrap();
        assert_eq!(a.mode.as_deref(), Some("plaintext"));
        assert_eq!(a.tun_name.as_deref(), Some("desmos0"));
        assert_eq!(a.listen.as_deref(), Some("0.0.0.0:4900"));
        assert_eq!(a.peer.as_deref(), Some("127.0.0.1:4901"));
    }

    #[test]
    fn missing_value_errors() {
        let err = parse_up_args(&argv(&["--mode"])).unwrap_err();
        assert!(matches!(err, CliError::MissingFlagValue(_)));
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse_up_args(&argv(&["--waffles", "yes"])).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(_)));
    }

    #[test]
    fn json_and_no_color_passthrough_are_accepted() {
        let a = parse_up_args(&argv(&["--mode", "plaintext", "--json"])).unwrap();
        assert_eq!(a.mode.as_deref(), Some("plaintext"));
    }
}
