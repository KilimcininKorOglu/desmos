//! Unix domain socket IPC server for CLI → daemon communication.
//!
//! Protocol: JSON-line request/response over a Unix stream socket.
//! Uses inline string formatting rather than `desmos-http::json`
//! because `desmos-core` sits below `desmos-http` in the crate DAG.

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::io::BufRead;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use desmos_rt::signal;

#[cfg(unix)]
use crate::log::Level;

#[cfg(unix)]
const SOCKET_PATH: &str = "/var/run/desmos.sock";

#[cfg(unix)]
pub fn default_socket_path() -> &'static str {
    SOCKET_PATH
}

#[cfg(unix)]
pub fn spawn_ipc_server(path: Option<&str>) -> io::Result<thread::JoinHandle<()>> {
    let path = path.unwrap_or(SOCKET_PATH).to_string();

    if Path::new(&path).exists() {
        let _ = std::fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    crate::log!(Level::Info, "ipc", "listening", path = path);

    let handle = thread::spawn(move || {
        ipc_accept_loop(&listener);
        let _ = std::fs::remove_file(&path);
    });

    Ok(handle)
}

#[cfg(unix)]
fn ipc_accept_loop(listener: &UnixListener) {
    loop {
        if signal::is_shutdown_requested() {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                handle_connection(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(unix)]
fn handle_connection(stream: std::os::unix::net::UnixStream) {
    let reader = io::BufReader::new(&stream);
    let mut writer = io::BufWriter::new(&stream);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = dispatch_command(&line);
        if writeln!(writer, "{response}").is_err() {
            break;
        }
        if writer.flush().is_err() {
            break;
        }
    }
}

#[cfg(unix)]
fn extract_command(json_line: &str) -> Option<&str> {
    let needle = "\"command\"";
    let idx = json_line.find(needle)?;
    let rest = &json_line[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let value_start = 1;
    let value_end = after_colon[value_start..].find('"')?;
    Some(&after_colon[value_start..value_start + value_end])
}

#[cfg(unix)]
fn dispatch_command(line: &str) -> String {
    let command = match extract_command(line) {
        Some(c) => c,
        None => return error_json("missing or invalid 'command' field"),
    };

    match command {
        "status" => cmd_status(),
        "down" => cmd_down(),
        "reload" => cmd_reload(),
        "config" => cmd_config(),
        "bonding" => cmd_bonding(),
        "logs" => cmd_logs(),
        "interfaces" => cmd_interfaces(),
        "clients_list" => cmd_clients_list(),
        "clients_kick" => cmd_clients_kick(line),
        other => error_json(&format!("unknown command: {other}")),
    }
}

#[cfg(unix)]
fn cmd_status() -> String {
    match super::try_context() {
        Some(ctx) => {
            let state = ctx.tunnel_state().as_str();
            let uptime = ctx.uptime_secs();
            let strategy = ctx.engine.current_strategy_name();
            let links = ctx.engine.links_snapshot();
            ok_json(&format!(
                r#"{{"tunnel_state":"{state}","uptime_s":{uptime},"strategy":"{strategy}","link_count":{}}}"#,
                links.len()
            ))
        }
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn cmd_down() -> String {
    signal::request_shutdown();
    ok_json(r#"{"shutdown":true}"#)
}

#[cfg(unix)]
fn cmd_reload() -> String {
    ok_json(r#"{"reloaded":true}"#)
}

#[cfg(unix)]
fn cmd_config() -> String {
    match super::try_context() {
        Some(ctx) => {
            let cfg = ctx.config.read().unwrap();
            let mode = cfg.general.mode.as_str();
            let mtu = cfg.general.tunnel_mtu;
            ok_json(&format!(r#"{{"mode":"{mode}","tunnel_mtu":{mtu}}}"#))
        }
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn cmd_bonding() -> String {
    match super::try_context() {
        Some(ctx) => {
            let strategy = ctx.engine.current_strategy_name();
            let links = ctx.engine.links_snapshot();
            ok_json(&format!(r#"{{"strategy":"{strategy}","link_count":{}}}"#, links.len()))
        }
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn cmd_logs() -> String {
    let entries = crate::log::snapshot_ring();
    let arr: Vec<String> = entries
        .iter()
        .rev()
        .take(50)
        .map(|e| {
            format!(
                r#"{{"level":"{}","target":"{}","message":"{}"}}"#,
                e.level.as_str(),
                e.target,
                e.msg
            )
        })
        .collect();
    ok_json(&format!(r#"{{"entries":[{}]}}"#, arr.join(",")))
}

#[cfg(unix)]
fn cmd_interfaces() -> String {
    match super::try_context() {
        Some(ctx) => {
            let links = ctx.engine.links_snapshot();
            let arr: Vec<String> = links
                .all()
                .iter()
                .map(|link| {
                    format!(
                        r#"{{"name":"{}","id":{},"weight":{}}}"#,
                        link.name, link.id, link.weight
                    )
                })
                .collect();
            ok_json(&format!(r#"{{"interfaces":[{}]}}"#, arr.join(",")))
        }
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn cmd_clients_list() -> String {
    match super::try_context() {
        Some(ctx) => match &ctx.registry {
            Some(reg) => {
                let ids = reg.table().ids();
                let arr: Vec<String> = ids
                    .iter()
                    .map(|id| format!(r#"{{"id":{}}}"#, id.0))
                    .collect();
                ok_json(&format!(
                    r#"{{"clients":[{}],"count":{}}}"#,
                    arr.join(","),
                    ids.len()
                ))
            }
            None => ok_json(r#"{"clients":[],"count":0}"#),
        },
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn cmd_clients_kick(line: &str) -> String {
    let id = match extract_field_u16(line, "id") {
        Some(v) => v,
        None => return error_json("missing or invalid 'id' field"),
    };
    match super::try_context() {
        Some(ctx) => match &ctx.registry {
            Some(reg) => {
                let removed = reg.remove_client(crate::session::SessionId(id)).is_some();
                ok_json(&format!(r#"{{"id":{id},"kicked":{removed}}}"#))
            }
            None => error_json("daemon not in server mode"),
        },
        None => error_json("daemon not running"),
    }
}

#[cfg(unix)]
fn extract_field_u16(json_line: &str, field: &str) -> Option<u16> {
    let needle = format!("\"{field}\"");
    let idx = json_line.find(&needle)?;
    let rest = &json_line[idx + needle.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit())?;
    after_colon[..end].parse().ok()
}

#[cfg(unix)]
fn ok_json(data: &str) -> String {
    format!(r#"{{"ok":true,"data":{data}}}"#)
}

#[cfg(unix)]
fn error_json(msg: &str) -> String {
    format!(r#"{{"ok":false,"error":"{msg}"}}"#)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn extract_command_basic() {
        assert_eq!(extract_command(r#"{"command":"status"}"#), Some("status"));
    }

    #[cfg(unix)]
    #[test]
    fn extract_command_with_args() {
        assert_eq!(extract_command(r#"{"command":"down","args":{}}"#), Some("down"));
    }

    #[cfg(unix)]
    #[test]
    fn extract_command_missing() {
        assert_eq!(extract_command(r#"{"foo":"bar"}"#), None);
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_unknown() {
        let resp = dispatch_command(r#"{"command":"foo"}"#);
        assert!(resp.contains(r#""ok":false"#));
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_down() {
        let resp = dispatch_command(r#"{"command":"down"}"#);
        assert!(resp.contains(r#""ok":true"#));
        assert!(resp.contains(r#""shutdown":true"#));
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_status_without_context() {
        let resp = dispatch_command(r#"{"command":"status"}"#);
        assert!(resp.contains(r#""ok":"#));
    }

    #[cfg(unix)]
    #[test]
    fn ok_json_format() {
        let j = ok_json(r#"{"x":1}"#);
        assert_eq!(j, r#"{"ok":true,"data":{"x":1}}"#);
    }

    #[cfg(unix)]
    #[test]
    fn error_json_format() {
        let j = error_json("bad");
        assert_eq!(j, r#"{"ok":false,"error":"bad"}"#);
    }
}
