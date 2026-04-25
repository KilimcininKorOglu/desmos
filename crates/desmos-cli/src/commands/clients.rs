//! `desmos clients` — list or kick connected clients (server mode).
//!
//! Sends IPC commands (`clients_list`, `clients_kick`) to the
//! running daemon. Pure text/JSON formatters are exhaustively
//! unit tested against synthetic `ClientRow` values.
//!
//! # Subcommands
//!
//! - `desmos clients`               → list (default)
//! - `desmos clients list`          → list (explicit)
//! - `desmos clients kick <id>`     → kick the session with id `<id>`
//!
//! # Flags
//!
//! - `--json` (global or subarg) swaps text output for JSON.
//!
//! # JSON shape
//!
//! ```text
//! { "clients": [
//!   { "id": 1, "cn": "alice", "src": "203.0.113.7:51820",
//!     "uptime_s": 42, "bytes_in": 1024, "bytes_out": 2048 }, ...
//! ] }
//! ```
//!
//! Kick response:
//!
//! ```text
//! { "kicked": { "id": 5, "ok": true } }
//! ```

use std::io::Write;

use crate::dispatch::Command;
use crate::errors::CliResult;
use crate::output::json_escape;
use crate::output::Writer;
use crate::parser::GlobalFlags;

/// One row of the `desmos clients` table. Populated by the
/// daemon runner from its `ClientRegistry` snapshot. Kept
/// separate from the internal `ClientRegistry` so the wire /
/// presentation format can evolve without disturbing the
/// server core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRow {
    pub id: u16,
    /// Human-readable identity. `"-"` when no CN is available
    /// (e.g. PSK auth mode).
    pub cn: String,
    /// Source socket address as `ip:port`.
    pub src: String,
    /// Seconds since the Noise handshake completed.
    pub uptime_s: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct ClientsCommand;

impl Command for ClientsCommand {
    fn name(&self) -> &'static str {
        "clients"
    }

    fn synopsis(&self) -> &'static str {
        "List or kick connected clients (server mode)"
    }

    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        let json_mode = is_json(subargs, globals);

        let (sub, rest) = split_subcommand(subargs);
        match sub {
            Some("kick") => run_kick(rest, globals, json_mode),
            Some("list") | None => run_list(globals, json_mode),
            Some(s) => {
                emit_error(
                    &Writer::from_globals(globals),
                    json_mode,
                    &format!("unknown `desmos clients` subcommand: `{s}`"),
                );
                Ok(64)
            }
        }
    }
}

fn run_list(globals: &GlobalFlags, json_mode: bool) -> CliResult {
    let writer = Writer::from_globals(globals);
    match crate::ipc_client::send_command("clients_list") {
        Ok(response) => {
            if json_mode {
                let _ = writeln!(std::io::stdout(), "{response}");
            } else {
                writer.println(&response);
            }
            Ok(0)
        }
        Err(msg) => {
            emit_error(&writer, json_mode, &msg);
            Ok(1)
        }
    }
}

fn run_kick(rest: &[String], globals: &GlobalFlags, json_mode: bool) -> CliResult {
    let writer = Writer::from_globals(globals);

    // Parse the id argument (skip --json flag if it appears).
    let id_str = rest.iter().find(|a| !is_flag(a));
    let id_str = match id_str {
        Some(s) => s,
        None => {
            emit_error(&writer, json_mode, "desmos clients kick: missing <id>");
            return Ok(64);
        }
    };
    let id = match id_str.parse::<u16>() {
        Ok(v) if v != 0 => v,
        _ => {
            emit_error(
                &writer,
                json_mode,
                &format!("desmos clients kick: invalid id `{id_str}` (expect 1..=65535)"),
            );
            return Ok(64);
        }
    };

    let req = format!(r#"{{"command":"clients_kick","id":{id}}}"#);
    match crate::ipc_client::send_command_with_json(&req) {
        Ok(response) => {
            if json_mode {
                let _ = writeln!(std::io::stdout(), "{response}");
            } else {
                writer.println(&response);
            }
            Ok(0)
        }
        Err(msg) => {
            emit_error(&writer, json_mode, &msg);
            Ok(1)
        }
    }
}

fn is_json(subargs: &[String], globals: &GlobalFlags) -> bool {
    globals.json || subargs.iter().any(|a| a == "--json")
}

fn is_flag(s: &str) -> bool {
    s.starts_with('-')
}

fn split_subcommand(subargs: &[String]) -> (Option<&str>, &[String]) {
    let first = subargs.iter().position(|a| !is_flag(a));
    match first {
        Some(idx) => {
            let sub = subargs[idx].as_str();
            let rest = &subargs[idx + 1..];
            (Some(sub), rest)
        }
        None => (None, &[][..]),
    }
}

fn emit_error(writer: &Writer, json_mode: bool, message: &str) {
    if json_mode {
        let payload = format!("{{\"error\":{{\"message\":{}}}}}", json_escape(message));
        let _ = writeln!(std::io::stderr(), "{payload}");
    } else {
        writer.error(message);
    }
}

// ---------------------------------------------------------------------------
// Formatters (pure — no I/O)
// ---------------------------------------------------------------------------

/// Render a slice of [`ClientRow`]s as a human-readable table.
/// Column widths grow to fit the widest value; empty lists
/// produce a single "no clients connected" message.
pub fn format_list_table(rows: &[ClientRow]) -> String {
    if rows.is_empty() {
        return String::from("no clients connected\n");
    }
    let headers = ["ID", "CN", "SRC", "UPTIME", "RX", "TX"];
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    let formatted: Vec<[String; 6]> = rows
        .iter()
        .map(|r| {
            [
                r.id.to_string(),
                r.cn.clone(),
                r.src.clone(),
                format_uptime(r.uptime_s),
                format_bytes(r.bytes_in),
                format_bytes(r.bytes_out),
            ]
        })
        .collect();
    for row in &formatted {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let mut out = String::new();
    // Header row.
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        push_padded(&mut out, h, widths[i]);
    }
    out.push('\n');
    // Separator.
    for (i, w) in widths.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        for _ in 0..*w {
            out.push('-');
        }
    }
    out.push('\n');
    // Data rows.
    for row in &formatted {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            push_padded(&mut out, cell, widths[i]);
        }
        out.push('\n');
    }
    out
}

/// Render a slice of [`ClientRow`]s as a single-line JSON
/// object keyed under `"clients"`.
pub fn format_list_json(rows: &[ClientRow]) -> String {
    let mut out = String::from("{\"clients\":[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":{},\"cn\":{},\"src\":{},\"uptime_s\":{},\"bytes_in\":{},\"bytes_out\":{}}}",
            r.id,
            json_escape(&r.cn),
            json_escape(&r.src),
            r.uptime_s,
            r.bytes_in,
            r.bytes_out,
        ));
    }
    out.push_str("]}");
    out
}

/// Render a kick result as plain text.
pub fn format_kick_text(id: u16, ok: bool) -> String {
    if ok {
        format!("kicked client {id}")
    } else {
        format!("no such client {id}")
    }
}

/// Render a kick result as JSON.
pub fn format_kick_json(id: u16, ok: bool) -> String {
    format!("{{\"kicked\":{{\"id\":{id},\"ok\":{ok}}}}}")
}

fn push_padded(out: &mut String, s: &str, width: usize) {
    out.push_str(s);
    for _ in s.len()..width {
        out.push(' ');
    }
}

fn format_uptime(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if n >= GIB {
        format!("{:.2}GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2}MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2}KiB", n as f64 / KIB as f64)
    } else {
        format!("{n}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u16, cn: &str, src: &str, up: u64, rx: u64, tx: u64) -> ClientRow {
        ClientRow { id, cn: cn.into(), src: src.into(), uptime_s: up, bytes_in: rx, bytes_out: tx }
    }

    #[test]
    fn empty_table_reports_no_clients() {
        let out = format_list_table(&[]);
        assert_eq!(out, "no clients connected\n");
    }

    #[test]
    fn single_row_table_has_header_and_data() {
        let rows = [row(1, "alice", "203.0.113.7:51820", 42, 1024, 2048)];
        let out = format_list_table(&rows);
        assert!(out.contains("ID"));
        assert!(out.contains("alice"));
        assert!(out.contains("203.0.113.7:51820"));
        assert!(out.contains("42s"));
        assert!(out.contains("1.00KiB"));
        assert!(out.contains("2.00KiB"));
    }

    #[test]
    fn multi_row_table_right_pads_columns() {
        let rows = [
            row(1, "a", "1.1.1.1:1", 1, 10, 20),
            row(2222, "loooong", "198.51.100.200:51820", 3600, 2 * 1024 * 1024, 512),
        ];
        let out = format_list_table(&rows);
        // Longest ID is "2222" (4 chars); header "ID" (2) → width = 4.
        // Check both rows preserve alignment by counting the gap after
        // the shortest ID cell: "1   " then spacing.
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() >= 4); // header + separator + 2 rows
        assert!(lines[0].starts_with("ID"));
        assert!(lines[2].starts_with("1   ")); // id 1 padded to width 4
        assert!(lines[3].starts_with("2222"));
    }

    #[test]
    fn empty_list_json_is_still_valid() {
        let out = format_list_json(&[]);
        assert_eq!(out, "{\"clients\":[]}");
    }

    #[test]
    fn single_row_json_matches_expected_shape() {
        let rows = [row(7, "bob", "192.0.2.9:443", 90, 5000, 6000)];
        let out = format_list_json(&rows);
        assert_eq!(
            out,
            "{\"clients\":[{\"id\":7,\"cn\":\"bob\",\"src\":\"192.0.2.9:443\",\"uptime_s\":90,\"bytes_in\":5000,\"bytes_out\":6000}]}"
        );
    }

    #[test]
    fn json_escapes_quotes_in_cn() {
        let rows = [row(1, "na\"me", "1.2.3.4:1", 0, 0, 0)];
        let out = format_list_json(&rows);
        assert!(out.contains("\"cn\":\"na\\\"me\""));
    }

    #[test]
    fn format_uptime_covers_every_magnitude() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(42), "42s");
        assert_eq!(format_uptime(61), "1m01s");
        assert_eq!(format_uptime(3600), "1h00m00s");
        assert_eq!(format_uptime(3661), "1h01m01s");
    }

    #[test]
    fn format_bytes_covers_every_magnitude() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.00KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00GiB");
    }

    #[test]
    fn format_kick_text_branches() {
        assert_eq!(format_kick_text(5, true), "kicked client 5");
        assert_eq!(format_kick_text(5, false), "no such client 5");
    }

    #[test]
    fn format_kick_json_branches() {
        assert_eq!(format_kick_json(5, true), "{\"kicked\":{\"id\":5,\"ok\":true}}");
        assert_eq!(format_kick_json(5, false), "{\"kicked\":{\"id\":5,\"ok\":false}}");
    }

    #[test]
    fn split_subcommand_handles_leading_flags() {
        let args: Vec<String> = vec!["--json".into(), "kick".into(), "5".into()];
        let (sub, rest) = split_subcommand(&args);
        assert_eq!(sub, Some("kick"));
        assert_eq!(rest, &["5".to_string()]);
    }

    #[test]
    fn split_subcommand_handles_no_subcommand() {
        let args: Vec<String> = vec!["--json".into()];
        let (sub, _) = split_subcommand(&args);
        assert_eq!(sub, None);
    }

    #[test]
    fn run_reports_daemon_not_reachable_on_list() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&[], &globals).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn run_rejects_unknown_subcommand() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&["explode".into()], &globals).unwrap();
        assert_eq!(code, 64);
    }

    #[test]
    fn run_kick_requires_an_id() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&["kick".into()], &globals).unwrap();
        assert_eq!(code, 64);
    }

    #[test]
    fn run_kick_rejects_non_numeric_id() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&["kick".into(), "foo".into()], &globals).unwrap();
        assert_eq!(code, 64);
    }

    #[test]
    fn run_kick_rejects_zero_id() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&["kick".into(), "0".into()], &globals).unwrap();
        assert_eq!(code, 64);
    }

    #[test]
    fn run_kick_with_valid_id_reports_daemon_unreachable() {
        let globals = GlobalFlags::default();
        let code = ClientsCommand.run(&["kick".into(), "5".into()], &globals).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn run_kick_accepts_json_flag_in_any_position() {
        let globals = GlobalFlags::default();
        let code =
            ClientsCommand.run(&["kick".into(), "--json".into(), "5".into()], &globals).unwrap();
        assert_eq!(code, 1);
    }
}
