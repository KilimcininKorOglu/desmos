//! `desmos interfaces` subcommand.
//!
//! Enumerates host interfaces via `desmos-core::net::list` and prints
//! a table (or a JSON array when the caller asked for `--json`).

use std::io::Write;

use desmos_core::net::list;
use desmos_core::net::NetworkInterface;

use crate::dispatch::Command;
use crate::errors::CliError;
use crate::errors::CliResult;
use crate::output::Writer;
use crate::parser::GlobalFlags;

pub struct InterfacesCommand;

impl Command for InterfacesCommand {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    fn synopsis(&self) -> &'static str {
        "List, enable, disable, or reweight bonded interfaces"
    }

    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        // Task 20 only implements the listing path. Sub-verbs like
        // `enable` / `disable` / `reweight` land with the bonding
        // engine in Task 25+.
        if let Some(first) = subargs.first() {
            if first != "list" && !first.starts_with("--") {
                let w = Writer::from_globals(globals);
                w.error(&format!(
                    "desmos interfaces: subcommand `{first}` not recognized. \
                     Only `list` is available."
                ));
                return Ok(64);
            }
        }

        let ifaces = match list() {
            Ok(v) => v,
            Err(e) => {
                return Err(CliError::SubcommandFailed(format!("interface discovery failed: {e}")));
            }
        };

        let w = Writer::from_globals(globals);
        let json_mode = globals.json || subargs.iter().any(|a| a == "--json");
        if json_mode {
            render_json(&ifaces)?;
        } else {
            render_table(&w, &ifaces);
        }
        Ok(0)
    }
}

/// Print a plain-text table with fixed columns. No colour codes here —
/// the `Writer` handles `--no-color`; this function only uses
/// whitespace alignment.
fn render_table(w: &Writer, ifaces: &[NetworkInterface]) {
    if ifaces.is_empty() {
        w.warn("no interfaces reported by the kernel");
        return;
    }
    let name_w = ifaces.iter().map(|i| i.name.len()).max().unwrap_or(4).max(4);
    let state_w = ifaces.iter().map(|i| i.operstate.len()).max().unwrap_or(5).max(5);

    w.println(&format!(
        "{:name_w$}  {:state_w$}  {:17}  {:15}  FLAGS",
        "NAME",
        "STATE",
        "MAC",
        "IPV4",
        name_w = name_w,
        state_w = state_w,
    ));
    for iface in ifaces {
        let first_ipv4 =
            iface.ipv4.first().map(|a| a.to_string()).unwrap_or_else(|| "-".to_string());
        let flag_label = format_flag_label(iface);
        w.println(&format!(
            "{:name_w$}  {:state_w$}  {:17}  {:15}  {flag_label}",
            iface.name,
            iface.operstate,
            iface.mac_string(),
            first_ipv4,
            name_w = name_w,
            state_w = state_w,
        ));
        // If there are extra IPs, print them on continuation lines.
        for extra in iface.ipv4.iter().skip(1) {
            w.println(&format!(
                "{:name_w$}  {:state_w$}  {:17}  {:15}",
                "",
                "",
                "",
                extra.to_string(),
                name_w = name_w,
                state_w = state_w,
            ));
        }
        for extra in iface.ipv6.iter() {
            w.println(&format!(
                "{:name_w$}  {:state_w$}  {:17}  {}",
                "",
                "",
                "",
                extra,
                name_w = name_w,
                state_w = state_w,
            ));
        }
    }
}

fn format_flag_label(iface: &NetworkInterface) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if iface.flags.up {
        parts.push("UP");
    }
    if iface.flags.running {
        parts.push("RUNNING");
    }
    if iface.flags.loopback {
        parts.push("LOOPBACK");
    }
    if iface.flags.point_to_point {
        parts.push("P2P");
    }
    if iface.flags.broadcast {
        parts.push("BROADCAST");
    }
    if iface.flags.multicast {
        parts.push("MULTICAST");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(",")
    }
}

/// Emit the interface list as a minimal JSON array. We hand-roll the
/// encoder because the workspace ships no `serde_json` dependency.
fn render_json(ifaces: &[NetworkInterface]) -> CliResult {
    let mut out = String::from("[");
    for (i, iface) in ifaces.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        out.push_str(&format!("\"name\":{}", json_string(&iface.name)));
        out.push_str(&format!(",\"mac\":{}", json_string(&iface.mac_string())));
        out.push_str(&format!(",\"operstate\":{}", json_string(&iface.operstate)));
        out.push_str(",\"ipv4\":[");
        for (j, a) in iface.ipv4.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&json_string(&a.to_string()));
        }
        out.push_str("],\"ipv6\":[");
        for (j, a) in iface.ipv6.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&json_string(&a.to_string()));
        }
        out.push_str("],\"flags\":{");
        out.push_str(&format!("\"up\":{}", iface.flags.up));
        out.push_str(&format!(",\"running\":{}", iface.flags.running));
        out.push_str(&format!(",\"loopback\":{}", iface.flags.loopback));
        out.push('}');
        out.push('}');
    }
    out.push(']');
    writeln!(std::io::stdout(), "{out}")
        .map_err(|e| CliError::SubcommandFailed(format!("write stdout: {e}")))?;
    Ok(0)
}

/// Minimal JSON string encoder: escapes `\`, `"`, and control characters.
/// Interface names only contain printable ASCII in practice, but we
/// still handle the escape set correctly.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("with \"quotes\""), "\"with \\\"quotes\\\"\"");
        assert_eq!(json_string("back\\slash"), "\"back\\\\slash\"");
        assert_eq!(json_string("tab\there"), "\"tab\\there\"");
    }

    #[test]
    fn format_flag_label_joins_active_flags() {
        let mut iface = NetworkInterface {
            name: "eth0".to_string(),
            mac: [0u8; 6],
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: desmos_core::net::IfaceFlags::default(),
            operstate: "up".to_string(),
        };
        assert_eq!(format_flag_label(&iface), "-");
        iface.flags.up = true;
        iface.flags.running = true;
        assert_eq!(format_flag_label(&iface), "UP,RUNNING");
        iface.flags.loopback = true;
        assert_eq!(format_flag_label(&iface), "UP,RUNNING,LOOPBACK");
    }
}
