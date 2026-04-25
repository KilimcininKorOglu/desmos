//! `desmos stats` — server-wide aggregate counters.
//!
//! Shows uptime, connected-client count, total bytes in / out,
//! handshake attempts, handshake rejects, and the current
//! bonding strategy. Renders as either a human-readable block
//! or a flat JSON object. Sends the `stats` IPC command to the
//! running daemon.

use std::io::Write;

use crate::dispatch::Command;
use crate::errors::CliResult;
use crate::output::json_escape;
use crate::output::Writer;
use crate::parser::GlobalFlags;

/// Aggregate server snapshot that the daemon runner will
/// compute from its `ClientRegistry` + bonding engine + NAT
/// controller. Kept as a pure data struct so the formatter
/// can evolve independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub uptime_s: u64,
    pub clients_connected: u32,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub handshakes_accepted: u64,
    pub handshakes_rejected: u64,
    pub bonding_strategy: String,
}

pub struct StatsCommand;

impl Command for StatsCommand {
    fn name(&self) -> &'static str {
        "stats"
    }

    fn synopsis(&self) -> &'static str {
        "Print aggregate server statistics"
    }

    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        let json_mode = globals.json || subargs.iter().any(|a| a == "--json");
        let writer = Writer::from_globals(globals);
        match crate::ipc_client::send_command("stats") {
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
// Formatters
// ---------------------------------------------------------------------------

/// Render a [`StatsSnapshot`] as a flat text block suitable
/// for interactive use.
pub fn format_stats_text(snap: &StatsSnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!("uptime            {}\n", format_uptime(snap.uptime_s)));
    out.push_str(&format!("clients connected {}\n", snap.clients_connected));
    out.push_str(&format!("bytes in          {}\n", format_bytes(snap.total_bytes_in)));
    out.push_str(&format!("bytes out         {}\n", format_bytes(snap.total_bytes_out)));
    out.push_str(&format!(
        "handshakes        {} accepted / {} rejected\n",
        snap.handshakes_accepted, snap.handshakes_rejected
    ));
    out.push_str(&format!("bonding strategy  {}\n", snap.bonding_strategy));
    out
}

/// Render a [`StatsSnapshot`] as a single-line JSON object.
pub fn format_stats_json(snap: &StatsSnapshot) -> String {
    format!(
        "{{\"uptime_s\":{},\"clients_connected\":{},\"total_bytes_in\":{},\"total_bytes_out\":{},\"handshakes_accepted\":{},\"handshakes_rejected\":{},\"bonding_strategy\":{}}}",
        snap.uptime_s,
        snap.clients_connected,
        snap.total_bytes_in,
        snap.total_bytes_out,
        snap.handshakes_accepted,
        snap.handshakes_rejected,
        json_escape(&snap.bonding_strategy),
    )
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

    fn snap() -> StatsSnapshot {
        StatsSnapshot {
            uptime_s: 3_661,
            clients_connected: 17,
            total_bytes_in: 3 * 1024 * 1024,
            total_bytes_out: 2 * 1024 * 1024 * 1024,
            handshakes_accepted: 25,
            handshakes_rejected: 3,
            bonding_strategy: "LatencyAdaptive".into(),
        }
    }

    #[test]
    fn text_block_has_every_row() {
        let out = format_stats_text(&snap());
        assert!(out.contains("uptime            1h01m01s"));
        assert!(out.contains("clients connected 17"));
        assert!(out.contains("bytes in          3.00MiB"));
        assert!(out.contains("bytes out         2.00GiB"));
        assert!(out.contains("handshakes        25 accepted / 3 rejected"));
        assert!(out.contains("bonding strategy  LatencyAdaptive"));
    }

    #[test]
    fn json_matches_flat_shape() {
        let out = format_stats_json(&snap());
        assert_eq!(
            out,
            "{\"uptime_s\":3661,\"clients_connected\":17,\"total_bytes_in\":3145728,\"total_bytes_out\":2147483648,\"handshakes_accepted\":25,\"handshakes_rejected\":3,\"bonding_strategy\":\"LatencyAdaptive\"}"
        );
    }

    #[test]
    fn json_escapes_strategy_name() {
        let mut s = snap();
        s.bonding_strategy = "na\"me".into();
        let out = format_stats_json(&s);
        assert!(out.contains("\"bonding_strategy\":\"na\\\"me\""));
    }

    #[test]
    fn zero_snapshot_renders_cleanly() {
        let s = StatsSnapshot {
            uptime_s: 0,
            clients_connected: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            handshakes_accepted: 0,
            handshakes_rejected: 0,
            bonding_strategy: "RoundRobin".into(),
        };
        let text = format_stats_text(&s);
        assert!(text.contains("uptime            0s"));
        assert!(text.contains("bytes in          0B"));

        let json = format_stats_json(&s);
        assert!(json.contains("\"uptime_s\":0"));
        assert!(json.contains("\"bonding_strategy\":\"RoundRobin\""));
    }

    #[test]
    fn run_reports_daemon_not_reachable() {
        let globals = GlobalFlags::default();
        let code = StatsCommand.run(&[], &globals).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_json_flag_reports_daemon_not_reachable() {
        let globals = GlobalFlags { json: true, ..GlobalFlags::default() };
        let code = StatsCommand.run(&[], &globals).unwrap();
        assert_eq!(code, 1);
    }
}
