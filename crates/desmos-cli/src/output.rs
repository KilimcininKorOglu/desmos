//! Output writer for human-readable CLI text and JSON envelopes.
//!
//! `Writer` picks its mode at construction time based on the global flags
//! and the `NO_COLOR` environment variable, then stays in that mode for the
//! lifetime of the command. The three modes are:
//!
//! - `Colored`: ANSI colour codes for status, warning, and error lines.
//! - `NoColor`: plain text, box-drawing characters still permitted.
//! - `Json`: suppresses all human-oriented decoration; callers emit raw JSON.
//!
//! Colour output respects the `NO_COLOR` environment variable (see
//! <https://no-color.org>) and the `--no-color` CLI flag.

use std::io;
use std::io::IsTerminal;
use std::io::Write;

use crate::parser::GlobalFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Colored,
    NoColor,
    Json,
}

pub struct Writer {
    mode: OutputMode,
}

impl Writer {
    pub fn from_globals(globals: &GlobalFlags) -> Self {
        Self { mode: detect_mode(globals) }
    }

    pub fn with_mode(mode: OutputMode) -> Self {
        Self { mode }
    }

    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    pub fn is_json(&self) -> bool {
        matches!(self.mode, OutputMode::Json)
    }

    pub fn println(&self, line: &str) {
        if self.is_json() {
            return;
        }
        let _ = writeln!(io::stdout(), "{line}");
    }

    pub fn success(&self, line: &str) {
        self.annotated(line, "\x1b[32m", "OK");
    }

    pub fn warn(&self, line: &str) {
        self.annotated(line, "\x1b[33m", "WARN");
    }

    pub fn error(&self, line: &str) {
        if self.is_json() {
            let _ = writeln!(io::stderr(), "{{\"error\":{{\"message\":{}}}}}", json_escape(line));
            return;
        }
        match self.mode {
            OutputMode::Colored => {
                let _ = writeln!(io::stderr(), "\x1b[31mERROR\x1b[0m: {line}");
            }
            OutputMode::NoColor => {
                let _ = writeln!(io::stderr(), "ERROR: {line}");
            }
            OutputMode::Json => {}
        }
    }

    /// Emit a raw JSON string. Only does anything when JSON mode is active.
    pub fn json(&self, payload: &str) {
        if self.is_json() {
            let _ = writeln!(io::stdout(), "{payload}");
        }
    }

    fn annotated(&self, line: &str, ansi: &str, prefix: &str) {
        if self.is_json() {
            return;
        }
        match self.mode {
            OutputMode::Colored => {
                let _ = writeln!(io::stdout(), "{ansi}{prefix}\x1b[0m: {line}");
            }
            OutputMode::NoColor => {
                let _ = writeln!(io::stdout(), "{prefix}: {line}");
            }
            OutputMode::Json => {}
        }
    }
}

fn detect_mode(globals: &GlobalFlags) -> OutputMode {
    if globals.json {
        return OutputMode::Json;
    }
    if globals.no_color || std::env::var_os("NO_COLOR").is_some() || !io::stdout().is_terminal() {
        return OutputMode::NoColor;
    }
    OutputMode::Colored
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
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
    fn json_mode_suppresses_println() {
        let w = Writer::with_mode(OutputMode::Json);
        assert!(w.is_json());
        w.println("hello");
    }

    #[test]
    fn json_escape_handles_control_chars() {
        assert_eq!(json_escape("hi\nworld"), "\"hi\\nworld\"");
        assert_eq!(json_escape("q\"uote"), "\"q\\\"uote\"");
    }
}
