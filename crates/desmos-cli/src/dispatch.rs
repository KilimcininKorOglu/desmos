//! Subcommand dispatcher. Implements a Chain of Responsibility over a list
//! of `Box<dyn Command>`: the first command whose `name()` matches claims
//! the argv and runs. Unknown names trigger a closest-match suggestion.

use std::io::Write;

use crate::commands;
use crate::errors::CliError;
use crate::errors::CliResult;
use crate::parser::GlobalFlags;
use crate::parser::ParsedArgs;

pub trait Command: Send + Sync {
    fn name(&self) -> &'static str;
    fn synopsis(&self) -> &'static str;
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult;
}

pub struct Dispatcher {
    commands: Vec<Box<dyn Command>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self { commands: Vec::new() }
    }

    pub fn register(mut self, cmd: Box<dyn Command>) -> Self {
        self.commands.push(cmd);
        self
    }

    pub fn with_standard_commands() -> Self {
        commands::all().into_iter().fold(Self::new(), |d, c| d.register(c))
    }

    pub fn command_names(&self) -> Vec<&'static str> {
        self.commands.iter().map(|c| c.name()).collect()
    }

    /// Parse and execute. Returns the process exit code; never panics.
    pub fn dispatch(&self, argv: Vec<String>) -> i32 {
        let parsed = match ParsedArgs::parse(argv) {
            Ok(p) => p,
            Err(e) => {
                self.print_error(&e);
                return e.exit_code();
            }
        };

        if parsed.globals.version {
            let _ = writeln!(std::io::stdout(), "desmos {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }

        if parsed.globals.help && parsed.subcommand.is_none() {
            self.print_help();
            return 0;
        }

        let name = match parsed.subcommand.as_deref() {
            Some(n) => n,
            None => {
                self.print_help();
                return 0;
            }
        };

        let cmd = match self.find(name) {
            Some(c) => c,
            None => {
                let err = CliError::UnknownSubcommand {
                    name: name.to_string(),
                    suggestion: self.closest_match(name),
                };
                self.print_error(&err);
                return err.exit_code();
            }
        };

        if parsed.globals.help {
            let _ = writeln!(std::io::stdout(), "desmos {}: {}", cmd.name(), cmd.synopsis());
            return 0;
        }

        match cmd.run(&parsed.subargs, &parsed.globals) {
            Ok(code) => code,
            Err(e) => {
                self.print_error(&e);
                e.exit_code()
            }
        }
    }

    fn find(&self, name: &str) -> Option<&dyn Command> {
        self.commands.iter().map(|c| c.as_ref()).find(|c| c.name() == name)
    }

    pub fn closest_match(&self, input: &str) -> Option<String> {
        let mut best: Option<(usize, &'static str)> = None;
        for cmd in &self.commands {
            let d = levenshtein(input, cmd.name());
            if d <= 3 && best.map(|(best_d, _)| d < best_d).unwrap_or(true) {
                best = Some((d, cmd.name()));
            }
        }
        best.map(|(_, name)| name.to_string())
    }

    fn print_error(&self, err: &CliError) {
        let _ = writeln!(std::io::stderr(), "{err}");
    }

    fn print_help(&self) {
        let out = std::io::stdout();
        let mut out = out.lock();
        let _ = writeln!(out, "desmos {} — Bond every link.", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(out);
        let _ = writeln!(out, "Usage:");
        let _ = writeln!(out, "  desmos [GLOBAL FLAGS] <subcommand> [ARGS]");
        let _ = writeln!(out);
        let _ = writeln!(out, "Global flags:");
        let _ = writeln!(out, "  -c, --config <PATH>    Path to desmos.toml");
        let _ = writeln!(out, "  -v, --verbose          Increase log verbosity (repeatable)");
        let _ = writeln!(out, "  -q, --quiet            Suppress non-error output");
        let _ = writeln!(out, "      --no-color         Disable ANSI colour output");
        let _ =
            writeln!(out, "      --json             Emit machine-readable JSON instead of text");
        let _ = writeln!(out, "  -h, --help             Show this help text");
        let _ = writeln!(out, "  -V, --version          Print version and exit");
        let _ = writeln!(out);
        let _ = writeln!(out, "Subcommands:");
        let width = self.commands.iter().map(|c| c.name().len()).max().unwrap_or(0);
        for cmd in &self.commands {
            let _ = writeln!(
                out,
                "  {name:<width$}  {synopsis}",
                name = cmd.name(),
                width = width,
                synopsis = cmd.synopsis(),
            );
        }
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::with_standard_commands()
    }
}

/// Classic DP Levenshtein distance. Bounded by `s.len().max(t.len())`.
fn levenshtein(s: &str, t: &str) -> usize {
    let sc: Vec<char> = s.chars().collect();
    let tc: Vec<char> = t.chars().collect();
    let (m, n) = (sc.len(), tc.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if sc[i - 1] == tc[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("status", "status"), 0);
        assert_eq!(levenshtein("satus", "status"), 1);
        assert_eq!(levenshtein("statuss", "status"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn dispatcher_lists_standard_command_names() {
        let d = Dispatcher::with_standard_commands();
        let names = d.command_names();
        assert!(names.contains(&"status"));
        assert!(names.contains(&"up"));
        assert!(names.contains(&"down"));
        assert!(names.contains(&"version"));
    }

    #[test]
    fn closest_match_suggests_for_typos() {
        let d = Dispatcher::with_standard_commands();
        assert_eq!(d.closest_match("satus"), Some("status".to_string()));
        assert_eq!(d.closest_match("xyzzy"), None);
    }

    #[test]
    fn dispatch_unknown_returns_exit_64() {
        let d = Dispatcher::with_standard_commands();
        let code = d.dispatch(vec!["desmos".into(), "waffles".into()]);
        assert_eq!(code, 64);
    }

    #[test]
    fn dispatch_status_returns_one_without_daemon() {
        let d = Dispatcher::with_standard_commands();
        let code = d.dispatch(vec!["desmos".into(), "status".into(), "--json".into()]);
        assert_eq!(code, 1);
    }

    #[test]
    fn dispatch_status_global_json_returns_one_without_daemon() {
        let d = Dispatcher::with_standard_commands();
        let code = d.dispatch(vec!["desmos".into(), "--json".into(), "status".into()]);
        assert_eq!(code, 1);
    }

    #[test]
    fn dispatch_help_prints_without_error() {
        let d = Dispatcher::with_standard_commands();
        let code = d.dispatch(vec!["desmos".into(), "--help".into()]);
        assert_eq!(code, 0);
    }
}
