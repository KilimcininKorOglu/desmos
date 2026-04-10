//! Hand-rolled CLI argument parser.
//!
//! Grammar (informal):
//!
//! ```text
//! argv       := program global_flags* subcommand? subargs*
//! global_flags := -c PATH | -c=PATH | --config PATH | --config=PATH
//!             | -v | --verbose
//!             | -q | --quiet
//!             | --no-color
//!             | --json
//!             | -h | --help
//!             | -V | --version
//! subcommand := IDENT
//! subargs    := any string (passed verbatim to the subcommand)
//! ```
//!
//! Short flags may cluster: `-vq` == `-v -q`. `-c` consumes the following
//! token as its value unless an inline form `-c=/path` is used.

use std::path::PathBuf;

use crate::errors::CliError;

#[derive(Debug, Clone, Default)]
pub struct GlobalFlags {
    pub config_path: Option<PathBuf>,
    pub verbose: u8,
    pub quiet: bool,
    pub no_color: bool,
    pub json: bool,
    pub help: bool,
    pub version: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedArgs {
    pub globals: GlobalFlags,
    pub subcommand: Option<String>,
    pub subargs: Vec<String>,
}

impl ParsedArgs {
    /// Parse a full `argv` vector (including `argv[0]`).
    pub fn parse(argv: Vec<String>) -> Result<Self, CliError> {
        let mut out = Self::default();
        let mut iter = argv.into_iter();
        // Discard program name.
        iter.next();

        while let Some(tok) = iter.next() {
            if out.subcommand.is_some() {
                out.subargs.push(tok);
                continue;
            }
            if tok == "--" {
                for rest in iter.by_ref() {
                    out.subargs.push(rest);
                }
                break;
            }
            if let Some(stripped) = tok.strip_prefix("--") {
                handle_long_flag(stripped, &mut iter, &mut out)?;
            } else if let Some(short) = tok.strip_prefix('-') {
                if short.is_empty() {
                    return Err(CliError::UnknownFlag(tok));
                }
                handle_short_flags(short, &mut iter, &mut out, &tok)?;
            } else {
                out.subcommand = Some(tok);
            }
        }

        Ok(out)
    }
}

fn handle_long_flag(
    rest: &str,
    iter: &mut std::vec::IntoIter<String>,
    out: &mut ParsedArgs,
) -> Result<(), CliError> {
    let (name, inline) = match rest.split_once('=') {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (rest, None),
    };
    match name {
        "config" => {
            let value = take_value("--config", inline, iter)?;
            out.globals.config_path = Some(PathBuf::from(value));
        }
        "verbose" => {
            reject_inline("--verbose", inline)?;
            out.globals.verbose = out.globals.verbose.saturating_add(1);
        }
        "quiet" => {
            reject_inline("--quiet", inline)?;
            out.globals.quiet = true;
        }
        "no-color" => {
            reject_inline("--no-color", inline)?;
            out.globals.no_color = true;
        }
        "json" => {
            reject_inline("--json", inline)?;
            out.globals.json = true;
        }
        "help" => {
            reject_inline("--help", inline)?;
            out.globals.help = true;
        }
        "version" => {
            reject_inline("--version", inline)?;
            out.globals.version = true;
        }
        _ => return Err(CliError::UnknownFlag(format!("--{name}"))),
    }
    Ok(())
}

fn handle_short_flags(
    short: &str,
    iter: &mut std::vec::IntoIter<String>,
    out: &mut ParsedArgs,
    original: &str,
) -> Result<(), CliError> {
    // Support `-c=PATH` and `-c PATH`. When the first char is `c`, everything
    // after it (stripping an optional `=`) is the value.
    let mut chars = short.chars();
    while let Some(c) = chars.next() {
        match c {
            'v' => out.globals.verbose = out.globals.verbose.saturating_add(1),
            'q' => out.globals.quiet = true,
            'h' => out.globals.help = true,
            'V' => out.globals.version = true,
            'c' => {
                let mut rest: String = chars.clone().collect();
                if rest.starts_with('=') {
                    rest.remove(0);
                }
                let value = if rest.is_empty() {
                    iter.next().ok_or_else(|| CliError::MissingFlagValue("-c".to_string()))?
                } else {
                    rest
                };
                out.globals.config_path = Some(PathBuf::from(value));
                return Ok(());
            }
            _ => return Err(CliError::UnknownFlag(format!("-{c}"))),
        }
    }
    let _ = original;
    Ok(())
}

fn take_value(
    flag: &str,
    inline: Option<String>,
    iter: &mut std::vec::IntoIter<String>,
) -> Result<String, CliError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    iter.next().ok_or_else(|| CliError::MissingFlagValue(flag.to_string()))
}

fn reject_inline(flag: &str, inline: Option<String>) -> Result<(), CliError> {
    if inline.is_some() {
        return Err(CliError::InvalidFlagValue {
            flag: flag.to_string(),
            value: inline.unwrap_or_default(),
            reason: "this flag takes no value",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(cmd: &[&str]) -> Vec<String> {
        std::iter::once("desmos").chain(cmd.iter().copied()).map(String::from).collect()
    }

    #[test]
    fn empty_argv_parses_to_defaults() {
        let parsed = ParsedArgs::parse(argv(&[])).unwrap();
        assert!(parsed.subcommand.is_none());
        assert_eq!(parsed.globals.verbose, 0);
    }

    #[test]
    fn short_and_long_flags_set_globals() {
        let parsed = ParsedArgs::parse(argv(&["-v", "-v", "-q", "--no-color", "--json"])).unwrap();
        assert_eq!(parsed.globals.verbose, 2);
        assert!(parsed.globals.quiet);
        assert!(parsed.globals.no_color);
        assert!(parsed.globals.json);
    }

    #[test]
    fn clustered_short_flags() {
        let parsed = ParsedArgs::parse(argv(&["-vvq"])).unwrap();
        assert_eq!(parsed.globals.verbose, 2);
        assert!(parsed.globals.quiet);
    }

    #[test]
    fn config_flag_long_and_short_forms() {
        let a = ParsedArgs::parse(argv(&["-c", "/etc/desmos.toml"])).unwrap();
        assert_eq!(a.globals.config_path.as_deref().unwrap().to_str(), Some("/etc/desmos.toml"));
        let b = ParsedArgs::parse(argv(&["-c=/etc/desmos.toml"])).unwrap();
        assert_eq!(b.globals.config_path.as_deref().unwrap().to_str(), Some("/etc/desmos.toml"));
        let c = ParsedArgs::parse(argv(&["--config", "/etc/desmos.toml"])).unwrap();
        assert_eq!(c.globals.config_path.as_deref().unwrap().to_str(), Some("/etc/desmos.toml"));
        let d = ParsedArgs::parse(argv(&["--config=/etc/desmos.toml"])).unwrap();
        assert_eq!(d.globals.config_path.as_deref().unwrap().to_str(), Some("/etc/desmos.toml"));
    }

    #[test]
    fn first_non_flag_becomes_subcommand() {
        let parsed = ParsedArgs::parse(argv(&["-v", "status", "--json"])).unwrap();
        assert_eq!(parsed.subcommand.as_deref(), Some("status"));
        assert_eq!(parsed.subargs, vec!["--json".to_string()]);
    }

    #[test]
    fn everything_after_subcommand_is_passed_through() {
        let parsed = ParsedArgs::parse(argv(&["up", "--", "-v", "--json"])).unwrap();
        assert_eq!(parsed.subcommand.as_deref(), Some("up"));
        assert_eq!(parsed.subargs, vec!["--", "-v", "--json"]);
    }

    #[test]
    fn double_dash_before_subcommand_stops_flag_parsing() {
        let parsed = ParsedArgs::parse(argv(&["--", "status", "-v"])).unwrap();
        assert!(parsed.subcommand.is_none());
        assert_eq!(parsed.subargs, vec!["status", "-v"]);
    }

    #[test]
    fn unknown_long_flag_errors() {
        let err = ParsedArgs::parse(argv(&["--waffles"])).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(ref s) if s == "--waffles"));
    }

    #[test]
    fn unknown_short_flag_errors() {
        let err = ParsedArgs::parse(argv(&["-z"])).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(ref s) if s == "-z"));
    }

    #[test]
    fn missing_value_for_config_errors() {
        let err = ParsedArgs::parse(argv(&["-c"])).unwrap_err();
        assert!(matches!(err, CliError::MissingFlagValue(_)));
    }

    #[test]
    fn help_and_version_flags_captured() {
        let a = ParsedArgs::parse(argv(&["--help"])).unwrap();
        assert!(a.globals.help);
        let b = ParsedArgs::parse(argv(&["-V"])).unwrap();
        assert!(b.globals.version);
    }
}
