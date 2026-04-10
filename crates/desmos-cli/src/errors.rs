//! CLI-layer error type and exit-code mapping.

use core::fmt;

pub type CliResult = Result<i32, CliError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Global or command-level flag was not recognised.
    UnknownFlag(String),
    /// Flag expected a value that was not supplied.
    MissingFlagValue(String),
    /// Flag received an invalid value (e.g. non-numeric where a number was expected).
    InvalidFlagValue { flag: String, value: String, reason: &'static str },
    /// No subcommand given and nothing to default to.
    NoSubcommand,
    /// Subcommand name does not match any registered command.
    UnknownSubcommand { name: String, suggestion: Option<String> },
    /// Subcommand handler failed with a typed message.
    SubcommandFailed(String),
}

impl CliError {
    /// POSIX-style exit code. 64 = EX_USAGE for CLI mistakes.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::UnknownFlag(_)
            | Self::MissingFlagValue(_)
            | Self::InvalidFlagValue { .. }
            | Self::NoSubcommand
            | Self::UnknownSubcommand { .. } => 64,
            Self::SubcommandFailed(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFlag(flag) => {
                write!(f, "cli: unrecognised flag `{flag}`. See `desmos --help`.")
            }
            Self::MissingFlagValue(flag) => {
                write!(f, "cli: flag `{flag}` expected a value. See `desmos --help`.")
            }
            Self::InvalidFlagValue { flag, value, reason } => {
                write!(f, "cli: invalid value `{value}` for `{flag}`. {reason}")
            }
            Self::NoSubcommand => {
                write!(f, "cli: no subcommand given. See `desmos --help`.")
            }
            Self::UnknownSubcommand { name, suggestion } => match suggestion {
                Some(s) => write!(
                    f,
                    "cli: unknown subcommand `{name}`. Did you mean `{s}`? See `desmos --help`."
                ),
                None => write!(f, "cli: unknown subcommand `{name}`. See `desmos --help`."),
            },
            Self::SubcommandFailed(msg) => write!(f, "desmos: {msg}"),
        }
    }
}

impl std::error::Error for CliError {}
