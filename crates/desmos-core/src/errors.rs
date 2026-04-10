//! Central error taxonomy for `desmos-core`.
//!
//! Sub-module errors (config, session, auth, bonding, net, rt) will be
//! folded in via `From` impls as those modules land in later tasks.

use core::fmt;

pub type Result<T> = core::result::Result<T, CoreError>;

#[derive(Debug)]
pub enum CoreError {
    Config(ConfigError),
    Io(IoError),
    Internal(&'static str),
}

#[derive(Debug)]
pub struct ConfigError {
    pub path: String,
    pub kind: ConfigErrorKind,
}

#[derive(Debug)]
pub enum ConfigErrorKind {
    MissingField,
    UnknownSection,
    TypeMismatch { expected: &'static str, got: &'static str },
    OutOfRange,
    Parse(String),
}

#[derive(Debug)]
pub struct IoError {
    pub context: &'static str,
    pub source: std::io::Error,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {}: {:?}", e.path, e.kind),
            Self::Io(e) => write!(f, "io: {}: {}", e.context, e.source),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(&e.source),
            _ => None,
        }
    }
}

impl From<IoError> for CoreError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl From<ConfigError> for CoreError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
