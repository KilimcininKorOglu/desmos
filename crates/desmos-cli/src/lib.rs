//! Desmos CLI parser, subcommand dispatcher, and coloured output layer.
//!
//! Respects `NO_COLOR` and `--no-color`. JSON mode disables all decoration.

pub mod commands;
pub mod dispatch;
pub mod errors;
pub mod output;
pub mod parser;

pub use dispatch::Command;
pub use dispatch::Dispatcher;
pub use errors::CliError;
pub use errors::CliResult;
pub use output::OutputMode;
pub use output::Writer;
pub use parser::GlobalFlags;
pub use parser::ParsedArgs;
