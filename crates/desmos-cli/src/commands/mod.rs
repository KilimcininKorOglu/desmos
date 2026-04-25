//! Subcommand implementations. Every command is a small struct that
//! implements [`crate::Command`].

pub mod clients;
pub mod interfaces;
pub mod stats;
pub mod up;

use std::io::Write;

use crate::dispatch::Command;
use crate::errors::CliResult;
use crate::ipc_client;
use crate::output::Writer;
use crate::parser::GlobalFlags;

pub use clients::ClientsCommand;
pub use interfaces::InterfacesCommand;
pub use stats::StatsCommand;
pub use up::UpCommand;

pub fn all() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(UpCommand),
        Box::new(DownCommand),
        Box::new(StatusCommand),
        Box::new(ReloadCommand),
        Box::new(ConfigCommand),
        Box::new(InterfacesCommand),
        Box::new(BondingCommand),
        Box::new(ClientsCommand),
        Box::new(StatsCommand),
        Box::new(LogsCommand),
        Box::new(WebuiCommand),
        Box::new(VersionCommand),
    ]
}

fn is_json_invocation(subargs: &[String], globals: &GlobalFlags) -> bool {
    globals.json || subargs.iter().any(|a| a == "--json")
}

fn ipc_run(command: &str, subargs: &[String], globals: &GlobalFlags) -> CliResult {
    match ipc_client::send_command(command) {
        Ok(response) => {
            if is_json_invocation(subargs, globals) {
                let _ = writeln!(std::io::stdout(), "{response}");
            } else {
                let w = Writer::from_globals(globals);
                w.println(&response);
            }
            Ok(0)
        }
        Err(msg) => {
            let w = Writer::from_globals(globals);
            w.error(&msg);
            Ok(1)
        }
    }
}

pub struct DownCommand;
impl Command for DownCommand {
    fn name(&self) -> &'static str {
        "down"
    }
    fn synopsis(&self) -> &'static str {
        "Tear the tunnel down"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct StatusCommand;
impl Command for StatusCommand {
    fn name(&self) -> &'static str {
        "status"
    }
    fn synopsis(&self) -> &'static str {
        "Show tunnel and link status"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct ReloadCommand;
impl Command for ReloadCommand {
    fn name(&self) -> &'static str {
        "reload"
    }
    fn synopsis(&self) -> &'static str {
        "Hot-reload the running configuration"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct ConfigCommand;
impl Command for ConfigCommand {
    fn name(&self) -> &'static str {
        "config"
    }
    fn synopsis(&self) -> &'static str {
        "Validate, show, or edit configuration"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct BondingCommand;
impl Command for BondingCommand {
    fn name(&self) -> &'static str {
        "bonding"
    }
    fn synopsis(&self) -> &'static str {
        "Show or hot-switch the bonding strategy"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct LogsCommand;
impl Command for LogsCommand {
    fn name(&self) -> &'static str {
        "logs"
    }
    fn synopsis(&self) -> &'static str {
        "Tail recent log entries"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct WebuiCommand;
impl Command for WebuiCommand {
    fn name(&self) -> &'static str {
        "webui"
    }
    fn synopsis(&self) -> &'static str {
        "Manage the embedded Web UI (password, bind address)"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        ipc_run(self.name(), subargs, globals)
    }
}

pub struct VersionCommand;
impl Command for VersionCommand {
    fn name(&self) -> &'static str {
        "version"
    }
    fn synopsis(&self) -> &'static str {
        "Print version and exit"
    }
    fn run(&self, _subargs: &[String], _globals: &GlobalFlags) -> CliResult {
        let _ = writeln!(std::io::stdout(), "desmos {}", env!("CARGO_PKG_VERSION"));
        Ok(0)
    }
}
