//! Subcommand implementations. Every command is a small struct that
//! implements [`crate::Command`]. Task 5 ships stubs; later tasks replace
//! them with real implementations.

use std::io::Write;

use crate::dispatch::Command;
use crate::errors::CliResult;
use crate::output::Writer;
use crate::parser::GlobalFlags;

/// Returns the list of standard commands registered with the dispatcher.
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
        Box::new(LogsCommand),
        Box::new(WebuiCommand),
        Box::new(VersionCommand),
    ]
}

fn is_json_invocation(subargs: &[String], globals: &GlobalFlags) -> bool {
    globals.json || subargs.iter().any(|a| a == "--json")
}

fn stub_run(name: &str, subargs: &[String], globals: &GlobalFlags) -> CliResult {
    if is_json_invocation(subargs, globals) {
        let _ = writeln!(std::io::stdout(), "{{}}");
    } else {
        let w = Writer::from_globals(globals);
        w.println(&format!("desmos: `{name}` not yet implemented"));
    }
    Ok(0)
}

pub struct UpCommand;
impl Command for UpCommand {
    fn name(&self) -> &'static str {
        "up"
    }
    fn synopsis(&self) -> &'static str {
        "Bring the tunnel up"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        stub_run(self.name(), subargs, globals)
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
        stub_run(self.name(), subargs, globals)
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
        if is_json_invocation(subargs, globals) {
            let _ = writeln!(std::io::stdout(), "{{}}");
        } else {
            let w = Writer::from_globals(globals);
            w.println("desmos status: tunnel not running");
        }
        Ok(0)
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
        stub_run(self.name(), subargs, globals)
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
        stub_run(self.name(), subargs, globals)
    }
}

pub struct InterfacesCommand;
impl Command for InterfacesCommand {
    fn name(&self) -> &'static str {
        "interfaces"
    }
    fn synopsis(&self) -> &'static str {
        "List, enable, disable, or reweight bonded interfaces"
    }
    fn run(&self, subargs: &[String], globals: &GlobalFlags) -> CliResult {
        stub_run(self.name(), subargs, globals)
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
        stub_run(self.name(), subargs, globals)
    }
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
        stub_run(self.name(), subargs, globals)
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
        stub_run(self.name(), subargs, globals)
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
        stub_run(self.name(), subargs, globals)
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
