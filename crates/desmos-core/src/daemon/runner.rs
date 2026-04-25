//! Daemon runner: the entry point that constructs shared state,
//! spawns service threads, and enters the reactor loop.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

use desmos_rt::signal;

use crate::bonding::Engine;
use crate::bonding::LatencyAdaptive;
use crate::bonding::LinkTable;
use crate::bonding::Redundant;
use crate::bonding::RoundRobin;
use crate::bonding::Weighted;
use crate::broadcast::Broadcast;
use crate::config::validate::BondingStrategy;
use crate::config::validate::Config;
use crate::log::Level;
use crate::pipeline::metrics::PipelineMetrics;

use super::init_context;
use super::DaemonContext;
use super::TunnelState;

pub fn run_daemon(config: Config) -> io::Result<()> {
    signal::install_signal_handlers();

    let strategy: Arc<dyn crate::bonding::BondingStrategy> =
        match config.client.as_ref().map(|c| c.bonding_strategy) {
            Some(BondingStrategy::RoundRobin) | None => Arc::new(RoundRobin::new()),
            Some(BondingStrategy::Weighted) => Arc::new(Weighted::new()),
            Some(BondingStrategy::LatencyAdaptive) => Arc::new(LatencyAdaptive::new()),
            Some(BondingStrategy::Redundant) => Arc::new(Redundant::new()),
        };

    let engine = Engine::new(strategy, LinkTable::new(vec![]));

    let ctx = Arc::new(DaemonContext {
        config: RwLock::new(config),
        engine,
        stats_bus: Arc::new(Broadcast::new(128)),
        log_bus: Arc::new(Broadcast::new(256)),
        metrics: Arc::new(PipelineMetrics::new()),
        tunnel_state: AtomicU8::new(TunnelState::Down as u8),
        started_at: Instant::now(),
        sockets: RwLock::new(HashMap::new()),
        registry: None,
    });

    init_context(ctx);

    crate::log!(Level::Info, "daemon", "started");

    let poll_interval = Duration::from_millis(250);
    loop {
        if signal::is_shutdown_requested() {
            break;
        }
        std::thread::sleep(poll_interval);
    }

    crate::log!(Level::Info, "daemon", "stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::validate::GeneralConfig;
    use crate::config::validate::LogLevel;
    use crate::config::validate::Mode;

    fn minimal_config() -> Config {
        Config {
            general: GeneralConfig {
                mode: Mode::Client,
                log_level: LogLevel::Info,
                tunnel_mtu: 1400,
            },
            server: None,
            client: None,
            webui: None,
            p2p: None,
        }
    }

    #[test]
    fn run_daemon_stops_on_shutdown_signal() {
        signal::request_shutdown();
        let result = run_daemon(minimal_config());
        assert!(result.is_ok());
    }
}
