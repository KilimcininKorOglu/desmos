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

    let ctx_ref = super::context();
    let mode = ctx_ref.config.read().unwrap().general.mode;
    let mtu = ctx_ref.config.read().unwrap().general.tunnel_mtu as usize;

    match mode {
        crate::config::validate::Mode::Client => {
            let cfg = ctx_ref.config.read().unwrap();
            let client_cfg = cfg.client.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "client mode requires [client] config")
            })?;
            #[cfg(target_os = "linux")]
            super::client::run_client_linux(
                client_cfg,
                &ctx_ref.engine,
                &ctx_ref.metrics,
                mtu,
                &|s| ctx_ref.set_tunnel_state(s),
            )?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (client_cfg, mtu);
                let poll_interval = Duration::from_millis(250);
                loop {
                    if signal::is_shutdown_requested() {
                        break;
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }
        crate::config::validate::Mode::Server | crate::config::validate::Mode::P2p => {
            let poll_interval = Duration::from_millis(250);
            loop {
                if signal::is_shutdown_requested() {
                    break;
                }
                std::thread::sleep(poll_interval);
            }
        }
    }

    crate::log!(Level::Info, "daemon", "stopped");
    Ok(())
}

// Integration-level tests for `run_daemon` require process isolation
// (signal globals, OnceLock context) and are exercised via
// `scripts/smoke-test.sh` against the real binary instead.
