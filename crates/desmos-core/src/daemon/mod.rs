//! Daemon shared state and process-global context.
//!
//! `DaemonContext` holds every piece of runtime state that the data
//! plane, HTTP handlers, and IPC server need to share.  It is stored
//! in a process-global `OnceLock<Arc<DaemonContext>>` so bare `fn`
//! pointer route handlers (which cannot capture state via closures)
//! can reach it through [`context()`].
//!
//! The pattern mirrors the existing global logger in
//! `crate::log::LOGGER`.

pub mod client;
pub mod handshake;
pub mod ipc;
pub mod runner;
pub mod server_loop;

use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Instant;

use crate::bonding::Engine;
use crate::bonding::LinkId;
use crate::broadcast::Broadcast;
use crate::config::validate::Config;
use crate::log::Entry;
use crate::pipeline::metrics::MetricsSnapshot;
use crate::pipeline::metrics::PipelineMetrics;
use crate::server::ClientRegistry;

use desmos_rt::UdpSocket;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelState {
    Down = 0,
    Up = 1,
    Degraded = 2,
}

impl TunnelState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Up,
            2 => Self::Degraded,
            _ => Self::Down,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Up => "up",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatsSnapshot {
    pub metrics: MetricsSnapshot,
    pub interfaces: Vec<InterfaceSnapshot>,
}

#[derive(Clone, Debug)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub link_id: LinkId,
    pub rtt_us: u64,
    pub loss_pct: f64,
    pub jitter_us: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub state: &'static str,
}

pub struct DaemonContext {
    pub config: RwLock<Config>,
    pub engine: Engine,
    pub stats_bus: Arc<Broadcast<StatsSnapshot>>,
    pub log_bus: Arc<Broadcast<Entry>>,
    pub metrics: Arc<PipelineMetrics>,
    pub tunnel_state: AtomicU8,
    pub started_at: Instant,
    pub sockets: RwLock<HashMap<LinkId, UdpSocket>>,
    pub registry: Option<ClientRegistry>,
}

impl DaemonContext {
    pub fn tunnel_state(&self) -> TunnelState {
        TunnelState::from_u8(self.tunnel_state.load(Ordering::Relaxed))
    }

    pub fn set_tunnel_state(&self, state: TunnelState) {
        self.tunnel_state.store(state as u8, Ordering::Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

static CTX: OnceLock<Arc<DaemonContext>> = OnceLock::new();

pub fn init_context(ctx: Arc<DaemonContext>) {
    let _ = CTX.set(ctx);
}

pub fn context() -> &'static Arc<DaemonContext> {
    CTX.get().expect("DaemonContext not initialized — daemon not running")
}

pub fn try_context() -> Option<&'static Arc<DaemonContext>> {
    CTX.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bonding::Engine;
    use crate::bonding::LinkTable;
    use crate::config::validate::Config;
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
    fn tunnel_state_round_trip() {
        assert_eq!(TunnelState::from_u8(0), TunnelState::Down);
        assert_eq!(TunnelState::from_u8(1), TunnelState::Up);
        assert_eq!(TunnelState::from_u8(2), TunnelState::Degraded);
        assert_eq!(TunnelState::from_u8(255), TunnelState::Down);
    }

    #[test]
    fn tunnel_state_as_str() {
        assert_eq!(TunnelState::Down.as_str(), "down");
        assert_eq!(TunnelState::Up.as_str(), "up");
        assert_eq!(TunnelState::Degraded.as_str(), "degraded");
    }

    #[test]
    fn stats_snapshot_is_clone() {
        let snap = StatsSnapshot {
            metrics: MetricsSnapshot::default(),
            interfaces: vec![InterfaceSnapshot {
                name: "eth0".into(),
                link_id: 1,
                rtt_us: 5000,
                loss_pct: 0.5,
                jitter_us: 200,
                bytes_tx: 1024,
                bytes_rx: 2048,
                state: "active",
            }],
        };
        let clone = snap.clone();
        assert_eq!(clone.interfaces.len(), 1);
        assert_eq!(clone.interfaces[0].name, "eth0");
    }

    #[test]
    fn daemon_context_uptime_and_state() {
        let ctx = DaemonContext {
            config: RwLock::new(minimal_config()),
            engine: Engine::new_with_round_robin(LinkTable::new(vec![])),
            stats_bus: Arc::new(Broadcast::new(64)),
            log_bus: Arc::new(Broadcast::new(64)),
            metrics: Arc::new(PipelineMetrics::new()),
            tunnel_state: AtomicU8::new(TunnelState::Down as u8),
            started_at: Instant::now(),
            sockets: RwLock::new(HashMap::new()),
            registry: None,
        };
        assert_eq!(ctx.tunnel_state(), TunnelState::Down);
        ctx.set_tunnel_state(TunnelState::Up);
        assert_eq!(ctx.tunnel_state(), TunnelState::Up);
        assert!(ctx.uptime_secs() < 2);
    }
}
