//! Encrypted client runner per platform.
//!
//! Each platform variant opens a TUN, binds one UDP socket per
//! configured interface, performs the Noise IK handshake, and enters
//! the reactor loop calling `forward_tun_to_udp_bonded` (outbound)
//! and `forward_udp_to_tun_encrypted` (inbound).

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
use desmos_proto::SessionId;
#[cfg(unix)]
use desmos_proto::PACKET_OVERHEAD;

#[cfg(unix)]
use desmos_rt::signal;
#[cfg(unix)]
use desmos_rt::Event;
#[cfg(unix)]
use desmos_rt::Interest;
#[cfg(unix)]
use desmos_rt::Reactor;
#[cfg(unix)]
use desmos_rt::Token;
#[cfg(unix)]
use desmos_rt::Tun;
#[cfg(unix)]
use desmos_rt::UdpSocket;

#[cfg(unix)]
use crate::bonding::Engine;
#[cfg(unix)]
use crate::bonding::Link;
#[cfg(unix)]
use crate::bonding::LinkId;
#[cfg(unix)]
use crate::bonding::LinkTable;
#[cfg(unix)]
use crate::config::validate::ClientConfig;
#[cfg(unix)]
use crate::daemon::handshake::client_handshake;
#[cfg(unix)]
use crate::daemon::handshake::load_private_key;
#[cfg(unix)]
use crate::daemon::handshake::parse_public_key_hex;
#[cfg(unix)]
use crate::log::Level;
#[cfg(unix)]
use crate::pipeline::forward_tun_to_udp_bonded;
#[cfg(unix)]
use crate::pipeline::forward_udp_to_tun_encrypted;
#[cfg(unix)]
use crate::pipeline::metrics::PipelineMetrics;
#[cfg(unix)]
use crate::session::Established;
#[cfg(unix)]
use crate::session::Session;

#[cfg(unix)]
const TUN_TOKEN: Token = Token(0);
#[cfg(unix)]
const STATS_INTERVAL: Duration = Duration::from_millis(500);

#[cfg(unix)]
struct SocketEntry {
    link_id: LinkId,
    sock: UdpSocket,
}

// ---- Linux entry point ----------------------------------------------------

#[cfg(target_os = "linux")]
pub fn run_client_linux(
    client_cfg: &ClientConfig,
    engine: &Engine,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
    set_tunnel_state: &dyn Fn(crate::daemon::TunnelState),
) -> io::Result<()> {
    use desmos_rt::EpollReactor;
    use desmos_rt::LinuxTun;

    let mut tun = LinuxTun::create("desmos0")?;
    crate::log!(Level::Info, "daemon", "tun created", iface = tun.name());

    let (mut sockets, session) = setup_sockets_and_handshake(client_cfg, engine)?;
    drop_privileges_if_root()?;
    set_tunnel_state(crate::daemon::TunnelState::Up);

    let mut reactor = EpollReactor::new()?;
    run_reactor_loop(&mut reactor, &mut tun, &mut sockets, &session, engine, metrics, mtu)?;

    set_tunnel_state(crate::daemon::TunnelState::Down);
    Ok(())
}

// ---- macOS entry point ----------------------------------------------------

#[cfg(target_os = "macos")]
pub fn run_client_kqueue(
    client_cfg: &ClientConfig,
    engine: &Engine,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
    set_tunnel_state: &dyn Fn(crate::daemon::TunnelState),
) -> io::Result<()> {
    use desmos_rt::KqueueReactor;
    use desmos_rt::MacosTun;

    let mut tun = MacosTun::create(0)?;
    crate::log!(Level::Info, "daemon", "tun created", iface = tun.name());

    let (mut sockets, session) = setup_sockets_and_handshake(client_cfg, engine)?;
    drop_privileges_if_root()?;
    set_tunnel_state(crate::daemon::TunnelState::Up);

    let mut reactor = KqueueReactor::new()?;
    run_reactor_loop(&mut reactor, &mut tun, &mut sockets, &session, engine, metrics, mtu)?;

    set_tunnel_state(crate::daemon::TunnelState::Down);
    Ok(())
}

// ---- FreeBSD entry point --------------------------------------------------

#[cfg(target_os = "freebsd")]
pub fn run_client_kqueue(
    client_cfg: &ClientConfig,
    engine: &Engine,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
    set_tunnel_state: &dyn Fn(crate::daemon::TunnelState),
) -> io::Result<()> {
    use desmos_rt::FreeBsdTun;
    use desmos_rt::KqueueReactor;

    let mut tun = FreeBsdTun::create(0)?;
    crate::log!(Level::Info, "daemon", "tun created", iface = tun.name());

    let (mut sockets, session) = setup_sockets_and_handshake(client_cfg, engine)?;
    drop_privileges_if_root()?;
    set_tunnel_state(crate::daemon::TunnelState::Up);

    let mut reactor = KqueueReactor::new()?;
    run_reactor_loop(&mut reactor, &mut tun, &mut sockets, &session, engine, metrics, mtu)?;

    set_tunnel_state(crate::daemon::TunnelState::Down);
    Ok(())
}

// ---- Privilege drop -------------------------------------------------------

#[cfg(unix)]
fn drop_privileges_if_root() -> io::Result<()> {
    let uid = unsafe { libc_getuid() };
    if uid != 0 {
        return Ok(());
    }
    let drop_cfg = desmos_rt::DropConfig { uid: 65534, gid: 65534 };
    let priv_state = desmos_rt::Privileged::new(drop_cfg);
    let _unpriv = priv_state.drop_privileges()?;
    crate::log!(Level::Info, "daemon", "privileges dropped", uid = 65534, gid = 65534);
    Ok(())
}

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    getuid()
}

// ---- Shared setup (sockets + handshake, no TUN) ---------------------------

#[cfg(unix)]
fn setup_sockets_and_handshake(
    client_cfg: &ClientConfig,
    engine: &Engine,
) -> io::Result<(Vec<SocketEntry>, Session<Established>)> {
    let server_addr: SocketAddr = client_cfg.server.parse().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("bad server address: {}", client_cfg.server),
        )
    })?;

    let private_key = load_private_key(&client_cfg.private_key_file)?;
    let server_pub = parse_public_key_hex(&client_cfg.server_public_key)?;

    let mut sockets = build_sockets(&client_cfg.interfaces)?;
    if sockets.is_empty() {
        sockets
            .push(SocketEntry { link_id: 1, sock: UdpSocket::bind("0.0.0.0:0".parse().unwrap())? });
    }

    let links: Vec<Link> = sockets
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let weight = client_cfg.interfaces.get(i).map(|ic| ic.weight).unwrap_or(10);
            Link::new(
                entry.link_id,
                entry.sock.bound_device().unwrap_or("default").to_string(),
                server_addr,
                weight,
            )
        })
        .collect();
    engine.swap_links(LinkTable::new(links));

    let session = client_handshake(
        &sockets[0].sock,
        server_addr,
        private_key,
        server_pub,
        SessionId(1),
        b"desmos-v1",
        Some(Duration::from_secs(10)),
    )?;
    crate::log!(Level::Info, "daemon", "handshake complete");

    Ok((sockets, session))
}

// ---- Shared reactor loop --------------------------------------------------

#[cfg(unix)]
fn run_reactor_loop<R: Reactor, T: Tun + AsRawFd>(
    reactor: &mut R,
    tun: &mut T,
    sockets: &mut [SocketEntry],
    session: &Session<Established>,
    engine: &Engine,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
) -> io::Result<()> {
    reactor.register(tun.as_raw_fd(), TUN_TOKEN, Interest::READABLE)?;
    for (i, entry) in sockets.iter().enumerate() {
        reactor.register(entry.sock.as_raw_fd(), Token((i + 1) as u64), Interest::READABLE)?;
    }

    let mut scratch = vec![0u8; mtu + PACKET_OVERHEAD];
    let mut events: Vec<Event> = Vec::with_capacity(64);
    let poll_timeout = Some(Duration::from_millis(250));
    let mut last_stats = Instant::now();

    crate::log!(Level::Info, "daemon", "reactor loop started", links = sockets.len());

    loop {
        if signal::is_shutdown_requested() {
            break;
        }

        events.clear();
        reactor.poll(&mut events, poll_timeout)?;

        for ev in &events {
            if ev.token == TUN_TOKEN {
                loop {
                    match forward_tun_to_udp_bonded(
                        tun,
                        engine,
                        |link_id| sockets.iter().find(|e| e.link_id == link_id).map(|e| &e.sock),
                        session,
                        &mut scratch,
                        metrics,
                    ) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            } else {
                let idx = (ev.token.0 - 1) as usize;
                if let Some(entry) = sockets.get(idx) {
                    loop {
                        match forward_udp_to_tun_encrypted(
                            &entry.sock,
                            tun,
                            session,
                            &mut scratch,
                            metrics,
                        ) {
                            Ok(_) => continue,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == ErrorKind::InvalidData => break,
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        if last_stats.elapsed() >= STATS_INTERVAL {
            last_stats = Instant::now();
            if let Some(ctx) = crate::daemon::try_context() {
                let snap = crate::daemon::StatsSnapshot {
                    metrics: metrics.snapshot(),
                    interfaces: Vec::new(),
                };
                ctx.stats_bus.send(snap);
            }
        }
    }

    crate::log!(Level::Info, "daemon", "reactor loop stopped");
    Ok(())
}

// ---- Socket construction --------------------------------------------------

#[cfg(unix)]
fn build_sockets(
    interfaces: &[crate::config::validate::InterfaceConfig],
) -> io::Result<Vec<SocketEntry>> {
    let mut out = Vec::new();
    for (i, iface) in interfaces.iter().enumerate() {
        if !iface.enabled {
            continue;
        }
        let link_id = (i as LinkId) + 1;
        #[cfg(target_os = "linux")]
        let sock = if iface.name.is_empty() {
            UdpSocket::bind("0.0.0.0:0".parse().unwrap())?
        } else {
            UdpSocket::bind_on_interface(&iface.name)?
        };
        #[cfg(not(target_os = "linux"))]
        let sock = {
            let _ = &iface.name;
            UdpSocket::bind("0.0.0.0:0".parse().unwrap())?
        };
        crate::log!(
            Level::Info,
            "daemon",
            "socket bound",
            link_id = link_id,
            iface = iface.name,
            local = sock.local_addr().unwrap()
        );
        out.push(SocketEntry { link_id, sock });
    }
    Ok(out)
}
