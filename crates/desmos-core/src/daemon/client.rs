//! Encrypted client runner per platform.
//!
//! Each platform variant opens a TUN, binds one UDP socket per
//! configured interface, performs the Noise IK handshake, and enters
//! the reactor loop calling `forward_tun_to_udp_bonded` (outbound)
//! and `forward_udp_to_tun_encrypted` (inbound).

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use desmos_proto::SessionId;
#[cfg(target_os = "linux")]
use desmos_proto::PACKET_OVERHEAD;

#[cfg(target_os = "linux")]
use desmos_rt::signal;
#[cfg(target_os = "linux")]
use desmos_rt::Event;
#[cfg(target_os = "linux")]
use desmos_rt::Interest;
#[cfg(target_os = "linux")]
use desmos_rt::Token;
#[cfg(target_os = "linux")]
use desmos_rt::UdpSocket;

#[cfg(target_os = "linux")]
use crate::bonding::Engine;
#[cfg(target_os = "linux")]
use crate::bonding::Link;
#[cfg(target_os = "linux")]
use crate::bonding::LinkId;
#[cfg(target_os = "linux")]
use crate::bonding::LinkTable;
#[cfg(target_os = "linux")]
use crate::config::validate::ClientConfig;
#[cfg(target_os = "linux")]
use crate::daemon::handshake::client_handshake;
#[cfg(target_os = "linux")]
use crate::daemon::handshake::load_private_key;
#[cfg(target_os = "linux")]
use crate::daemon::handshake::parse_public_key_hex;
#[cfg(target_os = "linux")]
use crate::log::Level;
#[cfg(target_os = "linux")]
use crate::pipeline::forward_tun_to_udp_bonded;
#[cfg(target_os = "linux")]
use crate::pipeline::forward_udp_to_tun_encrypted;
#[cfg(target_os = "linux")]
use crate::pipeline::metrics::PipelineMetrics;
#[cfg(target_os = "linux")]
use crate::session::Established;
#[cfg(target_os = "linux")]
use crate::session::Session;

#[cfg(target_os = "linux")]
const TUN_TOKEN: Token = Token(0);
#[cfg(target_os = "linux")]
const STATS_INTERVAL: Duration = Duration::from_millis(500);

#[cfg(target_os = "linux")]
struct SocketEntry {
    link_id: LinkId,
    sock: UdpSocket,
}

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
    use desmos_rt::Reactor;
    use std::os::fd::AsRawFd;

    let server_addr: SocketAddr = client_cfg.server.parse().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("bad server address: {}", client_cfg.server),
        )
    })?;

    let private_key = load_private_key(&client_cfg.private_key_file)?;
    let server_pub = parse_public_key_hex(&client_cfg.server_public_key)?;

    let mut tun = LinuxTun::create("desmos0")?;
    crate::log!(Level::Info, "daemon", "tun created", iface = tun.name());

    let mut sockets = build_sockets(&client_cfg.interfaces)?;
    if sockets.is_empty() {
        sockets
            .push(SocketEntry { link_id: 1, sock: UdpSocket::bind("0.0.0.0:0".parse().unwrap())? });
    }

    let links: Vec<Arc<Link>> = sockets
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let weight = client_cfg.interfaces.get(i).map(|ic| ic.weight).unwrap_or(10);
            Arc::new(Link::new(
                entry.link_id,
                entry.sock.bound_device().unwrap_or("default").to_string(),
                server_addr,
                weight,
            ))
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

    set_tunnel_state(crate::daemon::TunnelState::Up);

    run_reactor_loop(&mut tun, &mut sockets, &session, engine, metrics, mtu)?;

    set_tunnel_state(crate::daemon::TunnelState::Down);
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_reactor_loop<T: desmos_rt::Tun + std::os::fd::AsRawFd>(
    tun: &mut T,
    sockets: &mut [SocketEntry],
    session: &Session<Established>,
    engine: &Engine,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
) -> io::Result<()> {
    use desmos_rt::EpollReactor;
    use desmos_rt::Reactor;
    use std::os::fd::AsRawFd;

    let mut reactor = EpollReactor::new()?;
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

#[cfg(target_os = "linux")]
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
        let sock = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
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
