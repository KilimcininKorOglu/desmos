//! Server-mode UDP listener loop.
//!
//! Accepts incoming Noise IK handshakes from clients via
//! `ClientRegistry::accept_client_msg1`, then routes encrypted
//! data packets to their established sessions for decryption.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use desmos_proto::Header;
#[cfg(target_os = "linux")]
use desmos_proto::PacketType;
#[cfg(target_os = "linux")]
use desmos_proto::SessionId;
#[cfg(target_os = "linux")]
use desmos_proto::HEADER_LEN;
#[cfg(target_os = "linux")]
use desmos_proto::PACKET_OVERHEAD;

#[cfg(target_os = "linux")]
use desmos_rt::signal;
#[cfg(target_os = "linux")]
use desmos_rt::EpollReactor;
#[cfg(target_os = "linux")]
use desmos_rt::Event;
#[cfg(target_os = "linux")]
use desmos_rt::Interest;
#[cfg(target_os = "linux")]
use desmos_rt::LinuxTun;
#[cfg(target_os = "linux")]
use desmos_rt::Reactor;
#[cfg(target_os = "linux")]
use desmos_rt::Token;
#[cfg(target_os = "linux")]
use desmos_rt::Tun;
#[cfg(target_os = "linux")]
use desmos_rt::UdpSocket;

#[cfg(target_os = "linux")]
use crate::log::Level;
#[cfg(target_os = "linux")]
use crate::pipeline::metrics::PipelineMetrics;
#[cfg(target_os = "linux")]
use crate::server::ratelimit::RateLimiter;
#[cfg(target_os = "linux")]
use crate::server::ClientRegistry;

#[cfg(target_os = "linux")]
const TUN_TOKEN: Token = Token(0);
#[cfg(target_os = "linux")]
const UDP_TOKEN: Token = Token(1);

#[cfg(target_os = "linux")]
pub fn run_server_linux(
    listen_addr: SocketAddr,
    registry: &ClientRegistry,
    metrics: &Arc<PipelineMetrics>,
    mtu: usize,
    set_tunnel_state: &dyn Fn(crate::daemon::TunnelState),
) -> io::Result<()> {
    let mut tun = LinuxTun::create("desmos0")?;
    crate::log!(Level::Info, "server", "tun created", iface = tun.name());

    let udp = UdpSocket::bind(listen_addr)?;
    crate::log!(Level::Info, "server", "listening", addr = listen_addr);

    let mut reactor = EpollReactor::new()?;
    reactor.register(tun.as_raw_fd(), TUN_TOKEN, Interest::READABLE)?;
    reactor.register(udp.as_raw_fd(), UDP_TOKEN, Interest::READABLE)?;

    let rate_limiter = RateLimiter::with_default_policy();
    let mut addr_to_session: HashMap<SocketAddr, SessionId> = HashMap::new();
    let mut scratch = vec![0u8; mtu + PACKET_OVERHEAD];
    let mut events: Vec<Event> = Vec::with_capacity(64);
    let poll_timeout = Some(Duration::from_millis(250));
    let mut last_stats = Instant::now();

    set_tunnel_state(crate::daemon::TunnelState::Up);
    crate::log!(Level::Info, "server", "reactor loop started");

    loop {
        if signal::is_shutdown_requested() {
            break;
        }

        events.clear();
        reactor.poll(&mut events, poll_timeout)?;

        for ev in &events {
            if ev.token == UDP_TOKEN {
                loop {
                    match udp.recv_from(&mut scratch) {
                        Ok((n, from)) => {
                            handle_incoming(
                                &udp,
                                &mut tun,
                                &scratch[..n],
                                from,
                                registry,
                                &rate_limiter,
                                &mut addr_to_session,
                                metrics,
                            );
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            } else if ev.token == TUN_TOKEN {
                loop {
                    let n = match tun.recv(&mut scratch[HEADER_LEN..]) {
                        Ok(n) if n == 0 => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    };
                    let _ = n;
                    // TUN egress routing (client lookup by inner IP) is
                    // not yet implemented — requires inner-IP → session map.
                }
            }
        }

        if last_stats.elapsed() >= Duration::from_millis(500) {
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

    set_tunnel_state(crate::daemon::TunnelState::Down);
    crate::log!(Level::Info, "server", "reactor loop stopped");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_incoming<T: Tun>(
    udp: &UdpSocket,
    tun: &mut T,
    data: &[u8],
    from: SocketAddr,
    registry: &ClientRegistry,
    rate_limiter: &RateLimiter,
    addr_map: &mut HashMap<SocketAddr, SessionId>,
    metrics: &Arc<PipelineMetrics>,
) {
    metrics.record_received(data.len());

    if data.len() < HEADER_LEN {
        metrics.record_bad_header();
        return;
    }

    let header = match Header::decode(&data[..HEADER_LEN]) {
        Ok(h) => h,
        Err(_) => {
            metrics.record_bad_header();
            return;
        }
    };

    if header.packet_type == PacketType::Handshake {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if !rate_limiter.try_admit(from.ip(), now_ms) {
            return;
        }

        match registry.accept_client_msg1(&data[HEADER_LEN..], now_ms) {
            Ok((session_id, msg2)) => {
                addr_map.insert(from, session_id);
                let _ = udp.send_to(&msg2, from);
                crate::log!(
                    Level::Info,
                    "server",
                    "client connected",
                    session = session_id.0,
                    peer = from
                );
            }
            Err(e) => {
                crate::log!(
                    Level::Warn,
                    "server",
                    "handshake rejected",
                    error = format!("{e:?}"),
                    peer = from
                );
            }
        }
        return;
    }

    if let Some(&session_id) = addr_map.get(&from) {
        let table = registry.table();
        if let Some(slot) = table.get(session_id) {
            let guard = slot.lock().unwrap();
            if let crate::session::AnySession::Established(ref session) = *guard {
                let payload = &data[HEADER_LEN..];
                let mut ct = payload.to_vec();
                match session.decrypt_data(header.sequence, &mut ct) {
                    Ok(plaintext) => {
                        let _ = tun.send(&plaintext);
                    }
                    Err(_) => {
                        metrics.record_decrypt_failure();
                    }
                }
            }
        }
    }
}
