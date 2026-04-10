//! Single-interface plaintext packet pipeline.
//!
//! Phase 1 wires TUN → UDP → TUN with no encryption so we can prove the
//! syscall plumbing end-to-end. Phase 2 replaces the plaintext path with
//! Noise IK + ChaCha20-Poly1305. The pipeline stages live in
//! [`outbound`] and [`inbound`]; this module provides the Linux runner
//! that stitches them together with an [`EpollReactor`].

pub mod inbound;
pub mod outbound;

pub use inbound::forward_udp_to_tun;
pub use outbound::forward_tun_to_udp;

use std::net::SocketAddr;

/// Configuration for [`run_plaintext_linux`]. All fields are required;
/// the caller is responsible for pulling them out of `desmos-core::config`
/// or the CLI.
#[derive(Debug, Clone)]
pub struct PlaintextConfig {
    pub tun_name: String,
    pub listen: SocketAddr,
    pub peer: SocketAddr,
    pub session_id: desmos_proto::SessionId,
    pub mtu: usize,
}

/// Bring up a single TUN, a single UDP socket, and shuttle packets
/// between them until the process is killed. Linux-only in Phase 1.
///
/// Requires `CAP_NET_ADMIN` (TUN) and, if `cfg.listen` is on a privileged
/// port (< 1024) or `SO_BINDTODEVICE` is used, `CAP_NET_RAW`.
#[cfg(target_os = "linux")]
pub fn run_plaintext_linux(cfg: PlaintextConfig) -> std::io::Result<()> {
    use desmos_rt::EpollReactor;
    use desmos_rt::Event;
    use desmos_rt::Interest;
    use desmos_rt::LinuxTun;
    use desmos_rt::Reactor;
    use desmos_rt::Token;
    use desmos_rt::UdpSocket;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;

    use desmos_proto::Seq;

    const TUN_TOKEN: Token = Token(0);
    const UDP_TOKEN: Token = Token(1);

    let mut tun = LinuxTun::create(&cfg.tun_name)?;
    let udp = UdpSocket::bind(cfg.listen)?;

    let mut reactor = EpollReactor::new()?;
    reactor.register(tun.as_raw_fd(), TUN_TOKEN, Interest::READABLE)?;
    reactor.register(udp.as_raw_fd(), UDP_TOKEN, Interest::READABLE)?;

    let mut seq = Seq(0);
    let mut scratch = vec![0u8; cfg.mtu + desmos_proto::PACKET_OVERHEAD];
    let mut events: Vec<Event> = Vec::with_capacity(64);

    loop {
        events.clear();
        reactor.poll(&mut events, None)?;
        for ev in &events {
            if ev.token == TUN_TOKEN {
                loop {
                    match forward_tun_to_udp(
                        &mut tun,
                        &udp,
                        cfg.peer,
                        cfg.session_id,
                        &mut seq,
                        &mut scratch,
                    ) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            } else if ev.token == UDP_TOKEN {
                loop {
                    match forward_udp_to_tun(&udp, &mut tun, &mut scratch) {
                        Ok(_) => continue,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == ErrorKind::InvalidData => {
                            // Drop malformed frames silently in plaintext mode;
                            // Phase 2 counts them via atomic metrics.
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
}
