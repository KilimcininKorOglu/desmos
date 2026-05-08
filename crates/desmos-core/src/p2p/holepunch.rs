//! UDP hole punching for direct peer-to-peer flow
//! establishment.
//!
//! Given two peers who already know each other's STUN-reflected
//! `(ip, port)` pairs (via whatever signalling channel the
//! daemon carries), both sides run [`hole_punch`] on the same
//! UDP socket that will later carry the DWP data plane. On a
//! **cone NAT** (full-cone / restricted / port-restricted) the
//! first outgoing probe opens the NAT mapping and the peer's
//! matching probe punches through it, typically in the first
//! few hundred milliseconds. On a **symmetric NAT** the peer's
//! real port is not the one STUN saw, so [`HolePunchConfig::peer_alt_ports`]
//! lets the caller spray probes across a small candidate range
//! (usually `port ± N`) as a best-effort fallback. A better
//! fallback is relay which this module deliberately
//! does not try to own.
//!
//! # Wire format
//!
//! The probe packet is deliberately tiny so no NAT drops it on
//! size. 20 bytes:
//!
//! ```text
//! +--------------------+---------------------+
//! | 12-byte magic tag  | 8-byte random nonce |
//! +--------------------+---------------------+
//! ```
//!
//! The magic tag distinguishes a `Ping` from a `Pong`. The
//! nonce lets a side match an incoming `Pong` to the outgoing
//! `Ping` it corresponds to, so the punch completes only when
//! the peer actually received one of our probes (not some
//! leftover from a previous session or a scan attempt).
//!
//! # Algorithm
//!
//! 1. Pick a random 8-byte nonce.
//! 2. Send `Ping(nonce)` to the primary peer address **and**
//!    to every `peer_alt_ports[n]` candidate. This is a single
//!    burst, not a timed schedule — the first burst usually
//!    wins on a cone NAT.
//! 3. Block on [`std::net::UdpSocket::recv_from`] with a
//!    short read timeout. Loop:
//!    - On `Pong(nonce)` matching the stored nonce: return the
//!      source address as the confirmed peer.
//!    - On `Ping(peer_nonce)` from anywhere: reply with
//!      `Pong(peer_nonce)` so the *peer* can finish its own
//!      punch, then keep looping.
//! 4. On each timeout, re-send the full burst.
//! 5. Abort with [`P2pError::Timeout`] after
//!    [`HolePunchConfig::deadline_ms`] total elapsed.
//!
//! This is symmetric: both peers run the same algorithm and
//! converge on the same `(src, dst)` pair once the NAT
//! mappings exist.

use core::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Total wire length of a probe packet: 12-byte magic + 8-byte
/// nonce.
pub const PROBE_LEN: usize = 20;

const PING_MAGIC: &[u8; 12] = b"DESMOS-PING\0";
const PONG_MAGIC: &[u8; 12] = b"DESMOS-PONG\0";

/// The two probe packet kinds walked by [`decode_probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Ping,
    Pong,
}

/// Errors the hole-punching path can surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    /// The burst + wait loop exhausted the caller's deadline
    /// without ever receiving a matching `Pong`.
    Timeout,
    /// `deadline_ms == 0` or the interval was zero — a dead
    /// config that would never progress.
    BadConfig(&'static str),
    /// `std::net::UdpSocket` operation failed.
    Io(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("p2p: hole-punch timed out"),
            Self::BadConfig(r) => write!(f, "p2p: bad config: {r}"),
            Self::Io(e) => write!(f, "p2p: io: {e}"),
        }
    }
}

impl std::error::Error for P2pError {}

/// Configuration passed to [`hole_punch`].
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// STUN-reflected address the peer advertised. Always
    /// probed first.
    pub peer_primary: SocketAddr,
    /// Extra candidate ports to spray against the peer's IP
    /// on every burst. Used as a best-effort symmetric-NAT
    /// fallback — callers typically generate this from
    /// `peer_primary.port() ± N` or from a birthday-attack
    /// span.
    pub peer_alt_ports: Vec<u16>,
    /// Total deadline for the whole punching attempt, in
    /// milliseconds. 1500-3000 ms is typical on the LAN;
    /// 3000-6000 ms across the public internet.
    pub deadline_ms: u64,
    /// How long to wait for a reply between bursts. The burst
    /// cadence is `deadline_ms / interval_ms`, so a 3000 ms
    /// deadline with a 250 ms interval fires 12 bursts.
    pub interval_ms: u64,
}

impl HolePunchConfig {
    /// Quick constructor for a cone-NAT attempt with no
    /// symmetric fallback. Matches the default daemon runner
    /// configuration.
    pub fn cone(peer: SocketAddr, deadline_ms: u64, interval_ms: u64) -> Self {
        Self { peer_primary: peer, peer_alt_ports: Vec::new(), deadline_ms, interval_ms }
    }
}

/// Run the hole-punching loop until the peer is confirmed or
/// the deadline expires. Returns the `SocketAddr` the peer's
/// probes actually arrived from — that is the address the
/// bonding engine should install as the outbound destination
/// for this link.
pub fn hole_punch(socket: &UdpSocket, config: &HolePunchConfig) -> Result<SocketAddr, P2pError> {
    if config.deadline_ms == 0 {
        return Err(P2pError::BadConfig("deadline_ms must be > 0"));
    }
    if config.interval_ms == 0 {
        return Err(P2pError::BadConfig("interval_ms must be > 0"));
    }

    // On Windows, an ICMP port-unreachable in response to a send_to
    // surfaces as WSAECONNRESET on the next recv_from. That would
    // misclassify silent-peer timeouts as fatal I/O errors. Disable
    // the behavior unconditionally; it is a no-op on Unix.
    desmos_rt::socket::disable_udp_connreset(socket).map_err(|e| P2pError::Io(e.to_string()))?;

    let my_nonce = random_nonce();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(config.deadline_ms);
    let mut buf = [0u8; PROBE_LEN];

    loop {
        // Fire one burst: primary + every alt port.
        send_burst(socket, config, &my_nonce).map_err(|e| P2pError::Io(e.to_string()))?;

        // Wait for up to interval_ms for a reply, but clip to
        // the overall deadline so the last interval does not
        // overshoot.
        let now = Instant::now();
        if now >= deadline {
            return Err(P2pError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait = remaining.min(Duration::from_millis(config.interval_ms));
        socket.set_read_timeout(Some(wait)).map_err(|e| P2pError::Io(e.to_string()))?;

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let Some((kind, nonce)) = decode_probe(&buf[..n]) else {
                        continue;
                    };
                    match kind {
                        ProbeKind::Pong => {
                            if nonce == my_nonce {
                                return Ok(from);
                            }
                            // Stale / unrelated Pong — ignore.
                        }
                        ProbeKind::Ping => {
                            // Peer is punching *us* — help them
                            // finish by echoing their nonce.
                            let reply = encode_probe(ProbeKind::Pong, &nonce);
                            let _ = socket.send_to(&reply, from);
                            // Keep draining until the interval
                            // expires, in case the peer's own
                            // Pong is already in our socket queue.
                        }
                    }
                }
                Err(e) => {
                    let kind = e.kind();
                    if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                        break; // fall through to next burst
                    }
                    return Err(P2pError::Io(e.to_string()));
                }
            }
        }

        if Instant::now() >= deadline {
            return Err(P2pError::Timeout);
        }
    }
}

fn send_burst(socket: &UdpSocket, config: &HolePunchConfig, nonce: &[u8; 8]) -> io::Result<()> {
    let ping = encode_probe(ProbeKind::Ping, nonce);
    socket.send_to(&ping, config.peer_primary)?;
    for &alt in &config.peer_alt_ports {
        let alt_addr = SocketAddr::new(config.peer_primary.ip(), alt);
        if alt_addr == config.peer_primary {
            continue;
        }
        // Best-effort spray — individual send failures on one
        // alt port must not abort the burst.
        let _ = socket.send_to(&ping, alt_addr);
    }
    Ok(())
}

/// Build a 20-byte probe: 12-byte magic tag + 8-byte nonce.
pub fn encode_probe(kind: ProbeKind, nonce: &[u8; 8]) -> [u8; PROBE_LEN] {
    let mut out = [0u8; PROBE_LEN];
    let magic = match kind {
        ProbeKind::Ping => PING_MAGIC,
        ProbeKind::Pong => PONG_MAGIC,
    };
    out[..12].copy_from_slice(magic);
    out[12..].copy_from_slice(nonce);
    out
}

/// Parse an incoming 20-byte probe. Returns `None` if the
/// buffer is the wrong length or the magic tag is unknown.
pub fn decode_probe(bytes: &[u8]) -> Option<(ProbeKind, [u8; 8])> {
    if bytes.len() != PROBE_LEN {
        return None;
    }
    let magic = &bytes[..12];
    let kind = if magic == PING_MAGIC {
        ProbeKind::Ping
    } else if magic == PONG_MAGIC {
        ProbeKind::Pong
    } else {
        return None;
    };
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&bytes[12..]);
    Some((kind, nonce))
}

/// 8-byte nonce from a xorshift64 stream seeded by wall-clock
/// nanoseconds and a process-wide atomic counter. Not a
/// cryptographic nonce — it only has to be distinct across
/// in-flight punching attempts inside the same process.
fn random_nonce() -> [u8; 8] {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut state = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    if state == 0 {
        state = 0xBADC_0FFE_E0DD_F00Du64;
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state.to_be_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    fn loopback_pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        (a, b)
    }

    // ---- Pure protocol ---------------------------------------------------

    #[test]
    fn encode_decode_ping_round_trip() {
        let nonce = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let bytes = encode_probe(ProbeKind::Ping, &nonce);
        assert_eq!(bytes.len(), PROBE_LEN);
        let (kind, got) = decode_probe(&bytes).unwrap();
        assert_eq!(kind, ProbeKind::Ping);
        assert_eq!(got, nonce);
    }

    #[test]
    fn encode_decode_pong_round_trip() {
        let nonce = [0xAAu8; 8];
        let bytes = encode_probe(ProbeKind::Pong, &nonce);
        let (kind, got) = decode_probe(&bytes).unwrap();
        assert_eq!(kind, ProbeKind::Pong);
        assert_eq!(got, nonce);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_probe(&[]).is_none());
        assert!(decode_probe(&[0u8; PROBE_LEN - 1]).is_none());
        assert!(decode_probe(&[0u8; PROBE_LEN + 1]).is_none());
    }

    #[test]
    fn decode_rejects_unknown_magic() {
        let mut bytes = encode_probe(ProbeKind::Ping, &[0u8; 8]);
        bytes[0] = b'X';
        assert!(decode_probe(&bytes).is_none());
    }

    #[test]
    fn random_nonces_are_distinct() {
        let a = random_nonce();
        let b = random_nonce();
        assert_ne!(a, b);
    }

    #[test]
    fn bad_config_rejects_zero_deadline() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = HolePunchConfig::cone("127.0.0.1:1".parse().unwrap(), 0, 100);
        let err = hole_punch(&socket, &cfg).unwrap_err();
        assert_eq!(err, P2pError::BadConfig("deadline_ms must be > 0"));
    }

    #[test]
    fn bad_config_rejects_zero_interval() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = HolePunchConfig {
            peer_primary: "127.0.0.1:1".parse().unwrap(),
            peer_alt_ports: Vec::new(),
            deadline_ms: 100,
            interval_ms: 0,
        };
        let err = hole_punch(&socket, &cfg).unwrap_err();
        assert_eq!(err, P2pError::BadConfig("interval_ms must be > 0"));
    }

    // ---- Loopback integration -------------------------------------------

    /// Helper: role-play the *peer* side of a hole punch on a
    /// dedicated thread. It listens on `peer_sock`, echoes
    /// any Ping back as a Pong, and also fires its own Ping
    /// at `expect_src_addr` so the caller's `hole_punch` loop
    /// can decode it as a peer-initiated probe if it wants to.
    fn spawn_cone_peer(
        peer_sock: UdpSocket,
        expect_src_addr: SocketAddr,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buf = [0u8; PROBE_LEN];
            peer_sock.set_read_timeout(Some(Duration::from_millis(3_000))).unwrap();
            // Send our own initial Ping so the caller could
            // decode it as a peer probe, then wait for their
            // Ping and reply.
            let my_nonce = [0xEEu8; 8];
            let ping = encode_probe(ProbeKind::Ping, &my_nonce);
            let _ = peer_sock.send_to(&ping, expect_src_addr);

            // Now wait for the caller's Ping and reply with a
            // matching Pong. Keep draining until we've sent at
            // least one Pong.
            loop {
                match peer_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if let Some((kind, nonce)) = decode_probe(&buf[..n]) {
                            if kind == ProbeKind::Ping {
                                let pong = encode_probe(ProbeKind::Pong, &nonce);
                                peer_sock.send_to(&pong, from).unwrap();
                                return;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        })
    }

    #[test]
    fn cone_hole_punch_completes_on_first_burst_over_loopback() {
        let (caller_sock, peer_sock) = loopback_pair();
        let caller_addr = caller_sock.local_addr().unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();

        let handle = spawn_cone_peer(peer_sock, caller_addr);

        let cfg = HolePunchConfig::cone(peer_addr, 2_000, 200);
        let confirmed = hole_punch(&caller_sock, &cfg).unwrap();
        // Loopback confirms the peer's IP + ephemeral port we
        // bound earlier.
        assert_eq!(confirmed.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(confirmed, peer_addr);

        handle.join().unwrap();
    }

    #[test]
    fn caller_replies_to_peer_initiated_ping_so_peer_can_finish() {
        // Inverse of the happy path: the peer sends Ping first
        // and waits for the caller's Pong. The caller's
        // hole_punch loop must notice incoming Pings and echo
        // them as Pongs, then keep looping until it *also*
        // gets a Pong for its own nonce. The spawn_cone_peer
        // helper above does both — it sends an initial Ping
        // and then answers our Ping — so if the previous test
        // passed, this behaviour is already covered. We add an
        // explicit assertion on the peer-side Pong having
        // actually arrived.
        let (caller_sock, peer_sock) = loopback_pair();
        let caller_addr = caller_sock.local_addr().unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();

        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; PROBE_LEN];
            peer_sock.set_read_timeout(Some(Duration::from_millis(3_000))).unwrap();
            let my_nonce = [0x77u8; 8];
            let ping = encode_probe(ProbeKind::Ping, &my_nonce);
            peer_sock.send_to(&ping, caller_addr).unwrap();

            let mut got_pong = false;
            let mut got_caller_ping = false;
            for _ in 0..8 {
                match peer_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if let Some((kind, nonce)) = decode_probe(&buf[..n]) {
                            if kind == ProbeKind::Ping {
                                got_caller_ping = true;
                                let pong = encode_probe(ProbeKind::Pong, &nonce);
                                peer_sock.send_to(&pong, from).unwrap();
                            } else if kind == ProbeKind::Pong && nonce == my_nonce {
                                got_pong = true;
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            tx.send(got_pong && got_caller_ping).unwrap();
        });

        let cfg = HolePunchConfig::cone(peer_addr, 2_000, 200);
        hole_punch(&caller_sock, &cfg).unwrap();
        handle.join().unwrap();
        // The peer thread reports whether it received BOTH
        // (1) a caller Ping and (2) the caller's Pong for its
        // own nonce.
        assert!(rx.recv().unwrap());
    }

    #[test]
    fn symmetric_nat_fallback_finds_peer_on_alt_port() {
        // Simulate a symmetric NAT by binding the peer on a
        // different port than what STUN claims. The caller's
        // `peer_primary` is a dead port on the same IP, but
        // `peer_alt_ports` includes the real one.
        let caller_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let caller_addr = caller_sock.local_addr().unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_real_port = peer_sock.local_addr().unwrap().port();

        // A fake-STUN port that nothing listens on.
        let fake_stun_port = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
            // Drop s → port is now a black hole.
        };
        let fake_primary = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), fake_stun_port);

        let handle = spawn_cone_peer(peer_sock, caller_addr);

        let cfg = HolePunchConfig {
            peer_primary: fake_primary,
            peer_alt_ports: vec![peer_real_port],
            deadline_ms: 2_000,
            interval_ms: 200,
        };
        let confirmed = hole_punch(&caller_sock, &cfg).unwrap();
        assert_eq!(confirmed.port(), peer_real_port);
        handle.join().unwrap();
    }

    #[test]
    fn timeout_when_peer_is_silent() {
        // Peer sock exists but the thread never listens or
        // replies. The caller's bursts should simply expire.
        let caller_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        drop(peer_sock); // black hole

        let cfg = HolePunchConfig::cone(peer_addr, 600, 150);
        let err = hole_punch(&caller_sock, &cfg).unwrap_err();
        assert_eq!(err, P2pError::Timeout);
    }

    #[test]
    fn stray_pong_with_wrong_nonce_does_not_complete_punch() {
        // Peer sends a Pong with the WRONG nonce, then stays
        // silent. hole_punch must keep trying until timeout.
        let caller_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let caller_addr = caller_sock.local_addr().unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();

        thread::spawn(move || {
            // Send one stray Pong with a bogus nonce, then
            // just drain and drop incoming packets.
            let stray = encode_probe(ProbeKind::Pong, &[0xDEu8; 8]);
            peer_sock.send_to(&stray, caller_addr).unwrap();
            let mut buf = [0u8; PROBE_LEN];
            peer_sock.set_read_timeout(Some(Duration::from_millis(1_000))).unwrap();
            while peer_sock.recv_from(&mut buf).is_ok() {}
        });

        let cfg = HolePunchConfig::cone(peer_addr, 500, 100);
        let err = hole_punch(&caller_sock, &cfg).unwrap_err();
        assert_eq!(err, P2pError::Timeout);
    }

    #[test]
    fn display_covers_every_variant() {
        assert_eq!(P2pError::Timeout.to_string(), "p2p: hole-punch timed out");
        assert_eq!(P2pError::BadConfig("x").to_string(), "p2p: bad config: x");
        assert_eq!(P2pError::Io("boom".into()).to_string(), "p2p: io: boom");
    }
}
