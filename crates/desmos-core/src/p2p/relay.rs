//! Relay fallback for P2P tunnels.
//!
//! When UDP hole punching ([`super::holepunch`]) fails to establish a
//! direct path, both peers can fall back to routing their traffic
//! through a Desmos server acting as a relay. The config key
//! `[p2p].relay_servers` lists one or more candidate relay addresses
//! (typically public Desmos servers the operator runs).
//!
//! # Wire format
//!
//! Relay packets are thin wrappers around opaque payloads. 20 bytes
//! of framing + variable payload:
//!
//! ```text
//! +--------------------+----------+----------+--------+---------+
//! | 12-byte magic      | 1B  cmd  | 1B rsvd  | 2B len | payload |
//! +--------------------+----------+----------+--------+---------+
//! ```
//!
//! Magic tag is `DESMOS-RELAY` (12 bytes). Commands:
//!
//! | Cmd | Name       | Direction     | Payload                     |
//! |-----|------------|---------------|-----------------------------|
//! | 0   | Register   | peer → relay  | 32-byte peer public key     |
//! | 1   | Registered | relay → peer  | empty                       |
//! | 2   | Data       | bidirectional | opaque DWP bytes            |
//! | 3   | Peer­Joined | relay → peer  | empty (other peer arrived)  |
//! | 4   | Error      | relay → peer  | UTF-8 reason (≤ 200 bytes)  |
//!
//! The relay matches two peers that Register with the same key into
//! a pair and forwards Data frames between them transparently. The
//! relay never inspects the DWP payload — it is end-to-end encrypted.
//!
//! # Flow
//!
//! 1. Peer A sends `Register(pub_key)` to the relay.
//! 2. Relay replies `Registered` once the slot is allocated.
//! 3. When peer B registers with the same `pub_key`, the relay
//!    sends `PeerJoined` to both sides.
//! 4. Both peers now exchange `Data` frames. The relay copies each
//!    frame to the other peer in the pair.
//!
//! # Usage
//!
//! The top-level entry point is [`try_direct_then_relay`], which
//! runs hole punching first and falls back to relay within the
//! caller's deadline. Lower-level callers can use [`relay_connect`]
//! directly.

use core::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::holepunch::{self, HolePunchConfig, P2pError};

// ---- Wire constants --------------------------------------------------------

/// Magic tag for all relay-framed packets.
const RELAY_MAGIC: &[u8; 12] = b"DESMOS-RELAY";

/// Fixed header: 12-byte magic + 1 cmd + 1 reserved + 2 length.
const RELAY_HEADER_LEN: usize = 16;

/// Maximum payload a relay frame may carry (64 KiB minus header).
const MAX_RELAY_PAYLOAD: usize = 65519;

/// Maximum UDP receive buffer. Generous enough for any DWP frame.
const RECV_BUF_LEN: usize = 65535;

// ---- Command codes ---------------------------------------------------------

/// Relay command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCmd {
    /// Peer → relay: register into a pairing slot.
    Register = 0,
    /// Relay → peer: registration acknowledged.
    Registered = 1,
    /// Bidirectional opaque data forwarding.
    Data = 2,
    /// Relay → peer: the other peer joined the pair.
    PeerJoined = 3,
    /// Relay → peer: error message (UTF-8 body).
    Error = 4,
}

impl RelayCmd {
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Register),
            1 => Some(Self::Registered),
            2 => Some(Self::Data),
            3 => Some(Self::PeerJoined),
            4 => Some(Self::Error),
            _ => None,
        }
    }
}

// ---- Errors ----------------------------------------------------------------

/// Errors the relay path can surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Hole-punch phase failed (timeout or config).
    HolePunch(P2pError),
    /// None of the configured relay servers responded within
    /// the deadline.
    NoRelay,
    /// The relay server sent an explicit error message.
    RelayRejected(String),
    /// Received a relay frame with an unknown or unexpected
    /// command.
    BadFrame(&'static str),
    /// `[p2p].relay_servers` is empty — cannot fall back.
    NoRelayServers,
    /// I/O error on the UDP socket.
    Io(String),
    /// The relay session deadline expired while waiting for
    /// PeerJoined or data.
    Timeout,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HolePunch(e) => write!(f, "relay: hole-punch failed: {e}"),
            Self::NoRelay => f.write_str("relay: no relay server reachable"),
            Self::RelayRejected(r) => write!(f, "relay: server rejected: {r}"),
            Self::BadFrame(r) => write!(f, "relay: bad frame: {r}"),
            Self::NoRelayServers => f.write_str("relay: no relay servers configured"),
            Self::Io(e) => write!(f, "relay: io: {e}"),
            Self::Timeout => f.write_str("relay: timed out"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<P2pError> for RelayError {
    fn from(e: P2pError) -> Self {
        Self::HolePunch(e)
    }
}

// ---- Frame codec -----------------------------------------------------------

/// Encode a relay frame into a caller-supplied buffer. Returns the
/// number of bytes written, or `None` if the buffer is too small
/// or the payload exceeds [`MAX_RELAY_PAYLOAD`].
pub fn encode_relay_frame(buf: &mut [u8], cmd: RelayCmd, payload: &[u8]) -> Option<usize> {
    let total = RELAY_HEADER_LEN + payload.len();
    if payload.len() > MAX_RELAY_PAYLOAD || buf.len() < total {
        return None;
    }
    buf[..12].copy_from_slice(RELAY_MAGIC);
    buf[12] = cmd as u8;
    buf[13] = 0; // reserved
    let len_be = (payload.len() as u16).to_be_bytes();
    buf[14] = len_be[0];
    buf[15] = len_be[1];
    if !payload.is_empty() {
        buf[RELAY_HEADER_LEN..total].copy_from_slice(payload);
    }
    Some(total)
}

/// Decoded relay frame: command + payload slice.
#[derive(Debug)]
pub struct RelayFrame<'a> {
    pub cmd: RelayCmd,
    pub payload: &'a [u8],
}

/// Decode a relay frame from the given byte slice. Returns `None`
/// if the magic does not match, the buffer is too short, or the
/// declared payload length exceeds the buffer.
pub fn decode_relay_frame(bytes: &[u8]) -> Option<RelayFrame<'_>> {
    if bytes.len() < RELAY_HEADER_LEN {
        return None;
    }
    if &bytes[..12] != RELAY_MAGIC {
        return None;
    }
    let cmd = RelayCmd::from_byte(bytes[12])?;
    let payload_len = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
    let total = RELAY_HEADER_LEN + payload_len;
    if bytes.len() < total {
        return None;
    }
    Some(RelayFrame { cmd, payload: &bytes[RELAY_HEADER_LEN..total] })
}

// ---- Relay session ---------------------------------------------------------

/// An established relay session. Both peers hold one of these after
/// successfully registering with a relay server and receiving
/// `PeerJoined`.
#[derive(Debug)]
pub struct RelaySession {
    /// The relay server's address.
    pub relay_addr: SocketAddr,
    /// Re-usable send buffer (avoids per-send allocation).
    send_buf: Vec<u8>,
}

impl RelaySession {
    /// Wrap an already-connected relay endpoint.
    pub fn new(relay_addr: SocketAddr) -> Self {
        Self { relay_addr, send_buf: vec![0u8; RECV_BUF_LEN] }
    }

    /// Send an opaque payload (typically a DWP packet) to the
    /// peer via the relay.
    pub fn send(&mut self, socket: &UdpSocket, payload: &[u8]) -> Result<(), RelayError> {
        let n = encode_relay_frame(&mut self.send_buf, RelayCmd::Data, payload)
            .ok_or(RelayError::BadFrame("payload too large for relay frame"))?;
        socket
            .send_to(&self.send_buf[..n], self.relay_addr)
            .map_err(|e| RelayError::Io(e.to_string()))?;
        Ok(())
    }

    /// Receive the next data payload from the relay. Blocks up to
    /// the socket's current read timeout. Returns the payload
    /// bytes and the source address (which should always be the
    /// relay).
    ///
    /// Non-Data frames (Keepalive, Error, etc.) are handled
    /// inline: errors are surfaced, other control frames are
    /// silently consumed.
    pub fn recv<'a>(&self, socket: &UdpSocket, buf: &'a mut [u8]) -> Result<&'a [u8], RelayError> {
        loop {
            let (n, _from) = socket.recv_from(buf).map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    RelayError::Timeout
                } else {
                    RelayError::Io(e.to_string())
                }
            })?;
            let Some(frame) = decode_relay_frame(&buf[..n]) else {
                // Not a relay frame — probably a stray probe or
                // unrelated packet. Ignore.
                continue;
            };
            match frame.cmd {
                RelayCmd::Data => {
                    let plen = frame.payload.len();
                    // Move payload to the front of buf so the
                    // caller gets a contiguous slice starting at
                    // index 0.
                    buf.copy_within(RELAY_HEADER_LEN..RELAY_HEADER_LEN + plen, 0);
                    return Ok(&buf[..plen]);
                }
                RelayCmd::Error => {
                    let msg = std::str::from_utf8(frame.payload).unwrap_or("(invalid utf-8)");
                    return Err(RelayError::RelayRejected(msg.to_string()));
                }
                // PeerJoined, Registered, Register — control
                // frames that shouldn't appear mid-session. Skip.
                _ => continue,
            }
        }
    }
}

// ---- Connection helpers ----------------------------------------------------

/// Try to register with a single relay server. Sends a `Register`
/// frame with the peer public key, waits for `Registered`, then
/// waits for `PeerJoined`. Returns the `RelaySession` on success.
///
/// `deadline` is an absolute `Instant` by which the entire
/// registration + pairing must complete.
pub fn relay_connect(
    socket: &UdpSocket,
    relay_addr: SocketAddr,
    peer_public_key: &[u8; 32],
    deadline: Instant,
) -> Result<RelaySession, RelayError> {
    // On Windows, a UDP send_to to a port with no listener can cause
    // the next recv_from to return WSAECONNRESET instead of the
    // expected timeout. Neutralize this once up front; no-op on Unix.
    desmos_rt::socket::disable_udp_connreset(socket).map_err(|e| RelayError::Io(e.to_string()))?;

    let mut send_buf = [0u8; RELAY_HEADER_LEN + 32];
    let n = encode_relay_frame(&mut send_buf, RelayCmd::Register, peer_public_key)
        .ok_or(RelayError::BadFrame("register encode failed"))?;

    // Send register and wait for Registered + PeerJoined.
    socket.send_to(&send_buf[..n], relay_addr).map_err(|e| RelayError::Io(e.to_string()))?;

    let mut recv_buf = [0u8; RECV_BUF_LEN];
    let mut got_registered = false;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RelayError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        socket.set_read_timeout(Some(remaining)).map_err(|e| RelayError::Io(e.to_string()))?;

        match socket.recv_from(&mut recv_buf) {
            Ok((sz, _from)) => {
                let Some(frame) = decode_relay_frame(&recv_buf[..sz]) else {
                    continue;
                };
                match frame.cmd {
                    RelayCmd::Registered => {
                        got_registered = true;
                    }
                    RelayCmd::PeerJoined => {
                        if !got_registered {
                            // Protocol violation — PeerJoined
                            // before Registered. Accept it
                            // anyway; the relay knows best.
                        }
                        return Ok(RelaySession::new(relay_addr));
                    }
                    RelayCmd::Error => {
                        let msg = std::str::from_utf8(frame.payload).unwrap_or("(invalid utf-8)");
                        return Err(RelayError::RelayRejected(msg.to_string()));
                    }
                    _ => continue,
                }
            }
            Err(e) => {
                let kind = e.kind();
                if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                    return Err(RelayError::Timeout);
                }
                return Err(RelayError::Io(e.to_string()));
            }
        }
    }
}

/// Try each address in `relay_servers` sequentially until one
/// accepts the registration and pairs us with the remote peer.
/// Returns the first successful `RelaySession`.
pub fn relay_connect_any(
    socket: &UdpSocket,
    relay_servers: &[SocketAddr],
    peer_public_key: &[u8; 32],
    deadline: Instant,
) -> Result<RelaySession, RelayError> {
    if relay_servers.is_empty() {
        return Err(RelayError::NoRelayServers);
    }

    let count = relay_servers.len();
    let total_budget = deadline.saturating_duration_since(Instant::now());
    // Split the budget evenly across candidates, with a 500ms
    // minimum per attempt.
    let per_server = total_budget
        .checked_div(count as u32)
        .unwrap_or(Duration::from_millis(500))
        .max(Duration::from_millis(500));

    for &addr in relay_servers {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let attempt_deadline = (now + per_server).min(deadline);
        match relay_connect(socket, addr, peer_public_key, attempt_deadline) {
            Ok(session) => return Ok(session),
            Err(_) => continue,
        }
    }
    Err(RelayError::NoRelay)
}

// ---- Top-level orchestrator ------------------------------------------------

/// The outcome of [`try_direct_then_relay`].
#[derive(Debug)]
pub enum P2pOutcome {
    /// Hole punch succeeded — `addr` is the confirmed peer.
    Direct(SocketAddr),
    /// Hole punch failed; a relay session was established.
    Relayed(RelaySession),
}

/// Configuration for the combined direct + relay attempt.
#[derive(Debug, Clone)]
pub struct P2pConnectConfig {
    /// Hole-punching parameters.
    pub punch: HolePunchConfig,
    /// Parsed `SocketAddr` values from `[p2p].relay_servers`.
    pub relay_servers: Vec<SocketAddr>,
    /// 32-byte public key shared between the two peers. Used
    /// by the relay server to pair registrations.
    pub peer_public_key: [u8; 32],
    /// Total deadline (ms) for the entire direct + relay
    /// attempt. Hole punching uses `punch.deadline_ms`; the
    /// relay phase gets whatever time remains.
    pub total_deadline_ms: u64,
}

/// Try hole punching first. If it fails (timeout or bad config),
/// fall back to relay through the configured servers.
///
/// Returns [`P2pOutcome::Direct`] on a successful punch,
/// [`P2pOutcome::Relayed`] if the relay fallback succeeded, or
/// an error if both paths failed.
pub fn try_direct_then_relay(
    socket: &UdpSocket,
    config: &P2pConnectConfig,
) -> Result<P2pOutcome, RelayError> {
    let start = Instant::now();
    let total_deadline = start + Duration::from_millis(config.total_deadline_ms);

    // Phase 1: hole punch.
    match holepunch::hole_punch(socket, &config.punch) {
        Ok(addr) => return Ok(P2pOutcome::Direct(addr)),
        Err(P2pError::BadConfig(r)) => {
            return Err(RelayError::HolePunch(P2pError::BadConfig(r)));
        }
        Err(_) => {
            // Timeout or IO — fall through to relay.
        }
    }

    // Phase 2: relay fallback. Whatever time remains goes to
    // the relay negotiation.
    let now = Instant::now();
    if now >= total_deadline {
        return Err(RelayError::Timeout);
    }

    relay_connect_any(socket, &config.relay_servers, &config.peer_public_key, total_deadline)
        .map(P2pOutcome::Relayed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::thread;

    // ---- Frame codec -------------------------------------------------------

    #[test]
    fn encode_decode_register_round_trip() {
        let key = [0xAB_u8; 32];
        let mut buf = [0u8; 256];
        let n = encode_relay_frame(&mut buf, RelayCmd::Register, &key).unwrap();
        assert_eq!(n, RELAY_HEADER_LEN + 32);

        let frame = decode_relay_frame(&buf[..n]).unwrap();
        assert_eq!(frame.cmd, RelayCmd::Register);
        assert_eq!(frame.payload, &key);
    }

    #[test]
    fn encode_decode_data_round_trip() {
        let payload = b"hello encrypted DWP bytes";
        let mut buf = [0u8; 256];
        let n = encode_relay_frame(&mut buf, RelayCmd::Data, payload).unwrap();
        let frame = decode_relay_frame(&buf[..n]).unwrap();
        assert_eq!(frame.cmd, RelayCmd::Data);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn encode_decode_empty_payload() {
        let mut buf = [0u8; 256];
        let n = encode_relay_frame(&mut buf, RelayCmd::Registered, &[]).unwrap();
        assert_eq!(n, RELAY_HEADER_LEN);
        let frame = decode_relay_frame(&buf[..n]).unwrap();
        assert_eq!(frame.cmd, RelayCmd::Registered);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let big = vec![0u8; MAX_RELAY_PAYLOAD + 1];
        let mut buf = vec![0u8; RECV_BUF_LEN];
        assert!(encode_relay_frame(&mut buf, RelayCmd::Data, &big).is_none());
    }

    #[test]
    fn encode_rejects_undersized_buffer() {
        let payload = [0u8; 100];
        let mut buf = [0u8; 10]; // way too small
        assert!(encode_relay_frame(&mut buf, RelayCmd::Data, &payload).is_none());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(decode_relay_frame(&[]).is_none());
        assert!(decode_relay_frame(&[0u8; RELAY_HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut buf = [0u8; RELAY_HEADER_LEN];
        buf[..12].copy_from_slice(b"BADMAGICBADM");
        buf[12] = RelayCmd::Registered as u8;
        assert!(decode_relay_frame(&buf).is_none());
    }

    #[test]
    fn decode_rejects_unknown_command() {
        let mut buf = [0u8; RELAY_HEADER_LEN];
        buf[..12].copy_from_slice(RELAY_MAGIC);
        buf[12] = 0xFF;
        assert!(decode_relay_frame(&buf).is_none());
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut buf = [0u8; RELAY_HEADER_LEN + 2];
        buf[..12].copy_from_slice(RELAY_MAGIC);
        buf[12] = RelayCmd::Data as u8;
        // Claim 10 bytes of payload but only 2 are present.
        buf[14..16].copy_from_slice(&10_u16.to_be_bytes());
        assert!(decode_relay_frame(&buf).is_none());
    }

    #[test]
    fn relay_cmd_from_byte_exhaustive() {
        assert_eq!(RelayCmd::from_byte(0), Some(RelayCmd::Register));
        assert_eq!(RelayCmd::from_byte(1), Some(RelayCmd::Registered));
        assert_eq!(RelayCmd::from_byte(2), Some(RelayCmd::Data));
        assert_eq!(RelayCmd::from_byte(3), Some(RelayCmd::PeerJoined));
        assert_eq!(RelayCmd::from_byte(4), Some(RelayCmd::Error));
        assert_eq!(RelayCmd::from_byte(5), None);
        assert_eq!(RelayCmd::from_byte(255), None);
    }

    // ---- Relay connect (loopback mock relay) --------------------------------

    /// A minimal mock relay: listens on a UDP socket, replies with
    /// Registered + PeerJoined to any Register, then echoes Data
    /// frames back to the sender.
    fn spawn_mock_relay(sock: UdpSocket) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buf = [0u8; RECV_BUF_LEN];
            sock.set_read_timeout(Some(Duration::from_millis(3_000))).unwrap();
            loop {
                let (n, from) = match sock.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let Some(frame) = decode_relay_frame(&buf[..n]) else {
                    continue;
                };
                match frame.cmd {
                    RelayCmd::Register => {
                        // Reply Registered.
                        let mut out = [0u8; RELAY_HEADER_LEN];
                        let sz = encode_relay_frame(&mut out, RelayCmd::Registered, &[]).unwrap();
                        sock.send_to(&out[..sz], from).unwrap();
                        // Reply PeerJoined.
                        let sz = encode_relay_frame(&mut out, RelayCmd::PeerJoined, &[]).unwrap();
                        sock.send_to(&out[..sz], from).unwrap();
                    }
                    RelayCmd::Data => {
                        // Echo back.
                        sock.send_to(&buf[..n], from).unwrap();
                    }
                    _ => {}
                }
            }
        })
    }

    #[test]
    fn relay_connect_completes_with_mock_relay() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let handle = spawn_mock_relay(relay_sock);

        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = [0x42_u8; 32];
        let deadline = Instant::now() + Duration::from_millis(2_000);
        let session = relay_connect(&peer_sock, relay_addr, &key, deadline).unwrap();
        assert_eq!(session.relay_addr, relay_addr);

        handle.join().unwrap();
    }

    #[test]
    fn relay_connect_any_picks_first_reachable() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let handle = spawn_mock_relay(relay_sock);

        // First address is a dead port.
        let dead_port = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };
        let dead_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port);

        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = [0x42_u8; 32];
        let deadline = Instant::now() + Duration::from_millis(4_000);
        let session =
            relay_connect_any(&peer_sock, &[dead_addr, relay_addr], &key, deadline).unwrap();
        assert_eq!(session.relay_addr, relay_addr);

        handle.join().unwrap();
    }

    #[test]
    fn relay_connect_any_returns_no_relay_servers_when_empty() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = [0u8; 32];
        let deadline = Instant::now() + Duration::from_millis(500);
        let err = relay_connect_any(&sock, &[], &key, deadline).unwrap_err();
        assert_eq!(err, RelayError::NoRelayServers);
    }

    #[test]
    fn relay_connect_timeout_when_no_reply() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Dead address.
        let dead = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let key = [0u8; 32];
        let deadline = Instant::now() + Duration::from_millis(300);
        let err = relay_connect(&sock, dead, &key, deadline).unwrap_err();
        assert_eq!(err, RelayError::Timeout);
    }

    #[test]
    fn relay_session_send_recv_data_with_mock() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let handle = spawn_mock_relay(relay_sock);

        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = [0x42_u8; 32];
        let deadline = Instant::now() + Duration::from_millis(2_000);
        let mut session = relay_connect(&peer_sock, relay_addr, &key, deadline).unwrap();

        // Send data, mock echoes it back.
        let payload = b"encrypted DWP packet data";
        session.send(&peer_sock, payload).unwrap();

        peer_sock.set_read_timeout(Some(Duration::from_millis(1_000))).unwrap();
        let mut recv_buf = [0u8; RECV_BUF_LEN];
        let data = session.recv(&peer_sock, &mut recv_buf).unwrap();
        assert_eq!(data, payload);

        handle.join().unwrap();
    }

    #[test]
    fn relay_session_recv_surfaces_error_frame() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();

        // Custom relay that sends an Error frame.
        let handle = thread::spawn(move || {
            let mut buf = [0u8; RECV_BUF_LEN];
            relay_sock.set_read_timeout(Some(Duration::from_millis(2_000))).unwrap();
            let (_, from) = relay_sock.recv_from(&mut buf).unwrap();
            // Reply with error.
            let msg = b"relay full";
            let mut out = [0u8; 256];
            let sz = encode_relay_frame(&mut out, RelayCmd::Error, msg).unwrap();
            relay_sock.send_to(&out[..sz], from).unwrap();
        });

        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let key = [0u8; 32];
        // Send register.
        let mut send_buf = [0u8; 256];
        let n = encode_relay_frame(&mut send_buf, RelayCmd::Register, &key).unwrap();
        peer_sock.send_to(&send_buf[..n], relay_addr).unwrap();

        peer_sock.set_read_timeout(Some(Duration::from_millis(1_000))).unwrap();
        let session = RelaySession::new(relay_addr);
        let mut recv_buf = [0u8; RECV_BUF_LEN];
        let err = session.recv(&peer_sock, &mut recv_buf).unwrap_err();
        assert_eq!(err, RelayError::RelayRejected("relay full".to_string()));

        handle.join().unwrap();
    }

    // ---- try_direct_then_relay orchestrator --------------------------------

    #[test]
    fn direct_succeeds_skips_relay() {
        let (caller_sock, peer_sock) = {
            let a = UdpSocket::bind("127.0.0.1:0").unwrap();
            let b = UdpSocket::bind("127.0.0.1:0").unwrap();
            (a, b)
        };
        let peer_addr = peer_sock.local_addr().unwrap();

        // Peer side: respond to punches.
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 20];
            peer_sock.set_read_timeout(Some(Duration::from_millis(2_000))).unwrap();
            loop {
                match peer_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if let Some((holepunch::ProbeKind::Ping, nonce)) =
                            holepunch::decode_probe(&buf[..n])
                        {
                            let pong = holepunch::encode_probe(holepunch::ProbeKind::Pong, &nonce);
                            peer_sock.send_to(&pong, from).unwrap();
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let config = P2pConnectConfig {
            punch: HolePunchConfig::cone(peer_addr, 2_000, 200),
            relay_servers: vec![],
            peer_public_key: [0u8; 32],
            total_deadline_ms: 5_000,
        };
        let outcome = try_direct_then_relay(&caller_sock, &config).unwrap();
        assert!(matches!(outcome, P2pOutcome::Direct(a) if a == peer_addr));

        handle.join().unwrap();
    }

    #[test]
    fn falls_back_to_relay_when_punch_times_out() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let handle = spawn_mock_relay(relay_sock);

        let caller_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Dead peer — punch will time out.
        let dead_peer = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

        let config = P2pConnectConfig {
            punch: HolePunchConfig::cone(dead_peer, 300, 100),
            relay_servers: vec![relay_addr],
            peer_public_key: [0x42; 32],
            total_deadline_ms: 5_000,
        };
        let outcome = try_direct_then_relay(&caller_sock, &config).unwrap();
        assert!(matches!(outcome, P2pOutcome::Relayed(s) if s.relay_addr == relay_addr));

        handle.join().unwrap();
    }

    #[test]
    fn fails_when_both_punch_and_relay_fail() {
        let caller_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_peer = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let dead_relay = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 2);

        let config = P2pConnectConfig {
            punch: HolePunchConfig::cone(dead_peer, 200, 100),
            relay_servers: vec![dead_relay],
            peer_public_key: [0u8; 32],
            total_deadline_ms: 1_500,
        };
        let err = try_direct_then_relay(&caller_sock, &config).unwrap_err();
        assert!(matches!(err, RelayError::NoRelay | RelayError::Timeout), "got: {err:?}");
    }

    // ---- Display coverage --------------------------------------------------

    #[test]
    fn display_covers_every_relay_error_variant() {
        let cases: Vec<(RelayError, &str)> = vec![
            (
                RelayError::HolePunch(P2pError::Timeout),
                "relay: hole-punch failed: p2p: hole-punch timed out",
            ),
            (RelayError::NoRelay, "relay: no relay server reachable"),
            (RelayError::RelayRejected("full".into()), "relay: server rejected: full"),
            (RelayError::BadFrame("oops"), "relay: bad frame: oops"),
            (RelayError::NoRelayServers, "relay: no relay servers configured"),
            (RelayError::Io("boom".into()), "relay: io: boom"),
            (RelayError::Timeout, "relay: timed out"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }
}
