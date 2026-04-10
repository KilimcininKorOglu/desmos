//! End-to-end test for the Redundant bonding strategy plus the
//! bonded outbound pipeline stage. Verifies the three Task 26
//! acceptance items:
//!
//! 1. With three healthy links, every packet is transmitted exactly
//!    3× on the wire (once per link).
//! 2. The receiver's anti-replay window dedups the copies — the TUN
//!    outbox only ever holds one copy per logical packet.
//! 3. Throughput is bounded by the set of healthy links (we do not
//!    assert the "slowest link" number because loopback has no
//!    bandwidth cap; the Linux-only veth script in
//!    `scripts/rr_bonding_veth.sh` can be adapted for a real
//!    measurement under Phase 3 benches).

#![cfg(unix)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use desmos_core::bonding::Engine;
use desmos_core::bonding::Link;
use desmos_core::bonding::LinkId;
use desmos_core::bonding::LinkTable;
use desmos_core::bonding::Redundant;
use desmos_core::pipeline::forward_tun_to_udp_bonded;
use desmos_core::pipeline::forward_udp_to_tun_encrypted;
use desmos_core::pipeline::PipelineMetrics;
use desmos_core::session::Established;
use desmos_core::session::HandshakeOutcome;
use desmos_core::session::Handshaking;
use desmos_core::session::Session;
use desmos_proto::crypto::x25519::X25519PrivateKey;
use desmos_proto::SessionId;
use desmos_rt::Tun;
use desmos_rt::UdpSocket;

// ---------------------------------------------------------------------------
// MockTun (duplicated across integration tests so each binary is
// self-contained).
// ---------------------------------------------------------------------------

struct MockTun {
    name: String,
    inbox: VecDeque<Vec<u8>>,
    outbox: Vec<Vec<u8>>,
}

impl MockTun {
    fn new(name: &str) -> Self {
        Self { name: name.to_string(), inbox: VecDeque::new(), outbox: Vec::new() }
    }
}

impl AsRawFd for MockTun {
    fn as_raw_fd(&self) -> RawFd {
        -1
    }
}

impl Tun for MockTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbox.pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(ErrorKind::WouldBlock, "mock tun inbox empty")),
        }
    }

    fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbox.push(buf.to_vec());
        Ok(buf.len())
    }
}

fn handshake_pair(id: SessionId) -> (Session<Established>, Session<Established>) {
    let ini_static = X25519PrivateKey::from_bytes([0x11; 32]);
    let res_static = X25519PrivateKey::from_bytes([0x22; 32]);
    let res_pub = res_static.public_key();

    let ini_sess =
        Session::<Handshaking>::new_initiator(id, ini_static, res_pub, b"redundant-test");
    let res_sess =
        Session::<Handshaking>::new_responder(id, res_static, Vec::new(), b"redundant-test");
    let (msg1, ini_sess) = match ini_sess.advance(None, 0).unwrap() {
        HandshakeOutcome::NeedsMore { outbound, next } => (outbound, next),
        _ => panic!(),
    };
    let (msg2, responder) = match res_sess.advance(Some(&msg1), 0).unwrap() {
        HandshakeOutcome::Established { outbound, session } => (outbound.unwrap(), session),
        _ => panic!(),
    };
    let initiator = match ini_sess.advance(Some(&msg2), 0).unwrap() {
        HandshakeOutcome::Established { session, .. } => session,
        _ => panic!(),
    };
    (initiator, responder)
}

fn drain_all_sockets(
    sockets: &[&UdpSocket],
    res: &Session<Established>,
    tun: &mut MockTun,
    metrics: &PipelineMetrics,
    expected_arrivals: usize,
    deadline: Instant,
) {
    let mut scratch = vec![0u8; 4096];
    let mut turn = 0usize;
    let mut seen = 0usize;
    while seen < expected_arrivals {
        if Instant::now() > deadline {
            panic!(
                "timed out: saw {seen}/{expected_arrivals} arrivals; metrics={:?}",
                metrics.snapshot(),
            );
        }
        let sock = sockets[turn];
        turn = (turn + 1) % sockets.len();
        match forward_udp_to_tun_encrypted(sock, tun, res, &mut scratch, metrics) {
            Ok(_) => {
                let snap = metrics.snapshot();
                if snap.packets_received as usize > seen {
                    seen = snap.packets_received as usize;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_micros(50));
            }
            Err(e) => panic!("recv error: {e}"),
        }
    }
}

#[test]
fn three_link_redundant_fans_out_and_dedups() {
    let id = SessionId(201);
    let (ini, res) = handshake_pair(id);

    // Three "links": three distinct UDP sockets on loopback.
    let sock_a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sock_c = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer_a = sock_a.local_addr().unwrap();
    let peer_b = sock_b.local_addr().unwrap();
    let peer_c = sock_c.local_addr().unwrap();

    // Sender-side sockets (one per link). The bonded stage looks up
    // the socket via the closure.
    let sender_a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sender_b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let sender_c = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    let engine = Engine::new(
        Arc::new(Redundant::new()),
        LinkTable::new(vec![
            Link::new(1, "linkA", peer_a, 10),
            Link::new(2, "linkB", peer_b, 10),
            Link::new(3, "linkC", peer_c, 10),
        ]),
    );

    // Map link ids to sender sockets. The bonded stage calls the
    // closure once per link in the LinkSelection.
    let socket_map: HashMap<LinkId, &UdpSocket> =
        HashMap::from([(1, &sender_a), (2, &sender_b), (3, &sender_c)]);
    let get_sock = |id: LinkId| socket_map.get(&id).copied();

    let mut tun_a = MockTun::new("redundant_a");
    let payload = b"important-realtime-audio-frame".to_vec();
    tun_a.inbox.push_back(payload.clone());

    let mut scratch = vec![0u8; 4096];
    let send_metrics = PipelineMetrics::new();
    let total_sent =
        forward_tun_to_udp_bonded(&mut tun_a, &engine, get_sock, &ini, &mut scratch, &send_metrics)
            .unwrap();

    // 3 links × (16-byte header + payload + 16-byte tag). total_sent
    // should equal `3 * frame_len`.
    let frame_len = 16 + payload.len() + 16;
    assert_eq!(total_sent, 3 * frame_len);
    assert_eq!(send_metrics.snapshot().packets_sent, 3);
    assert_eq!(send_metrics.snapshot().bytes_sent as usize, 3 * frame_len);

    // Receiver side: drain all 3 sockets. The first arrival decrypts
    // cleanly; the second and third are replay-dropped by the
    // anti-replay window inside `decrypt_data`.
    let mut tun_b = MockTun::new("redundant_b");
    let recv_metrics = PipelineMetrics::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    drain_all_sockets(&[&sock_a, &sock_b, &sock_c], &res, &mut tun_b, &recv_metrics, 3, deadline);

    // Exactly one packet made it to the TUN outbox; the other two
    // arrivals turned into replay drops.
    assert_eq!(tun_b.outbox.len(), 1);
    assert_eq!(tun_b.outbox[0], payload);

    let snap = recv_metrics.snapshot();
    assert_eq!(snap.packets_received, 3);
    assert_eq!(snap.replay_drops, 2);
    assert_eq!(snap.decrypt_failures, 0);
    assert_eq!(snap.bad_header, 0);
}

#[test]
fn redundant_with_only_one_healthy_link_still_sends_once() {
    let id = SessionId(202);
    let (ini, res) = handshake_pair(id);

    let sock = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer = sock.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    // Three links but two are marked dead up front.
    let mut links = vec![
        Link::new(1, "dead1", peer, 10),
        Link::new(2, "alive", peer, 10),
        Link::new(3, "dead2", peer, 10),
    ];
    links[0].mark_dead();
    links[2].mark_dead();

    let engine = Engine::new(Arc::new(Redundant::new()), LinkTable::new(links));
    let socket_map: HashMap<LinkId, &UdpSocket> = HashMap::from([(2, &sender)]);
    let get_sock = |id: LinkId| socket_map.get(&id).copied();

    let mut tun_a = MockTun::new("one_alive_a");
    tun_a.inbox.push_back(b"single-copy".to_vec());

    let mut scratch = vec![0u8; 4096];
    let send_metrics = PipelineMetrics::new();
    forward_tun_to_udp_bonded(&mut tun_a, &engine, get_sock, &ini, &mut scratch, &send_metrics)
        .unwrap();

    assert_eq!(send_metrics.snapshot().packets_sent, 1);

    // Receiver gets exactly one copy, no replay.
    let mut tun_b = MockTun::new("one_alive_b");
    let recv_metrics = PipelineMetrics::new();
    drain_all_sockets(
        &[&sock],
        &res,
        &mut tun_b,
        &recv_metrics,
        1,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(tun_b.outbox.len(), 1);
    assert_eq!(recv_metrics.snapshot().replay_drops, 0);
}

#[test]
fn redundant_with_all_links_dead_drops_the_packet() {
    let id = SessionId(203);
    let (ini, _res) = handshake_pair(id);

    let mut links = vec![Link::new(1, "d1", "127.0.0.1:1".parse().unwrap(), 10)];
    links[0].mark_dead();
    let engine = Engine::new(Arc::new(Redundant::new()), LinkTable::new(links));
    let get_sock = |_id: LinkId| -> Option<&UdpSocket> { None };

    let mut tun_a = MockTun::new("all_dead_a");
    tun_a.inbox.push_back(b"doomed".to_vec());

    let mut scratch = vec![0u8; 4096];
    let send_metrics = PipelineMetrics::new();
    let total =
        forward_tun_to_udp_bonded(&mut tun_a, &engine, get_sock, &ini, &mut scratch, &send_metrics)
            .unwrap();
    // No healthy links → LinkSelection::None → nothing sent.
    assert_eq!(total, 0);
    assert_eq!(send_metrics.snapshot().packets_sent, 0);
}
