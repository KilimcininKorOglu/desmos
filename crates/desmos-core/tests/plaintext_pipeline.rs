//! End-to-end pipeline test using a pair of loopback UDP sockets and
//! in-memory mock TUN devices. Verifies that a byte blob placed on
//! `tun_a`'s inbox is wrapped in a DWP Data frame, punted through
//! `udp_a → udp_b`, unwrapped by the inbound stage, and delivered to
//! `tun_b`'s outbox — exactly the round trip Task 14's acceptance
//! criterion calls for.
//!
//! The real `desmos up --mode plaintext` command wires the same stages
//! against a `LinuxTun` and an `EpollReactor`; this test exercises the
//! pipeline logic without requiring CAP_NET_ADMIN.

#![cfg(unix)]

use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::time::Duration;
use std::time::Instant;

use desmos_core::pipeline::forward_tun_to_udp;
use desmos_core::pipeline::forward_udp_to_tun;
use desmos_proto::Seq;
use desmos_proto::SessionId;
use desmos_rt::Tun;
use desmos_rt::UdpSocket;

/// In-memory Tun fake. Packets placed on `inbox` are delivered to
/// `recv`; packets sent via `send` land on `outbox`. `as_raw_fd`
/// returns -1 because no real kernel object backs it.
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

fn wait_readable(sock: &UdpSocket, timeout_ms: u64) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut probe = [0u8; 1];
    loop {
        match sock.as_std().peek(&mut probe) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(ErrorKind::TimedOut, "udp not readable in time"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
}

#[test]
fn plaintext_loopback_round_trip() {
    let udp_a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    let mut tun_a = MockTun::new("mock_a");
    let mut tun_b = MockTun::new("mock_b");

    // A 20-byte "IP packet" stand-in. The forwarder does not care about
    // the IP header format in plaintext mode.
    let payload = b"hello desmos tunnel!".to_vec();
    tun_a.inbox.push_back(payload.clone());

    let mut seq = Seq(0);
    let mut scratch = vec![0u8; 2048];

    let sent =
        forward_tun_to_udp(&mut tun_a, &udp_a, addr_b, SessionId(42), &mut seq, &mut scratch)
            .expect("tun->udp");
    assert_eq!(sent, desmos_proto::HEADER_LEN + payload.len());

    wait_readable(&udp_b, 500).expect("udp_b should become readable");

    let delivered = forward_udp_to_tun(&udp_b, &mut tun_b, &mut scratch).expect("udp->tun");
    assert_eq!(delivered, payload.len());
    assert_eq!(tun_b.outbox.len(), 1);
    assert_eq!(tun_b.outbox[0], payload);
}

#[test]
fn inbound_rejects_short_frame() {
    let udp_a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    // Send only 4 bytes — shorter than the 16-byte DWP header.
    udp_a.send_to(b"oops", addr_b).unwrap();
    wait_readable(&udp_b, 500).unwrap();

    let mut tun_b = MockTun::new("mock_b");
    let mut scratch = vec![0u8; 2048];
    let err = forward_udp_to_tun(&udp_b, &mut tun_b, &mut scratch).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(tun_b.outbox.is_empty());
}

#[test]
fn outbound_preserves_sequence_on_back_to_back_packets() {
    let udp_a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let udp_b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr_b = udp_b.local_addr().unwrap();

    let mut tun_a = MockTun::new("mock_a");
    tun_a.inbox.push_back(b"packet-one".to_vec());
    tun_a.inbox.push_back(b"packet-two".to_vec());

    let mut seq = Seq(0);
    let mut scratch = vec![0u8; 2048];

    for _ in 0..2 {
        forward_tun_to_udp(&mut tun_a, &udp_a, addr_b, SessionId(7), &mut seq, &mut scratch)
            .unwrap();
    }
    assert_eq!(seq, Seq(2));
}
