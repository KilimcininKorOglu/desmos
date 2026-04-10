//! Linux-only acceptance tests for the epoll reactor.
//!
//! Gated behind `target_os = "linux"` so the file compiles cleanly on
//! macOS / BSD / Windows and the tests simply do not run there.

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::Duration;

use desmos_rt::EpollReactor;
use desmos_rt::Event;
use desmos_rt::Interest;
use desmos_rt::Reactor;
use desmos_rt::Token;

fn fd_count() -> usize {
    // /proc/self/fd contains one entry per open file descriptor.
    std::fs::read_dir("/proc/self/fd").map(|it| it.count()).unwrap_or(0)
}

#[test]
fn register_udp_socket_gets_read_ready_on_incoming_packet() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();

    let mut reactor = EpollReactor::new().unwrap();
    reactor.register(sock.as_raw_fd(), Token(0xAB), Interest::READABLE).unwrap();

    // Send something to ourselves so the kernel marks the socket readable.
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"hello", addr).unwrap();

    let mut events: Vec<Event> = Vec::new();
    let n = reactor.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
    assert!(n >= 1, "reactor reported no events");
    let ev = events[0];
    assert_eq!(ev.token, Token(0xAB));
    assert!(ev.readiness.is_readable());
}

#[test]
fn thousand_register_deregister_cycles_do_not_leak_fds() {
    let mut reactor = EpollReactor::new().unwrap();
    let baseline = fd_count();
    for i in 0..1000u64 {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        reactor.register(sock.as_raw_fd(), Token(i), Interest::READABLE).unwrap();
        reactor.deregister(sock.as_raw_fd()).unwrap();
        // Dropping `sock` closes the fd.
    }
    let after = fd_count();
    // Allow a tiny slack for background std bookkeeping.
    assert!(after <= baseline + 2, "fd count grew from {baseline} to {after}",);
}

#[test]
fn deregister_stops_delivering_events() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();

    let mut reactor = EpollReactor::new().unwrap();
    reactor.register(sock.as_raw_fd(), Token(1), Interest::READABLE).unwrap();
    reactor.deregister(sock.as_raw_fd()).unwrap();

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"ignored", addr).unwrap();

    let mut events: Vec<Event> = Vec::new();
    let n = reactor.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
    assert_eq!(n, 0, "deregistered fd still fired events");
}
