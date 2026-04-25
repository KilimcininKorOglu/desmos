//! Client-side Noise IK handshake over a real UDP socket.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use desmos_proto::crypto::x25519::PublicKey;
use desmos_proto::crypto::x25519::X25519PrivateKey;
use desmos_proto::SessionId;

use crate::session::Established;
use crate::session::HandshakeOutcome;
use crate::session::Handshaking;
use crate::session::Session;

use desmos_rt::UdpSocket;

const DEFAULT_TIMEOUT_MS: u64 = 5000;

pub fn client_handshake(
    sock: &UdpSocket,
    server: SocketAddr,
    private_key: X25519PrivateKey,
    server_pub: PublicKey,
    session_id: SessionId,
    prologue: &[u8],
    timeout: Option<Duration>,
) -> io::Result<Session<Established>> {
    let timeout = timeout.unwrap_or(Duration::from_millis(DEFAULT_TIMEOUT_MS));
    let deadline = Instant::now() + timeout;

    let ini = Session::<Handshaking>::new_initiator(session_id, private_key, server_pub, prologue);

    let (msg1, ini) = match ini
        .advance(None, now_ms())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("handshake msg1: {e}")))?
    {
        HandshakeOutcome::NeedsMore { outbound, next } => (outbound, next),
        HandshakeOutcome::Established { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected Established after first advance",
            ));
        }
    };

    sock.send_to(&msg1, server)?;

    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"));
        }

        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from != server {
                    continue;
                }
                let msg2 = &buf[..n];
                let session = ini.advance(Some(msg2), now_ms()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("handshake msg2: {e}"))
                })?;
                match session {
                    HandshakeOutcome::Established { session, .. } => return Ok(session),
                    HandshakeOutcome::NeedsMore { .. } => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "unexpected NeedsMore after msg2",
                        ));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn load_private_key(path: &str) -> io::Result<X25519PrivateKey> {
    let data = std::fs::read(path)?;
    let bytes = if data.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        arr
    } else {
        let hex_str = String::from_utf8(data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key file is not UTF-8"))?;
        let hex_str = hex_str.trim();
        if hex_str.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected 64 hex chars or 32 raw bytes, got {} chars", hex_str.len()),
            ));
        }
        decode_hex_32(hex_str)?
    };
    Ok(X25519PrivateKey::from_bytes(bytes))
}

pub fn parse_public_key_hex(hex_str: &str) -> io::Result<PublicKey> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 64 hex chars for public key, got {}", hex_str.len()),
        ));
    }
    let bytes = decode_hex_32(hex_str)?;
    Ok(PublicKey(bytes))
}

fn decode_hex_32(hex: &str) -> io::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "odd hex length"));
        }
        out[i] = hex_byte(chunk[0])? << 4 | hex_byte(chunk[1])?;
    }
    Ok(out)
}

fn hex_byte(c: u8) -> io::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex char")),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_key_parse_round_trip() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_public_key_hex(hex).unwrap();
        assert_eq!(key.0[0], 0x01);
        assert_eq!(key.0[15], 0xef);
        assert_eq!(key.0[31], 0xef);
    }

    #[test]
    fn hex_key_wrong_length_errors() {
        assert!(parse_public_key_hex("0123").is_err());
    }

    #[test]
    fn hex_key_invalid_char_errors() {
        let hex = "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(parse_public_key_hex(hex).is_err());
    }

    #[test]
    fn loopback_handshake() {
        let ini_key = X25519PrivateKey::from_bytes([0x11; 32]);
        let res_key = X25519PrivateKey::from_bytes([0x22; 32]);
        let res_pub = res_key.public_key();
        let prologue = b"test-loopback";

        let client_sock = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_sock = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match server_sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let msg1 = &buf[..n];
                        let res = Session::<Handshaking>::new_responder(
                            SessionId(1),
                            res_key.clone(),
                            Vec::new(),
                            prologue,
                        );
                        let outcome = res.advance(Some(msg1), now_ms()).unwrap();
                        match outcome {
                            HandshakeOutcome::Established { outbound: Some(msg2), .. } => {
                                server_sock.send_to(&msg2, from).unwrap();
                                return;
                            }
                            _ => panic!("responder should be established"),
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() > deadline {
                            panic!("server timed out");
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("server recv error: {e}"),
                }
            }
        });

        let session = client_handshake(
            &client_sock,
            server_addr,
            ini_key,
            res_pub,
            SessionId(1),
            prologue,
            Some(Duration::from_secs(5)),
        )
        .unwrap();

        let (_, ct) = session.encrypt_packet(b"hello from client").unwrap();
        assert!(!ct.is_empty());

        handle.join().unwrap();
    }
}
