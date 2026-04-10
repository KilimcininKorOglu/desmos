//! Inbound pipeline stage: receive one UDP datagram, unwrap its DWP
//! header, and deliver the IP payload to the TUN.
//!
//! Two variants:
//! - `forward_udp_to_tun` is the plaintext path from Phase 1.
//! - `forward_udp_to_tun_encrypted` is the Phase 2 path that checks
//!   anti-replay, decrypts the AEAD payload via the matching
//!   `Session<Established>`, and bumps the right counter on any drop.

use std::io;
use std::io::ErrorKind;

use desmos_proto::Header;
use desmos_proto::PacketType;
use desmos_proto::HEADER_LEN;
use desmos_rt::Tun;
use desmos_rt::UdpSocket;

use crate::pipeline::PipelineMetrics;
use crate::session::Established;
use crate::session::Session;
use crate::session::SessionError;

/// Read one DWP datagram from `udp` and deliver the payload to `tun`.
/// Returns `Ok(0)` for control or keepalive frames that carry no IP
/// payload. Propagates `WouldBlock` so the caller can drain the reactor.
pub fn forward_udp_to_tun<T: Tun>(
    udp: &UdpSocket,
    tun: &mut T,
    scratch: &mut [u8],
) -> io::Result<usize> {
    if scratch.len() < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "forward_udp_to_tun: scratch buffer too small",
        ));
    }
    let (n, _from) = udp.recv_from(scratch)?;
    if n < HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forward_udp_to_tun: datagram shorter than DWP header",
        ));
    }

    let header = Header::decode(&scratch[..HEADER_LEN])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("wire decode: {e}")))?;
    if !matches!(header.packet_type, PacketType::Data) {
        return Ok(0);
    }
    let declared = header.payload_len as usize;
    let available = n - HEADER_LEN;
    if declared > available {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "forward_udp_to_tun: payload truncated: declared {declared}, available {available}"
            ),
        ));
    }

    tun.send(&scratch[HEADER_LEN..HEADER_LEN + declared])?;
    Ok(declared)
}

/// Encrypted inbound stage: read one DWP datagram from `udp`, run the
/// sequence through the session's anti-replay window, decrypt the
/// payload via the session's recv key, and deliver the plaintext to
/// `tun`. Drops are silent on the wire but each one increments a
/// specific counter in `metrics`:
///
/// - `bad_header`       on malformed DWP headers or truncated payloads.
/// - `replay_drops`     on duplicates / out-of-window sequences.
/// - `decrypt_failures` on tag mismatch, wrong session id, or tampered ciphertext.
///
/// Returns `Ok(0)` for non-Data frames (keepalive / control) and
/// `Ok(delivered)` for Data frames where `delivered` is the plaintext
/// length written to the TUN.
pub fn forward_udp_to_tun_encrypted<T: Tun>(
    udp: &UdpSocket,
    tun: &mut T,
    session: &Session<Established>,
    scratch: &mut [u8],
    metrics: &PipelineMetrics,
) -> io::Result<usize> {
    if scratch.len() < HEADER_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "forward_udp_to_tun_encrypted: scratch buffer too small",
        ));
    }
    let (n, _from) = udp.recv_from(scratch)?;
    metrics.record_received(n);

    if n < HEADER_LEN {
        metrics.record_bad_header();
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "forward_udp_to_tun_encrypted: datagram shorter than DWP header",
        ));
    }

    let header = match Header::decode(&scratch[..HEADER_LEN]) {
        Ok(h) => h,
        Err(e) => {
            metrics.record_bad_header();
            return Err(io::Error::new(ErrorKind::InvalidData, format!("wire decode: {e}")));
        }
    };
    if !matches!(header.packet_type, PacketType::Data) {
        return Ok(0);
    }
    let declared = header.payload_len as usize;
    let available = n - HEADER_LEN;
    if declared > available {
        metrics.record_bad_header();
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("payload truncated: declared {declared}, available {available}"),
        ));
    }
    // The sender narrowed a u64 counter to u32 when writing the header;
    // widen back. Sessions rekey long before the upper half is relevant.
    let seq = header.sequence.0 as u64;

    let ciphertext_range = HEADER_LEN..HEADER_LEN + declared;
    let plaintext = match session.decrypt_data(seq, &mut scratch[ciphertext_range]) {
        Ok(pt) => pt,
        Err(SessionError::Replay(_)) => {
            metrics.record_replay_drop();
            return Ok(0);
        }
        Err(SessionError::Crypto(_)) => {
            metrics.record_decrypt_failure();
            return Ok(0);
        }
        Err(e) => {
            return Err(io::Error::new(ErrorKind::Other, format!("session decrypt: {e}")));
        }
    };

    tun.send(&plaintext)?;
    Ok(plaintext.len())
}
