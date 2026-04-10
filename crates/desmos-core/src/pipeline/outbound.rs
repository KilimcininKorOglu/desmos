//! Outbound pipeline stage: read one IP packet from the TUN, wrap it in a
//! DWP frame, and send it to the peer over UDP.
//!
//! Two variants:
//! - `forward_tun_to_udp` is the original plaintext path kept from
//!   Phase 1 so `desmos up --mode plaintext` still works for debugging.
//! - `forward_tun_to_udp_encrypted` is the Phase 2 path that seals the
//!   payload with a `Session<Established>` from `desmos-core::session`
//!   and stamps the assigned sequence into the DWP header.

use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;

use desmos_proto::Flags;
use desmos_proto::Header;
use desmos_proto::InterfaceId;
use desmos_proto::PacketType;
use desmos_proto::Seq;
use desmos_proto::SessionId;
use desmos_proto::TimestampUs;
use desmos_proto::HEADER_LEN;
use desmos_proto::WIRE_VERSION;
use desmos_rt::Tun;
use desmos_rt::UdpSocket;

use crate::pipeline::PipelineMetrics;
use crate::session::Established;
use crate::session::Session;

/// Read exactly one IP packet from `tun` and send it as a DWP Data frame
/// to `peer` on `udp`. Returns the number of bytes written on the wire
/// (including the 16-byte header). Propagates `WouldBlock` so the caller
/// can drain the reactor until the TUN is empty.
pub fn forward_tun_to_udp<T: Tun>(
    tun: &mut T,
    udp: &UdpSocket,
    peer: SocketAddr,
    session_id: SessionId,
    seq: &mut Seq,
    scratch: &mut [u8],
) -> io::Result<usize> {
    if scratch.len() < HEADER_LEN + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "forward_tun_to_udp: scratch buffer too small",
        ));
    }
    let payload_len = tun.recv(&mut scratch[HEADER_LEN..])?;
    if payload_len == 0 {
        return Ok(0);
    }
    if payload_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forward_tun_to_udp: packet larger than 65535 bytes",
        ));
    }

    let header = Header {
        version: WIRE_VERSION,
        packet_type: PacketType::Data,
        flags: Flags::EMPTY,
        session_id,
        sequence: *seq,
        timestamp_us: TimestampUs(0),
        payload_len: payload_len as u16,
        interface_id: InterfaceId(0),
    };
    header
        .encode(&mut scratch[..HEADER_LEN])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("wire encode: {e}")))?;

    *seq = seq.next();
    let total = HEADER_LEN + payload_len;
    udp.send_to(&scratch[..total], peer)?;
    Ok(total)
}

/// Encrypted outbound stage: read one IP packet from `tun`, seal it
/// with the session's send key, wrap it in a DWP Data frame, and send
/// it to `peer`. The wire layout is `[16-byte DWP header] [ciphertext
/// || 16-byte Poly1305 tag]`. The header's `sequence` field carries
/// the low 32 bits of the counter used to build the AEAD nonce and
/// AAD, so the receiver can reconstruct both.
///
/// `scratch` must be big enough for `HEADER_LEN + plaintext + TAG_LEN`;
/// the plaintext lands in `scratch[HEADER_LEN..]` and is then sealed
/// in place via the session's copy-to-new-Vec path before the final
/// write-back into `scratch`.
pub fn forward_tun_to_udp_encrypted<T: Tun>(
    tun: &mut T,
    udp: &UdpSocket,
    peer: SocketAddr,
    session: &Session<Established>,
    scratch: &mut [u8],
    metrics: &PipelineMetrics,
) -> io::Result<usize> {
    if scratch.len() < HEADER_LEN + 1 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "forward_tun_to_udp_encrypted: scratch buffer too small",
        ));
    }

    let plaintext_len = tun.recv(&mut scratch[HEADER_LEN..])?;
    if plaintext_len == 0 {
        return Ok(0);
    }

    let plaintext = scratch[HEADER_LEN..HEADER_LEN + plaintext_len].to_vec();
    let (seq, ciphertext) = session
        .encrypt_packet(&plaintext)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("session encrypt: {e}")))?;

    let ct_len = ciphertext.len();
    if ct_len > u16::MAX as usize {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "forward_tun_to_udp_encrypted: ciphertext > 65535 bytes",
        ));
    }
    if HEADER_LEN + ct_len > scratch.len() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "forward_tun_to_udp_encrypted: scratch buffer too small for ciphertext",
        ));
    }

    // Wire format uses a 32-bit seq. The AEAD nonce / AAD use the full
    // 64-bit counter; sessions rekey long before this narrowing would
    // ever wrap (2^32 packets is ~48 Tbit at 1500-byte frames).
    if seq > u32::MAX as u64 {
        return Err(io::Error::new(
            ErrorKind::Other,
            "forward_tun_to_udp_encrypted: seq exceeds 32 bits; rekey overdue",
        ));
    }
    let header = Header {
        version: WIRE_VERSION,
        packet_type: PacketType::Data,
        flags: Flags::EMPTY,
        session_id: session.id(),
        sequence: Seq(seq as u32),
        timestamp_us: TimestampUs(0),
        payload_len: ct_len as u16,
        interface_id: InterfaceId(0),
    };
    header
        .encode(&mut scratch[..HEADER_LEN])
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("wire encode: {e}")))?;
    scratch[HEADER_LEN..HEADER_LEN + ct_len].copy_from_slice(&ciphertext);

    let total = HEADER_LEN + ct_len;
    udp.send_to(&scratch[..total], peer)?;
    metrics.record_sent(total);
    Ok(total)
}
