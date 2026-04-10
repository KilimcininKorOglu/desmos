//! Outbound pipeline stage: read one IP packet from the TUN, wrap it in a
//! DWP Data frame, send it to the peer over UDP. Plaintext path only —
//! crypto lands in Phase 2 (Tasks 15+).

use std::io;
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
