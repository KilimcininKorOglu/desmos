//! Inbound pipeline stage: receive one UDP datagram, unwrap its DWP
//! header, write the IP payload to the TUN. Plaintext path only.

use std::io;

use desmos_proto::Header;
use desmos_proto::PacketType;
use desmos_proto::HEADER_LEN;
use desmos_rt::Tun;
use desmos_rt::UdpSocket;

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
