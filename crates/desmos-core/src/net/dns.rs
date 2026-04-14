//! Minimal UDP DNS resolver for leak-protected queries.
//!
//! Builds a standard DNS A-record query packet and parses the response.
//! Only supports A (IPv4) record lookups — sufficient for the tunnel's
//! DNS leak protection feature.
//!
//! Wire format follows RFC 1035 §4.

use std::fmt;

/// DNS query/response error.
#[derive(Debug)]
pub enum DnsError {
    /// Name too long (> 253 characters).
    NameTooLong,
    /// Individual label too long (> 63 characters).
    LabelTooLong,
    /// Response packet too short to parse.
    TruncatedResponse,
    /// Response ID does not match query ID.
    IdMismatch,
    /// Server returned a non-zero RCODE.
    ServerError(u8),
    /// No answer records found.
    NoAnswer,
    /// I/O error.
    Io(std::io::Error),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTooLong => write!(f, "domain name exceeds 253 characters"),
            Self::LabelTooLong => write!(f, "domain label exceeds 63 characters"),
            Self::TruncatedResponse => write!(f, "DNS response too short"),
            Self::IdMismatch => write!(f, "DNS response ID mismatch"),
            Self::ServerError(code) => write!(f, "DNS server error (RCODE={code})"),
            Self::NoAnswer => write!(f, "no answer records in DNS response"),
            Self::Io(e) => write!(f, "DNS I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// DNS record type: A (IPv4 address).
pub const TYPE_A: u16 = 1;

/// DNS class: IN (Internet).
pub const CLASS_IN: u16 = 1;

/// Header length in bytes.
const HEADER_LEN: usize = 12;

/// Maximum DNS UDP packet size.
pub const MAX_DNS_PACKET: usize = 512;

/// Build a DNS A-record query packet for the given domain name.
///
/// Returns the raw packet bytes and the transaction ID used.
pub fn build_query(name: &str, tx_id: u16) -> Result<Vec<u8>, DnsError> {
    if name.len() > 253 {
        return Err(DnsError::NameTooLong);
    }

    let mut buf = Vec::with_capacity(64);

    // Header: ID, flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // QR=0, OPCODE=0, RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question section: encode domain name as labels.
    for label in name.split('.') {
        let len = label.len();
        if len > 63 {
            return Err(DnsError::LabelTooLong);
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // Root label terminator.

    // QTYPE=A, QCLASS=IN.
    buf.extend_from_slice(&TYPE_A.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());

    Ok(buf)
}

/// A parsed DNS A-record answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Transaction ID.
    pub tx_id: u16,
    /// Resolved IPv4 addresses.
    pub addresses: Vec<[u8; 4]>,
    /// TTL of the first answer (seconds).
    pub ttl: u32,
}

/// Parse a DNS response packet and extract A-record answers.
pub fn parse_response(packet: &[u8], expected_id: u16) -> Result<DnsAnswer, DnsError> {
    if packet.len() < HEADER_LEN {
        return Err(DnsError::TruncatedResponse);
    }

    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    if tx_id != expected_id {
        return Err(DnsError::IdMismatch);
    }

    // Check RCODE (low 4 bits of byte 3).
    let rcode = packet[3] & 0x0F;
    if rcode != 0 {
        return Err(DnsError::ServerError(rcode));
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    // Skip questions section.
    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        // Skip QTYPE (2) + QCLASS (2).
        if pos + 4 > packet.len() {
            return Err(DnsError::TruncatedResponse);
        }
        pos += 4;
    }

    // Parse answer records.
    let mut addresses = Vec::new();
    let mut first_ttl = 0u32;
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return Err(DnsError::TruncatedResponse);
        }

        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let _rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            return Err(DnsError::TruncatedResponse);
        }

        if rtype == TYPE_A && rdlength == 4 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&packet[pos..pos + 4]);
            if addresses.is_empty() {
                first_ttl = ttl;
            }
            addresses.push(addr);
        }

        pos += rdlength;
    }

    if addresses.is_empty() {
        return Err(DnsError::NoAnswer);
    }

    Ok(DnsAnswer { tx_id, addresses, ttl: first_ttl })
}

/// Skip a DNS name (label sequence or compressed pointer) in the packet.
///
/// Returns the position after the name.
fn skip_name(packet: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        if pos >= packet.len() {
            return Err(DnsError::TruncatedResponse);
        }

        let len = packet[pos] as usize;
        if len == 0 {
            // Root label — end of name.
            return Ok(pos + 1);
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total, then done.
            if pos + 1 >= packet.len() {
                return Err(DnsError::TruncatedResponse);
            }
            return Ok(pos + 2);
        }

        // Normal label.
        pos += 1 + len;
    }
}

/// Resolve a domain name to IPv4 addresses using a specific DNS server.
///
/// Sends a UDP query to `server_addr` (e.g. "1.1.1.1:53") and waits
/// up to `timeout` for a response.
pub fn resolve(
    name: &str,
    server_addr: &str,
    tx_id: u16,
    timeout: std::time::Duration,
) -> Result<DnsAnswer, DnsError> {
    use std::net::UdpSocket;

    let query = build_query(name, tx_id)?;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(timeout))?;
    sock.send_to(&query, server_addr)?;

    let mut buf = [0u8; MAX_DNS_PACKET];
    let (n, _) = sock.recv_from(&mut buf)?;

    parse_response(&buf[..n], tx_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_basic() {
        let pkt = build_query("example.com", 0x1234).unwrap();
        // Header: 12 bytes.
        assert_eq!(pkt[0], 0x12);
        assert_eq!(pkt[1], 0x34);
        // RD flag set.
        assert_eq!(pkt[2] & 0x01, 0x01);
        // QDCOUNT = 1.
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1);
        // First label: "example" (7 bytes).
        assert_eq!(pkt[12], 7);
        assert_eq!(&pkt[13..20], b"example");
        // Second label: "com" (3 bytes).
        assert_eq!(pkt[20], 3);
        assert_eq!(&pkt[21..24], b"com");
        // Root terminator.
        assert_eq!(pkt[24], 0);
        // QTYPE=A(1), QCLASS=IN(1).
        assert_eq!(u16::from_be_bytes([pkt[25], pkt[26]]), TYPE_A);
        assert_eq!(u16::from_be_bytes([pkt[27], pkt[28]]), CLASS_IN);
    }

    #[test]
    fn name_too_long() {
        let long_name = "a".repeat(254);
        assert!(matches!(build_query(&long_name, 1), Err(DnsError::NameTooLong)));
    }

    #[test]
    fn label_too_long() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(matches!(build_query(&long_label, 1), Err(DnsError::LabelTooLong)));
    }

    #[test]
    fn parse_response_basic() {
        // Build a synthetic response for "example.com" -> 93.184.216.34.
        let query = build_query("example.com", 0xABCD).unwrap();
        let mut resp = Vec::new();

        // Header.
        resp.extend_from_slice(&[0xAB, 0xCD]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question (copy from query, offset 12..).
        resp.extend_from_slice(&query[12..]);

        // Answer: compressed name pointer to offset 12.
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer.
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300.
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4.
        resp.extend_from_slice(&[93, 184, 216, 34]); // RDATA.

        let ans = parse_response(&resp, 0xABCD).unwrap();
        assert_eq!(ans.tx_id, 0xABCD);
        assert_eq!(ans.addresses, vec![[93, 184, 216, 34]]);
        assert_eq!(ans.ttl, 300);
    }

    #[test]
    fn parse_response_id_mismatch() {
        let mut resp = vec![0u8; 12];
        resp[0] = 0x00;
        resp[1] = 0x01;
        assert!(matches!(parse_response(&resp, 0x0002), Err(DnsError::IdMismatch)));
    }

    #[test]
    fn parse_response_truncated() {
        assert!(matches!(parse_response(&[0u8; 4], 0), Err(DnsError::TruncatedResponse)));
    }

    #[test]
    fn parse_response_server_error() {
        let mut resp = vec![0u8; 12];
        resp[3] = 0x03; // RCODE=3 (NXDOMAIN).
        assert!(matches!(parse_response(&resp, 0), Err(DnsError::ServerError(3))));
    }

    #[test]
    fn parse_response_no_answer() {
        // Valid header, QDCOUNT=0, ANCOUNT=0.
        let resp = vec![0u8; 12];
        assert!(matches!(parse_response(&resp, 0), Err(DnsError::NoAnswer)));
    }

    #[test]
    fn build_query_single_label() {
        let pkt = build_query("localhost", 1).unwrap();
        assert_eq!(pkt[12], 9); // "localhost" = 9 chars.
    }

    #[test]
    fn parse_response_multiple_answers() {
        let query = build_query("multi.test", 0x5678).unwrap();
        let mut resp = Vec::new();

        // Header.
        resp.extend_from_slice(&[0x56, 0x78]);
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        resp.extend_from_slice(&[0x00, 0x02]); // ANCOUNT=2
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);

        // Question.
        resp.extend_from_slice(&query[12..]);

        // Answer 1.
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[10, 0, 0, 1]);

        // Answer 2.
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&120u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[10, 0, 0, 2]);

        let ans = parse_response(&resp, 0x5678).unwrap();
        assert_eq!(ans.addresses.len(), 2);
        assert_eq!(ans.addresses[0], [10, 0, 0, 1]);
        assert_eq!(ans.addresses[1], [10, 0, 0, 2]);
        assert_eq!(ans.ttl, 60); // First answer TTL.
    }
}
