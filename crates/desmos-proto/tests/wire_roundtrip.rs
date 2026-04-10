//! Deterministic 1000-case round-trip fuzzer for the DWP header codec.
//!
//! Uses a seeded xorshift64 PRNG so failures are reproducible from the
//! seed alone. proptest is unusable on MSRV 1.75.0 (see
//! `crates/desmos-core/tests/toml_roundtrip.rs` for the full story).

use desmos_proto::Flags;
use desmos_proto::Header;
use desmos_proto::InterfaceId;
use desmos_proto::PacketType;
use desmos_proto::Seq;
use desmos_proto::SessionId;
use desmos_proto::TimestampUs;
use desmos_proto::HEADER_LEN;
use desmos_proto::WIRE_VERSION;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed } }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

fn random_header(rng: &mut Rng) -> Header {
    let packet_type = match rng.next_u64() % 5 {
        0 => PacketType::Data,
        1 => PacketType::Handshake,
        2 => PacketType::Keepalive,
        3 => PacketType::Probe,
        _ => PacketType::Control,
    };
    Header {
        version: WIRE_VERSION,
        packet_type,
        // Full 8-bit flag space, including unknown bits the decoder must preserve.
        flags: Flags::from_bits(rng.next_u8()),
        session_id: SessionId(rng.next_u16()),
        sequence: Seq(rng.next_u32()),
        timestamp_us: TimestampUs(rng.next_u32()),
        payload_len: rng.next_u16(),
        interface_id: InterfaceId(rng.next_u8()),
    }
}

#[test]
fn roundtrip_1000_random_headers() {
    let mut rng = Rng::new(0xdead_c0de_1234_5678);
    let mut buf = [0u8; HEADER_LEN];
    for case in 0..1000 {
        let h = random_header(&mut rng);
        h.encode(&mut buf).expect("encode");
        let decoded = Header::decode(&buf).unwrap_or_else(|e| {
            panic!("decode failed on case {case}: {e}\nheader={h:?}\nbytes={buf:?}")
        });
        assert_eq!(decoded, h, "roundtrip mismatch on case {case}");
    }
}

#[test]
fn roundtrip_edge_case_values() {
    let cases = [
        Header {
            version: WIRE_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::EMPTY,
            session_id: SessionId(0),
            sequence: Seq(0),
            timestamp_us: TimestampUs(0),
            payload_len: 0,
            interface_id: InterfaceId(0),
        },
        Header {
            version: WIRE_VERSION,
            packet_type: PacketType::Control,
            flags: Flags::from_bits(0xff),
            session_id: SessionId(u16::MAX),
            sequence: Seq(u32::MAX),
            timestamp_us: TimestampUs(u32::MAX),
            payload_len: u16::MAX,
            interface_id: InterfaceId(u8::MAX),
        },
    ];
    let mut buf = [0u8; HEADER_LEN];
    for h in cases {
        h.encode(&mut buf).unwrap();
        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded, h);
    }
}
