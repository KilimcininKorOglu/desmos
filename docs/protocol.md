# DWP Protocol Reference

The Desmos Wire Protocol (DWP) is a custom binary protocol carried over UDP.
Each packet consists of a 16-byte unencrypted header, an encrypted payload,
and a 16-byte AEAD authentication tag.

## Packet Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  Type |    Flags      |          Session ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Timestamp (microseconds)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         | Interface ID  |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+              Encrypted Payload (variable length)              +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   AEAD Tag (16 bytes)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Header Fields

| Offset | Size   | Field          | Description                              |
|--------|--------|----------------|------------------------------------------|
| 0      | 4 bits | Version        | Protocol version, currently `1`          |
| 0      | 4 bits | Type           | Packet type (see below)                  |
| 1      | 1 byte | Flags          | Bitfield (see below)                     |
| 2-3    | 2 bytes| Session ID     | u16 big-endian, identifies the session   |
| 4-7    | 4 bytes| Sequence       | u32 big-endian, monotonic per-session    |
| 8-11   | 4 bytes| Timestamp      | u32 big-endian, microseconds since epoch |
| 12-13  | 2 bytes| Payload Length | u16 big-endian, encrypted payload size   |
| 14     | 1 byte | Interface ID   | Identifies the sending interface          |
| 15     | 1 byte | Reserved       | Must be zero                             |

**Total header size: 16 bytes.**

## Packet Types

| Value | Name      | Description                                |
|-------|-----------|--------------------------------------------|
| 0     | Data      | Tunnel payload (IP packets)                |
| 1     | Handshake | Noise IK handshake messages                |
| 2     | Keepalive | Empty payload, maintains NAT mappings      |
| 3     | Probe     | Link quality measurement (RTT, loss)       |
| 4     | Control   | Configuration and signaling messages       |

## Flags

| Bit | Name      | Description                                |
|-----|-----------|--------------------------------------------|
| 0   | FIN       | Session teardown                           |
| 1   | ACK       | Acknowledgment                             |
| 2   | FRAG      | Packet is a fragment (PMTUD)               |
| 3   | REDUNDANT | Packet sent on multiple links              |
| 4   | PRIORITY  | High-priority packet                       |
| 5-7 | Reserved  | Must be zero, preserved for compatibility  |

## Encryption

- **Algorithm**: ChaCha20-Poly1305 AEAD (RFC 8439)
- **Key derivation**: BLAKE3 keyed hash from session master secret
- **Nonce**: 12 bytes, derived from sequence number + interface ID
- **Tag size**: 16 bytes (Poly1305)
- **Associated data**: The 16-byte header (authenticated but not encrypted)

The header is transmitted in plaintext so routers and middleboxes can
forward packets without decryption. Only the payload is encrypted.

## Handshake

The Noise IK pattern is used for 1-RTT key exchange:

```
Initiator                          Responder
    |                                  |
    |--- e, es, s, ss --------------->|  (Handshake message 1)
    |                                  |
    |<-- e, ee, se -------------------|  (Handshake message 2)
    |                                  |
    [Session established, rekey timer starts]
```

- **DH**: X25519 (hand-rolled from TweetNaCl)
- **Cipher**: ChaCha20-Poly1305 (via ring)
- **Hash**: BLAKE3
- **Rekey**: Every 2^32 packets or 120 seconds, whichever comes first

## Fragmentation (PMTUD)

When a packet exceeds the path MTU, the FRAG flag is set and the
payload is split into fragments. Each fragment carries a fragment
offset in the first 4 bytes of the encrypted payload. The receiver
reassembles fragments using a time-bounded reassembly buffer
(default 50 ms window).

## Wire Sizes

| Component        | Size           |
|------------------|----------------|
| Header           | 16 bytes       |
| AEAD tag         | 16 bytes       |
| Minimum packet   | 32 bytes       |
| Default MTU      | 1400 bytes     |
| Max payload      | 65,519 bytes   |
| Packet overhead  | 256 bytes (with slack) |
