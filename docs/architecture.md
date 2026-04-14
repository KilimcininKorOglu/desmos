# Architecture

Desmos is a cross-platform connection bonding VPN built entirely in Rust.
It aggregates multiple network interfaces into a single encrypted tunnel,
distributing traffic across links for higher throughput and resilience.

## Workspace DAG

Seven crates form a strict dependency DAG with no cycles:

```
desmos-proto   desmos-rt
     \            /
      desmos-core
           |
      desmos-http
       /       \
desmos-webui  desmos-cli
       \       /
        desmos    (binary)
```

| Crate          | Role                                                     |
|----------------|----------------------------------------------------------|
| `desmos-proto` | Wire protocol, crypto primitives, handshake (I/O-free)   |
| `desmos-rt`    | Hand-rolled async runtime: reactor, TUN, sockets, timers |
| `desmos-core`  | Domain logic: bonding, sessions, config, auth, server    |
| `desmos-http`  | HTTP/1.1 server, WebSocket, JSON codec, Basic Auth       |
| `desmos-webui` | REST API handlers and embedded React SPA                 |
| `desmos-cli`   | CLI argument parser and subcommand dispatcher            |
| `desmos`       | Binary entry point, daemon runner                        |

## Runtime Dependency Budget

Exactly five external runtime crates are permitted:

| Crate     | Purpose                                   |
|-----------|-------------------------------------------|
| `ring`    | ChaCha20-Poly1305 AEAD, PBKDF2, HKDF     |
| `blake3`  | Session key derivation, integrity hashing  |
| `socket2` | Cross-platform socket options              |
| `wintun`  | Windows TUN adapter (Windows-only)         |

Everything else is hand-rolled: TOML parser, JSON codec, HTTP server,
WebSocket, CLI parser, event loop, timer wheel, and DNS resolver.

## Platform I/O Model

Each platform has a native non-blocking I/O backend:

| Platform        | Reactor   | TUN Backend         |
|-----------------|-----------|---------------------|
| Linux           | epoll     | `/dev/net/tun`      |
| macOS           | kqueue    | `utun` (SystemConfiguration) |
| FreeBSD         | kqueue    | `/dev/tun`          |
| Windows         | IOCP      | Wintun              |

The reactor is the only component that touches `unsafe` syscall FFI.
All platform-specific code lives in `desmos-rt`.

## Encryption Pipeline

```
Application packet
       |
  [TUN read]
       |
  [Bonding Engine] --- selects outbound link(s)
       |
  [DWP Header]    --- 16-byte unencrypted header
       |
  [ChaCha20-Poly1305 AEAD] --- encrypt payload
       |
  [UDP send]       --- per-interface socket
```

Inbound traffic reverses the pipeline: UDP recv, AEAD decrypt, reorder
buffer, TUN write.

## Bonding Strategies

Four strategies are available, hot-switchable at runtime:

| Strategy          | Algorithm                                    |
|-------------------|----------------------------------------------|
| Round-Robin       | Rotate across links sequentially              |
| Weighted          | Distribute proportional to configured weights |
| Latency-Adaptive  | Score links by RTT, loss, jitter, throughput  |
| Redundant         | Send every packet on all links                |

Link quality is measured via probe packets every 500 ms. The link score
formula is:

```
score = w1*(1/RTT) + w2*(1-loss) + w3*(1/jitter) + w4*throughput
```

## Session Lifecycle

Sessions use a typestate pattern: `Initiator -> Handshaking -> Established`.
The Noise IK handshake (X25519 + ChaCha20-Poly1305 + BLAKE3) completes in
1 RTT. Rekey occurs every 2^32 packets or 120 seconds.

## Failover

| Condition              | Threshold                       |
|------------------------|---------------------------------|
| Degraded               | >20% loss or >500 ms RTT for 5 probes |
| Dead                   | No response for 3 seconds       |
| Recovery               | 10-second probation at reduced weight |

## Authentication

Four methods are supported for tunnel peers:

- **PSK**: Pre-shared key
- **Public Key**: Ed25519 key pair
- **TOTP**: RFC 6238, +/- 1 period tolerance
- **mTLS**: Minimal TLS 1.3 certificate verification via ring

The Web UI uses HTTP Basic Auth with PBKDF2-HMAC-SHA256 password hashing.

## Web UI

A React SPA is compiled by Vite and embedded into the binary at build time
via `include_bytes!`. The hand-rolled HTTP server serves both the API and
static files. Six pages: Dashboard, Interfaces, Bonding, Connections, Logs,
Settings. Live updates via WebSocket at 2 Hz.

## DNS Leak Protection

When `dns_leak_protection = true`, the system DNS resolver is overridden
to route queries through the tunnel. Platform-specific implementations:
Linux/FreeBSD rewrite `/etc/resolv.conf`, macOS uses `scutil`, Windows
uses `netsh`. An RAII guard ensures the original configuration is restored
on teardown.
