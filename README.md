# Desmos

**Bond every link.**

Desmos is an open-source connection bonding VPN written in Rust. It combines
Wi-Fi, Ethernet, LTE, and any other network interface into a single encrypted
tunnel that is both faster and more reliable than any link alone. A single
static binary ships on six platforms with only five external dependencies.

[![CI](https://img.shields.io/github/actions/workflow/status/KilimcininKorOglu/desmos/ci.yml?branch=main)](https://github.com/KilimcininKorOglu/desmos/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- Bond 2-8 network interfaces into a single encrypted tunnel
- Four bonding strategies: Round-Robin, Weighted, Latency-Adaptive, Redundant
- Sub-second failover on interface loss with 10-second probation recovery
- Noise IK handshake (X25519 + ChaCha20-Poly1305 + BLAKE3), 1-RTT key exchange
- Client-server and peer-to-peer modes with STUN hole-punching and relay fallback
- Runs on Linux, macOS, Windows, FreeBSD, OpenWrt, and pfSense
- Single static binary, five external runtime dependencies
- Embedded Web UI with live throughput charts and WebSocket streaming
- DNS leak protection with automatic system resolver override
- Hand-rolled HTTP server, JSON codec, WebSocket, CLI parser, and TOML parser

## Performance

| Metric                         | Target                      |
|--------------------------------|-----------------------------|
| Single-core throughput         | >= 2 Gbps                   |
| Bonding overhead               | < 3%                        |
| Handshake latency              | < 5 ms                      |
| Failover time                  | < 1 second                  |
| Client memory (3 interfaces)   | < 20 MB                     |
| Binary size (Linux x86_64)     | < 5 MB                      |

## Install

### From source

```bash
git clone https://github.com/KilimcininKorOglu/desmos.git
cd desmos
cargo build --release
```

The binary is at `target/release/desmos`.

### Linux (musl static)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### OpenWrt (IPK)

```bash
# Cross-compile for the target architecture (see docs for toolchain setup)
cargo build --release --target <openwrt-target>
# Package with the included IPK builder
./packaging/openwrt/build-ipk.sh
```

### Windows

```bash
cargo build --release
# Requires wintun.dll in the same directory as the binary
```

### macOS / FreeBSD

```bash
cargo build --release
```

## Quick Start

### Client

Create `/etc/desmos/config.toml`:

```toml
[general]
mode = "client"
log_level = "info"
tunnel_mtu = 1400

[client]
server = "vpn.example.com:4789"
server_public_key = "<server-public-key>"
private_key_file = "/etc/desmos/client.key"
bonding_strategy = "latency-adaptive"
reorder_window_ms = 50
dns_leak_protection = true
dns_servers = ["1.1.1.1", "8.8.8.8"]

[[client.interfaces]]
name = "eth0"
weight = 100
enabled = true

[[client.interfaces]]
name = "wlan0"
weight = 80
enabled = true
```

Start the tunnel:

```bash
sudo desmos up
```

Check status:

```bash
desmos status
```

### Server

```toml
[general]
mode = "server"
log_level = "info"
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4789"
public_key = "<server-public-key>"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[auth]
method = "psk"
psk = "<pre-shared-key>"

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "<pbkdf2-hash>"
```

```bash
sudo desmos up --config /etc/desmos/server.toml
```

## Workspace

```
desmos-proto    Wire protocol, crypto primitives, handshake (I/O-free)
desmos-rt       Hand-rolled async runtime: reactor, TUN, sockets, timers
desmos-core     Domain logic: bonding, sessions, config, auth, server
desmos-http     HTTP/1.1 server, WebSocket, JSON codec, Basic Auth
desmos-webui    REST API handlers, embedded React SPA
desmos-cli      CLI parser, subcommand dispatcher
desmos          Binary entry point
```

## Documentation

| Document                                          | Description                  |
|---------------------------------------------------|------------------------------|
| [Architecture](docs/architecture.md)              | Workspace DAG, platform model|
| [Protocol](docs/protocol.md)                      | DWP wire format              |
| [CLI Reference](docs/cli.md)                      | All 12 subcommands           |
| [Web UI Reference](docs/webui.md)                 | Pages, API, WebSocket        |
| [ADR 0001](docs/adr/0001-workspace-layout.md)     | Workspace layout             |
| [ADR 0002](docs/adr/0002-hand-rolled-runtime.md)  | Hand-rolled runtime          |
| [ADR 0003](docs/adr/0003-5-crate-budget.md)       | Five-crate budget            |
| [ADR 0004](docs/adr/0004-typestate-for-sessions.md)| Typestate sessions          |

## Authentication

| Method     | Use case                                          |
|------------|---------------------------------------------------|
| PSK        | Simple shared secret for small deployments        |
| Public Key | Ed25519 key pair, no shared secret needed         |
| TOTP       | RFC 6238 time-based one-time password             |
| mTLS       | Certificate-based, for enterprise environments    |

The Web UI uses HTTP Basic Auth with PBKDF2-HMAC-SHA256.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `cargo fmt && cargo clippy -D warnings && cargo test --workspace`
4. Submit a pull request

All code must pass `cargo deny check bans licenses sources` before merge.

## License

Desmos is released under the MIT License. See [LICENSE](LICENSE).
