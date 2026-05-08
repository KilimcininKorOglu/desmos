# Desmos

**Bond every link.**

Desmos is an open-source connection bonding VPN. It aggregates multiple network
interfaces (Wi-Fi + Ethernet + LTE + Starlink, etc.) into a single encrypted
tunnel that is both faster and more reliable than any link alone.

Written in Rust with a hand-rolled async runtime, Noise IK handshake,
ChaCha20-Poly1305 AEAD, and an embedded React admin UI. Ships as a single
static binary under 700 KB on six platforms with exactly five external runtime
dependencies.

[![CI](https://img.shields.io/github/actions/workflow/status/KilimcininKorOglu/desmos/ci.yml?branch=main)](https://github.com/KilimcininKorOglu/desmos/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/KilimcininKorOglu/desmos)](https://github.com/KilimcininKorOglu/desmos/releases)

## How It Works

```
          +---------+    TUN     +---------+    UDP/encrypted    +---------+
  apps -> | desmos  | --------> | bonding | ------------------> | desmos  | -> apps
          | client  |           | engine  |    per-interface     | server  |
          +---------+           +---------+    sockets           +---------+
                                  |  |  |
                              eth0 wlan0 lte0
```

Desmos opens a TUN device, intercepts all traffic, encrypts it with
ChaCha20-Poly1305, and distributes packets across multiple physical interfaces
using one of four bonding strategies. The server reassembles and decrypts.

## Features

- Bond 2-8 network interfaces into one encrypted tunnel
- Four bonding strategies, hot-swappable at runtime:
  - **Round-Robin** -- equal distribution across links
  - **Weighted** -- proportional distribution by configured weight
  - **Latency-Adaptive** -- favors lowest-RTT link (default)
  - **Redundant** -- sends every packet on all links for maximum reliability
- Sub-second failover with 10-second probation recovery
- Noise IK handshake: X25519 + ChaCha20-Poly1305 + BLAKE3, 1-RTT
- Client-server and P2P modes (STUN hole-punching + relay fallback)
- Six platforms: Linux, macOS, Windows, FreeBSD, OpenWrt, pfSense
- Single static binary, 650 KB (Linux x86_64 musl, stripped)
- Embedded Web UI: live throughput charts, WebSocket log streaming, strategy switching
- 17-route REST API with Prometheus metrics endpoint
- DNS leak protection with automatic resolver override
- PSK, public-key, TOTP, and mTLS authentication
- Hand-rolled: HTTP server, JSON codec, WebSocket, CLI parser, TOML parser, async runtime

## Performance

Measured on a single core, 1400-byte MTU:

| Metric                       | Measured         | Target     |
|------------------------------|------------------|------------|
| AEAD throughput              | 9.5 Gbps         | >= 2 Gbps  |
| Scheduler dispatch (RR)      | 67 ns/packet     | < 200 ns   |
| Reorder buffer (in-order)    | 73 ns/packet     | < 1 ms p99 |
| Handshake latency            | < 5 ms           | < 5 ms     |
| Failover time                | < 1 s            | < 1 s      |
| Binary size (musl, stripped) | 650 KB            | < 5 MB     |

## Install

### From release

Download the latest binary from
[Releases](https://github.com/KilimcininKorOglu/desmos/releases):

```bash
# Linux x86_64
curl -LO https://github.com/KilimcininKorOglu/desmos/releases/latest/download/desmos-x86_64-unknown-linux-musl.tar.gz
tar xzf desmos-x86_64-unknown-linux-musl.tar.gz
sudo mv desmos /usr/local/bin/
```

### From source

Requires Rust 1.75+ (pinned via `rust-toolchain.toml`):

```bash
git clone https://github.com/KilimcininKorOglu/desmos.git
cd desmos
cargo build --release
# Binary: target/release/desmos
```

### Platform-specific

| Platform          | Notes                                                              |
|-------------------|--------------------------------------------------------------------|
| Linux (musl)      | `cargo build --release --target x86_64-unknown-linux-musl`         |
| macOS             | `cargo build --release` (requires utun, run with `sudo`)           |
| Windows           | `cargo build --release` (requires `wintun.dll` next to binary)     |
| FreeBSD           | `cargo build --release`                                            |
| OpenWrt           | `./scripts/build-openwrt.sh` or cross-compile with `--no-default-features` |
| Homebrew (macOS)  | `brew install --build-from-source desmos` (from tap)               |

## Quick Start

### 1. Generate a config

```bash
desmos config generate > /etc/desmos/config.toml
```

### 2. Edit the config

**Client** (`/etc/desmos/config.toml`):

```toml
[general]
mode = "client"
tunnel_mtu = 1400

[client]
server = "vpn.example.com:4900"
server_public_key = "<hex-encoded-server-pubkey>"
private_key_file = "/etc/desmos/client.key"
bonding_strategy = "latency-adaptive"
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

**Server** (`/etc/desmos/server.toml`):

```toml
[general]
mode = "server"
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4900"
public_key = "<hex-encoded-server-pubkey>"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[server.auth]
method = "psk"
psk = "<shared-secret>"

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "<pbkdf2-phc-string>"
```

### 3. Validate

```bash
desmos config validate --config /etc/desmos/config.toml
```

### 4. Start

```bash
sudo desmos up --config /etc/desmos/config.toml
```

### 5. Monitor

```bash
desmos status          # Tunnel state, uptime, strategy, link count
desmos interfaces      # All host network interfaces
desmos stats           # Aggregate counters
desmos bonding         # Current strategy and link health
desmos clients         # Connected sessions (server mode)
desmos logs            # Recent log entries
```

Open `http://127.0.0.1:8080` for the Web UI dashboard.

## CLI Reference

```
desmos up           Start the tunnel (requires root/admin)
desmos down         Tear down the tunnel
desmos status       Show tunnel and link status
desmos reload       Hot-reload configuration
desmos config       Generate, validate, or show configuration
desmos bonding      Show or switch bonding strategy
desmos interfaces   List host network interfaces
desmos clients      List or kick connected clients (server mode)
desmos stats        Print aggregate server statistics
desmos logs         Tail recent log entries
desmos webui        Manage the embedded Web UI
desmos version      Print version and exit
```

All commands accept `--json` for machine-readable output. See
[docs/cli.md](docs/cli.md) for the full reference.

## Architecture

Seven-crate workspace with a strict dependency DAG (no cycles):

```
desmos-proto  ->  desmos-rt  ->  desmos-core  ->  desmos-http  -+
                                                                +->  desmos (bin)
                                    desmos-webui  --------------+
                                    desmos-cli   ---------------+
```

| Crate          | Responsibility                                              |
|----------------|-------------------------------------------------------------|
| `desmos-proto` | Wire types, Noise IK, AEAD, BLAKE3. No I/O.                |
| `desmos-rt`    | Reactors (epoll/kqueue/IOCP), TUN, sockets, timers.        |
| `desmos-core`  | Bonding engine, sessions, config, auth, server, P2P.       |
| `desmos-http`  | HTTP/1.1 server, WebSocket, JSON codec, Basic Auth.        |
| `desmos-webui` | REST API (17 routes), WebSocket streams, embedded React SPA.|
| `desmos-cli`   | Argument parser, 12 subcommands, IPC client.               |
| `desmos`       | Binary entry point.                                        |

Only five external runtime crates are allowed (`deny.toml` enforced):

| Crate      | Purpose                                |
|------------|----------------------------------------|
| `ring`     | AEAD, X25519, PBKDF2                   |
| `blake3`   | Transcript hash, KDF                   |
| `socket2`  | Socket primitives                      |
| `wintun`   | Windows TUN driver (Windows only)      |

Everything else (HTTP, JSON, TOML, CLI, async runtime, logging) is hand-rolled.

## Documentation

| Document                                           | Description                        |
|----------------------------------------------------|------------------------------------|
| [Getting Started](docs/getting-started.md)         | Install, configure, run, verify    |
| [Architecture](docs/architecture.md)               | Workspace DAG, platform model      |
| [Protocol](docs/protocol.md)                       | DWP wire format, Noise IK          |
| [CLI Reference](docs/cli.md)                       | All 12 subcommands                 |
| [Web UI Reference](docs/webui.md)                  | Pages, REST API, WebSocket         |
| [ADR 0001](docs/adr/0001-workspace-layout.md)      | Workspace layout rationale         |
| [ADR 0002](docs/adr/0002-hand-rolled-runtime.md)   | Why no tokio                       |
| [ADR 0003](docs/adr/0003-5-crate-budget.md)        | Five-crate dependency budget       |
| [ADR 0004](docs/adr/0004-typestate-for-sessions.md) | Typestate session pattern         |

## Authentication

| Method     | Mechanism                                          |
|------------|----------------------------------------------------|
| PSK        | Shared secret mixed into Noise IK handshake        |
| Public Key | X25519 key pairs, authorized_keys file             |
| TOTP       | RFC 6238, +/-1 period window, replay protection    |
| mTLS       | X.509 certificate chain verification via `ring`    |

Web UI uses HTTP Basic Auth with PBKDF2-HMAC-SHA256.

## Contributing

```bash
# Development cycle
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check bans licenses sources

# Frontend (optional, inside crates/desmos-webui/web/)
npm ci && npm run build
npm run typecheck && npm run lint
```

All code must pass the quality gate above before merge. MSRV is 1.75.0 (pinned).

## License

MIT. See [LICENSE](LICENSE).
