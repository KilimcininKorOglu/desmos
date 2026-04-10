# Desmos — Connection Bonding VPN

**Version:** 1.0 PRD  
**Author:** KilimcininKorOglu  
**Date:** 2026-04-10  
**Language:** Rust  
**License:** MIT

---

## 1. Overview

Desmos is an open-source, cross-platform connection bonding VPN that combines multiple network interfaces (Wi-Fi, Ethernet, LTE/5G, secondary WAN) into a single, faster, and more reliable tunnel. It operates in a client-server architecture with optional P2P mode, written in Rust with minimal external dependencies.

The name comes from Greek δεσμός ("bond, link") — reflecting the core purpose of binding connections together.

### 1.1 Problem Statement

- Single internet connections are unreliable: Wi-Fi drops, cellular has variable latency, wired connections fail
- Existing solutions (Speedify, OpenMPTCProuter) are either proprietary, expensive, or complex to deploy
- No open-source solution exists that combines bonding, encryption, and cross-platform support in a single lightweight binary

### 1.2 Goals

- Bond 2–8 network interfaces into a unified tunnel with automatic failover
- Achieve near-aggregate bandwidth via intelligent packet distribution
- Support client-server and P2P tunnel modes
- Run on Linux, Windows, macOS, FreeBSD, OpenWrt, and pfSense
- Ship as a single static binary per platform (no runtime dependencies)
- Provide CLI + Web UI management interfaces

### 1.3 Non-Goals (v1.0)

- Full mesh VPN (Tailscale/Nebula style) — single tunnel only
- Built-in NAT traversal relay infrastructure (STUN/TURN provided, relay fallback via existing Desmos server)
- Mobile platforms (iOS/Android) — future versions
- WireGuard/OpenVPN protocol compatibility — Desmos uses its own protocol

---

## 2. Architecture

### 2.1 High-Level Design

```
┌─────────────────────────────────────────────────────┐
│                    Desmos Client                     │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  eth0    │  │  wlan0   │  │  lte0    │  Interfaces│
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │              │                 │
│  ┌────▼──────────────▼──────────────▼─────┐          │
│  │         Bonding Engine                  │          │
│  │  ┌─────────────────────────────────┐   │          │
│  │  │  Scheduler (RR/Weighted/        │   │          │
│  │  │  Latency-Adaptive/Redundant)    │   │          │
│  │  └─────────────────────────────────┘   │          │
│  │  ┌─────────────────────────────────┐   │          │
│  │  │  Packet Sequencer & Reorder Buf │   │          │
│  │  └─────────────────────────────────┘   │          │
│  └────────────────┬───────────────────┘   │          │
│                   │                                   │
│  ┌────────────────▼───────────────────┐              │
│  │  Crypto Layer (ChaCha20-Poly1305)  │              │
│  └────────────────┬───────────────────┘              │
│                   │                                   │
│  ┌────────────────▼───────────────────┐              │
│  │  TUN Interface (desmos0)           │              │
│  └────────────────────────────────────┘              │
└─────────────────────────────────────────────────────┘
                    │  UDP tunnels (per interface)
                    ▼
┌─────────────────────────────────────────────────────┐
│                   Desmos Server                      │
│                                                      │
│  ┌────────────────────────────────────┐              │
│  │  Tunnel Multiplexer                │              │
│  │  (reassemble from multiple paths)  │              │
│  └────────────────┬───────────────────┘              │
│                   │                                   │
│  ┌────────────────▼───────────────────┐              │
│  │  TUN Interface → Internet          │              │
│  └────────────────────────────────────┘              │
└─────────────────────────────────────────────────────┘
```

### 2.2 Operating Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Client-Server** | Client bonds interfaces, server aggregates and routes to internet | Primary mode — remote VPN with bonding |
| **P2P Tunnel** | Two peers bond interfaces for a direct encrypted tunnel | Site-to-site, direct file transfer |

### 2.3 Core Components

```
desmos/
├── src/
│   ├── main.rs                  # Entry point, CLI parsing
│   ├── config/
│   │   ├── mod.rs
│   │   └── schema.rs            # TOML config parsing (hand-rolled)
│   ├── tun/
│   │   ├── mod.rs               # Platform-agnostic TUN trait
│   │   ├── linux.rs             # Linux TUN via ioctl
│   │   ├── macos.rs             # macOS utun
│   │   ├── windows.rs           # Wintun driver interface
│   │   ├── freebsd.rs           # FreeBSD /dev/tun
│   │   └── openwrt.rs           # OpenWrt (Linux TUN + UCI hooks)
│   ├── bonding/
│   │   ├── mod.rs               # Bonding engine trait + orchestrator
│   │   ├── scheduler.rs         # Scheduling strategies
│   │   ├── probe.rs             # Link quality monitoring (RTT, loss, jitter)
│   │   ├── reorder.rs           # Packet reordering buffer
│   │   └── failover.rs          # Interface failover logic
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── wire.rs              # Wire format (header + payload)
│   │   ├── handshake.rs         # Key exchange (X25519 + Noise-like)
│   │   ├── session.rs           # Session management
│   │   └── keepalive.rs         # Keepalive & dead peer detection
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── chacha20.rs          # ChaCha20-Poly1305 AEAD
│   │   ├── x25519.rs            # X25519 key exchange
│   │   ├── blake3.rs            # BLAKE3 hashing
│   │   └── noise.rs             # Noise protocol framework (IK pattern)
│   ├── net/
│   │   ├── mod.rs
│   │   ├── interface.rs         # Network interface discovery & monitoring
│   │   ├── socket.rs            # UDP socket per interface (SO_BINDTODEVICE)
│   │   ├── stun.rs              # STUN client (NAT traversal for P2P)
│   │   └── dns.rs               # Minimal DNS resolver
│   ├── server/
│   │   ├── mod.rs
│   │   ├── listener.rs          # Multi-client tunnel listener
│   │   ├── nat.rs               # NAT/masquerade for client traffic
│   │   └── auth.rs              # Client authentication
│   ├── webui/
│   │   ├── mod.rs
│   │   ├── server.rs            # Embedded HTTP server
│   │   ├── api.rs               # REST API endpoints
│   │   ├── ws.rs                # WebSocket for real-time stats
│   │   └── static/              # Embedded frontend (HTML/JS/CSS)
│   └── cli/
│       ├── mod.rs
│       └── commands.rs          # CLI subcommands
├── Cargo.toml
├── desmos.toml.example          # Example config
└── README.md
```

---

## 3. Desmos Wire Protocol (DWP)

### 3.1 Packet Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  | Type  |    Flags      |         Session ID            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Timestamp (µs)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |    Interface ID  |  Reserved  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Encrypted Payload                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Authentication Tag (128-bit)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Header: 16 bytes (unencrypted)**

| Field | Bits | Description |
|-------|------|-------------|
| Version | 4 | Protocol version (1) |
| Type | 4 | 0=Data, 1=Handshake, 2=Keepalive, 3=Probe, 4=Control |
| Flags | 8 | FIN, ACK, FRAG, REDUNDANT, PRIORITY |
| Session ID | 16 | Session identifier |
| Sequence Number | 32 | Monotonic per-session counter |
| Timestamp | 32 | Microsecond precision for RTT calculation |
| Payload Length | 16 | Encrypted payload length |
| Interface ID | 8 | Source interface index |
| Reserved | 8 | Future use |

### 3.2 Handshake (Noise IK Pattern)

```
Client                                    Server
  │                                          │
  │  1. → e, es, s, ss (InitiatorHello)     │
  │     [client ephemeral + static]          │
  │                                          │
  │  2. ← e, ee, se (ResponderHello)        │
  │     [server ephemeral]                   │
  │                                          │
  │  3. → Transport Data                     │
  │     [encrypted with derived keys]        │
  │                                          │
```

- Key exchange: X25519
- Symmetric cipher: ChaCha20-Poly1305
- Hash: BLAKE3
- Key derivation: HKDF-BLAKE3
- Perfect forward secrecy via ephemeral keys
- Rekey every 2^32 packets or 120 seconds (whichever first)

### 3.3 Transport Layer

- **UDP-based** — one UDP socket per physical interface, all targeting same server endpoint
- **MTU discovery** via PMTUD (Path MTU Discovery) with fallback to 1280
- **Fragmentation** handled at DWP layer (FRAG flag) for payloads exceeding tunnel MTU

---

## 4. Bonding Engine

### 4.1 Scheduling Strategies

| Strategy | Algorithm | Best For |
|----------|-----------|----------|
| **Round-Robin** | Distribute packets sequentially across interfaces | Equal-speed links |
| **Weighted** | Distribute proportional to configured weights | Known asymmetric links |
| **Latency-Adaptive** | Distribute based on real-time RTT/loss/jitter scoring | Mixed quality links (default) |
| **Redundant** | Send same packet on all interfaces | Ultra-reliability, latency-critical |

### 4.2 Link Quality Monitoring

Each interface is continuously probed:

```
Link Score = w1 * (1/RTT_avg) + w2 * (1 - loss_rate) + w3 * (1/jitter) + w4 * throughput
```

- **Probe interval:** 500ms (adjustable)
- **RTT:** Measured via Probe packets with microsecond timestamps
- **Loss rate:** Rolling window of last 100 packets
- **Jitter:** Standard deviation of RTT over rolling window
- **Throughput:** Estimated from ACK'd data volume per second

### 4.3 Packet Reordering Buffer

Since packets arrive via different interfaces with varying latencies:

- Reorder buffer holds out-of-order packets up to **max_reorder_window** (default: 50ms)
- Packets delivered to TUN in sequence-number order
- If gap timeout expires, skip missing packet (assumed lost)
- Duplicate detection via sequence number + interface ID bitmap

### 4.4 Failover

- Interface marked **degraded** if loss > 20% or RTT > 500ms for 5 consecutive probes
- Interface marked **dead** if no probe response for 3 seconds
- Traffic immediately redistributed to remaining healthy interfaces
- Recovered interface enters **probation** (reduced weight) for 10 seconds before full reintegration

---

## 5. Platform Support

### 5.1 TUN/TAP Implementation

| Platform | TUN Method | Socket Binding | Privileges |
|----------|-----------|----------------|------------|
| **Linux** | `/dev/net/tun` via `ioctl(TUNSETIFF)` | `SO_BINDTODEVICE` | `CAP_NET_ADMIN` |
| **macOS** | `/dev/utunN` via `socket(PF_SYSTEM)` | Per-socket routing via `IP_BOUND_IF` | root |
| **Windows** | Wintun driver (bundled `.dll`) | Interface-specific `bind()` | Administrator |
| **FreeBSD** | `/dev/tunN` via `open()` + `ioctl` | `IP_SENDSRCADDR` + routing | root |
| **OpenWrt** | Linux TUN + UCI integration | `SO_BINDTODEVICE` | root |
| **pfSense** | FreeBSD TUN + `devd` hooks | Same as FreeBSD | root |

### 5.2 Build Targets

```
# Tier 1 (CI-tested, release binaries)
x86_64-unknown-linux-musl        # Linux (static, glibc-free)
x86_64-unknown-linux-gnu         # Linux (glibc)
aarch64-unknown-linux-musl       # Linux ARM64 (RPi, servers)
x86_64-apple-darwin              # macOS Intel
aarch64-apple-darwin             # macOS Apple Silicon
x86_64-pc-windows-msvc           # Windows
x86_64-unknown-freebsd           # FreeBSD / pfSense

# Tier 2 (CI-tested, best-effort)
mips-unknown-linux-musl          # OpenWrt (older routers)
mipsel-unknown-linux-musl        # OpenWrt (MIPS LE)
aarch64-unknown-linux-musl       # OpenWrt (ARM64 routers)
armv7-unknown-linux-musleabihf   # OpenWrt (ARM routers)
```

### 5.3 OpenWrt Integration

- LuCI app package (`luci-app-desmos`) for web-based configuration
- UCI config schema at `/etc/config/desmos`
- init.d service script with procd integration
- IPK package for opkg

### 5.4 pfSense Integration

- FreeBSD pkg for pfSense
- pfSense package XML manifest for GUI integration
- rc.d service script

---

## 6. Configuration

### 6.1 Config File (`desmos.toml`)

```toml
[general]
mode = "client"                    # "client" | "server" | "p2p"
log_level = "info"                 # "trace" | "debug" | "info" | "warn" | "error"
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4900"
public_key = "base64_encoded_server_public_key"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[server.auth]
method = "psk"                     # "psk" | "pubkey" | "totp" | "mtls"
psk = "shared_secret_here"
# TOTP options (when method = "totp")
totp_secret = "base32_encoded_secret"
totp_digits = 6
totp_period = 30
# mTLS options (when method = "mtls")
ca_cert = "/etc/desmos/ca.pem"
server_cert = "/etc/desmos/server.crt"
server_key = "/etc/desmos/server.key"

[client]
server = "vpn.example.com:4900"
server_public_key = "base64_encoded_server_public_key"
private_key_file = "~/.config/desmos/client.key"
bonding_strategy = "latency-adaptive"  # "round-robin" | "weighted" | "latency-adaptive" | "redundant"
reorder_window_ms = 50
dns_leak_protection = true             # Route all DNS through tunnel (optional, default: true)
dns_servers = ["1.1.1.1", "8.8.8.8"]  # DNS servers used when leak protection is enabled

[[client.interfaces]]
name = "eth0"
weight = 100
enabled = true

[[client.interfaces]]
name = "wlan0"
weight = 80
enabled = true

[[client.interfaces]]
name = "wwan0"
weight = 50
enabled = true

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "argon2_hash_here"

[p2p]
peer_public_key = "base64_encoded_peer_key"
peer_endpoint = "peer.example.com:4900"
stun_servers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
```

### 6.2 CLI Interface

```
desmos — Connection Bonding VPN

USAGE:
    desmos <COMMAND> [OPTIONS]

COMMANDS:
    up              Start tunnel (client/server/p2p based on config)
    down            Stop tunnel
    status          Show tunnel status, interface stats, throughput
    interfaces      List available network interfaces
    keygen          Generate keypair
    config          Validate or generate config
    webui           Start standalone Web UI

CLIENT SUBCOMMANDS:
    desmos up --config /path/to/desmos.toml
    desmos status
    desmos status --json
    desmos interfaces --monitor          # Real-time interface monitoring
    desmos bonding set-strategy <NAME>   # Hot-switch bonding strategy
    desmos bonding disable <IFACE>       # Temporarily disable interface
    desmos bonding enable <IFACE>        # Re-enable interface

SERVER SUBCOMMANDS:
    desmos up --mode server --listen 0.0.0.0:4900
    desmos clients                       # List connected clients
    desmos clients kick <SESSION_ID>     # Disconnect client
    desmos stats                         # Server throughput stats

GLOBAL OPTIONS:
    -c, --config <PATH>     Config file path (default: /etc/desmos/desmos.toml)
    -v, --verbose           Increase log verbosity
    -q, --quiet             Suppress output
    --no-color              Disable colored output
    --json                  Output in JSON format
```

---

## 7. Web UI

### 7.1 Technology

- Embedded HTTP server (hand-rolled, no framework)
- Frontend: React (built at compile time, output embedded in binary via `include_bytes!`)
- WebSocket for real-time stats streaming
- REST API for configuration and control

### 7.2 Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Real-time throughput graph, per-interface bandwidth bars, tunnel status |
| **Interfaces** | List of interfaces with RTT/loss/jitter, enable/disable toggle |
| **Bonding** | Strategy selection, weight sliders, reorder buffer stats |
| **Connections** | (Server) Connected clients, session info, per-client bandwidth |
| **Logs** | Live log stream with level filtering |
| **Settings** | Config editor, keypair management, auth settings |

### 7.3 REST API

```
GET    /api/v1/status                  # Tunnel status
GET    /api/v1/interfaces              # Interface list + stats
PUT    /api/v1/interfaces/:name        # Enable/disable/configure interface
GET    /api/v1/bonding                 # Current strategy + metrics
PUT    /api/v1/bonding/strategy        # Change bonding strategy
GET    /api/v1/stats                   # Throughput, packets, errors
GET    /api/v1/clients                 # (Server) Connected clients
DELETE /api/v1/clients/:session_id     # (Server) Kick client
GET    /api/v1/config                  # Current config
PUT    /api/v1/config                  # Update config (hot-reload)
GET    /api/v1/logs?level=info&n=100   # Recent logs
WS     /api/v1/ws/stats               # Real-time stats stream
WS     /api/v1/ws/logs                 # Real-time log stream
```

---

## 8. Crypto Architecture

### 8.1 Dependency Decision

| Component | Implementation | Rationale |
|-----------|---------------|-----------|
| ChaCha20-Poly1305 | `ring` crate | Audited, BoringSSL-backed, constant-time |
| X25519 | `ring` crate | Same — avoid rolling own ECC |
| BLAKE3 | `blake3` crate | Official, SIMD-optimized, single-purpose |
| Argon2 (password hashing) | `argon2` crate | Audited, security-critical for Web UI auth |
| HKDF | Built on BLAKE3 | Simple, no extra dependency |
| Noise framework | Hand-rolled | Only IK pattern needed, ~500 LOC |

### 8.2 Minimal Dependency List

| Crate | Purpose | Justification |
|-------|---------|---------------|
| `ring` | Crypto primitives | Security-critical, must not be hand-rolled |
| `blake3` | Hashing | SIMD-optimized official implementation |
| `socket2` | Cross-platform socket options | `SO_BINDTODEVICE`, `IP_BOUND_IF` etc. |
| `wintun` | Windows TUN driver FFI | No alternative for Windows TUN |
| `argon2` | Password hashing | Security-critical for Web UI authentication |

**Total: 5 external crates.** Everything else is hand-written:

- CLI argument parsing: hand-rolled
- TOML parsing: hand-rolled (subset parser)
- HTTP server: hand-rolled
- WebSocket: hand-rolled
- JSON serialization: hand-rolled
- Logging: hand-rolled
- Async runtime: hand-rolled (epoll/kqueue/IOCP event loop)

---

## 9. Async Runtime

### 9.1 Custom Event Loop

No tokio/async-std. Desmos implements a minimal event loop per platform:

| Platform | Mechanism | Implementation |
|----------|-----------|----------------|
| Linux | `epoll` | `epoll_create1`, `epoll_ctl`, `epoll_wait` via syscalls |
| macOS / FreeBSD | `kqueue` | `kqueue()`, `kevent()` via syscalls |
| Windows | IOCP | `CreateIoCompletionPort`, `GetQueuedCompletionStatus` |

The event loop manages:
- TUN device read/write
- Multiple UDP sockets (one per interface)
- WebSocket connections
- HTTP server connections
- Timer wheel for keepalives, probes, rekey

### 9.2 Threading Model

```
Thread 1: Event loop (packet I/O, TUN read/write)
Thread 2: Bonding engine (scheduling decisions, probe processing)
Thread 3: Crypto (encryption/decryption pipeline)
Thread 4: Web UI HTTP server
Thread 5: Stats collector & logger
```

Inter-thread communication via lock-free SPSC/MPSC ring buffers (hand-rolled).

---

## 10. Security

### 10.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Passive eavesdropping | ChaCha20-Poly1305 encryption on all tunnel traffic |
| Active MITM | Noise IK handshake with pre-shared server public key |
| Replay attacks | Sequence numbers + sliding window anti-replay |
| Key compromise | PFS via ephemeral X25519, periodic rekey |
| DoS on server | Rate limiting, cookie-based handshake anti-amplification |
| Web UI unauthorized access | Argon2 password hash, bind to localhost by default |

### 10.2 Privilege Separation

```
1. Start as root/admin → create TUN, bind sockets
2. Drop to unprivileged user (desmos:desmos)
3. seccomp-bpf filter (Linux) restricts syscalls
4. pledge/unveil (FreeBSD) restricts filesystem + syscalls
5. Sandbox profile (macOS) restricts capabilities
```

---

## 11. Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Single-core throughput | ≥ 2 Gbps | ChaCha20 SIMD + zero-copy path |
| Bonding overhead | < 3% | vs raw aggregate bandwidth |
| Handshake latency | < 5ms | 1-RTT handshake |
| Failover time | < 1 second | Interface down → traffic rerouted |
| Memory (client) | < 20 MB RSS | Steady state, 3 interfaces |
| Memory (server, 100 clients) | < 200 MB RSS | |
| Binary size (stripped) | < 5 MB | Linux x86_64 static |
| Reorder buffer latency | < 1ms | 99th percentile added latency |

---

## 12. Development Roadmap

### Phase 1 — Foundation (Weeks 1–4)

- [ ] Project scaffolding, CI/CD (GitHub Actions)
- [ ] Custom event loop (epoll → Linux first)
- [ ] TUN device creation (Linux)
- [ ] UDP socket per interface with `SO_BINDTODEVICE`
- [ ] Wire protocol (header serialize/deserialize)
- [ ] Basic packet forwarding (single interface, no encryption)

### Phase 2 — Crypto & Bonding (Weeks 5–8)

- [ ] Noise IK handshake with X25519 (via `ring`)
- [ ] ChaCha20-Poly1305 tunnel encryption
- [ ] Session management & rekey
- [ ] Round-Robin bonding (multi-interface)
- [ ] Packet reordering buffer
- [ ] Link quality probing (RTT, loss)

### Phase 3 — Advanced Bonding & Failover (Weeks 9–12)

- [ ] Weighted scheduling
- [ ] Latency-Adaptive scheduling
- [ ] Redundant scheduling
- [ ] Interface failover & recovery
- [ ] PMTUD + DWP fragmentation
- [ ] Anti-replay sliding window

### Phase 4 — Server Mode (Weeks 13–16)

- [ ] Multi-client server with NAT/masquerade
- [ ] Client authentication (PSK, pubkey, TOTP, mTLS)
- [ ] Per-client bandwidth tracking
- [ ] Rate limiting & DoS protection
- [ ] Server CLI commands (clients, kick, stats)

### Phase 5 — P2P & NAT Traversal (Weeks 17–19)

- [ ] STUN client implementation
- [ ] UDP hole punching
- [ ] P2P tunnel establishment
- [ ] Relay fallback via Desmos server (if direct P2P fails, route through any available Desmos server as relay)

### Phase 6 — Cross-Platform (Weeks 20–24)

- [ ] macOS utun + kqueue event loop
- [ ] Windows Wintun + IOCP event loop
- [ ] FreeBSD /dev/tun + kqueue
- [ ] OpenWrt (cross-compile, LuCI app, UCI config, IPK)
- [ ] pfSense (pkg, rc.d)
- [ ] Privilege dropping per platform
- [ ] seccomp-bpf (Linux), pledge/unveil (FreeBSD)

### Phase 7 — Web UI & Polish (Weeks 25–28)

- [ ] Embedded HTTP server
- [ ] REST API
- [ ] WebSocket real-time stats
- [ ] React frontend dashboard (build pipeline + embed in binary)
- [ ] DNS leak protection (optional, route DNS through tunnel)
- [ ] Config hot-reload
- [ ] Comprehensive documentation
- [ ] Performance benchmarks & optimization

---

## 13. Testing Strategy

### 13.1 Unit Tests

- Wire protocol serialization/deserialization
- Bonding scheduler correctness (deterministic with mock interfaces)
- Reorder buffer (packet ordering, timeout, duplicates)
- Crypto round-trip (encrypt → decrypt)
- Config TOML parser

### 13.2 Integration Tests

- Full tunnel establishment (client ↔ server on localhost with veth pairs)
- Multi-interface bonding (Linux network namespaces with `tc netem`)
- Failover simulation (bring interface down mid-transfer)
- Handshake under packet loss/delay

### 13.3 Platform Tests (CI)

- Linux: GitHub Actions (native)
- macOS: GitHub Actions (native)
- Windows: GitHub Actions (native)
- FreeBSD: Cross-compiled, tested in Vagrant/QEMU
- OpenWrt: Cross-compiled, tested in QEMU

### 13.4 Performance Tests

- `iperf3` through tunnel with varying interface counts
- Bonding efficiency: actual throughput / sum of interface bandwidths
- Failover latency: time from interface down to traffic rerouted
- Crypto throughput: packets/sec at varying payload sizes

---

## 14. Packaging & Distribution

| Platform | Format | Distribution |
|----------|--------|-------------|
| Linux | `.tar.gz`, `.deb`, `.rpm`, AppImage | GitHub Releases, AUR |
| macOS | `.tar.gz`, Homebrew formula | GitHub Releases, `brew tap` |
| Windows | `.zip`, `.msi` (via WiX) | GitHub Releases, `winget` |
| FreeBSD | `.pkg` | GitHub Releases, FreeBSD ports (future) |
| OpenWrt | `.ipk` | GitHub Releases, custom opkg feed |
| pfSense | FreeBSD `.pkg` | GitHub Releases |

---

## 15. Comparison

| Feature | Desmos | Speedify | OpenMPTCProuter | WireGuard |
|---------|--------|----------|-----------------|-----------|
| Connection bonding | ✅ | ✅ | ✅ (MPTCP) | ❌ |
| Encryption | ChaCha20-Poly1305 | Proprietary | OpenVPN/WG | ChaCha20-Poly1305 |
| Open source | ✅ | ❌ | ✅ | ✅ |
| Single binary | ✅ | ❌ | ❌ | ✅ (kernel module) |
| P2P mode | ✅ | ❌ | ❌ | ✅ |
| Web UI | ✅ | ✅ (desktop app) | ✅ | ❌ |
| OpenWrt | ✅ | ❌ | ✅ | ✅ |
| pfSense | ✅ | ❌ | ❌ | ✅ |
| Windows | ✅ | ✅ | ❌ | ✅ |
| Minimal deps | ✅ (5 crates) | N/A | ❌ | ✅ (kernel) |
| Self-hosted | ✅ | ❌ (their servers) | ✅ | ✅ |

---

## 16. Future Considerations (Post-v1.0)

- **iOS / Android** clients (requires platform TUN APIs)
- **Full mesh mode** — multiple peers in a mesh network
- **Split tunneling** — route specific apps/IPs outside tunnel
- **Traffic shaping** — per-application bandwidth allocation
- **GUI desktop client** — native system tray app
- **Hosted relay infrastructure** — for users who can't self-host server
- **MPTCP support** — leverage kernel MPTCP where available as alternative transport
- **Plugin system** — custom bonding strategies, auth providers
