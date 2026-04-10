# Desmos — Specification

> Open-source, cross-platform connection bonding VPN that combines multiple network interfaces into a single, faster, and more reliable encrypted tunnel.

**Source:** Derived from `./prd.md` (read 2026-04-10). Engineering gaps filled via targeted elicitation on 2026-04-10 (workspace layout, toolchain policy, Web UI build strategy, CI scope).

---

## 1. Overview

### 1.1 What Is Desmos?

Desmos is a connection bonding VPN written in Rust. It aggregates 2 to 8 physical network interfaces — Ethernet, Wi-Fi, LTE/5G, secondary WAN — into a single logical tunnel that is simultaneously faster (throughput sums) and more reliable (any interface can fail without dropping the tunnel). It ships as a single static binary per platform with a hand-rolled async runtime, hand-rolled protocol, hand-rolled HTTP server, and exactly five external crates.

The name comes from the Greek δεσμός ("bond, link"), reflecting the core idea of binding independent connections together. Operating modes are Client-Server (primary: a client aggregates its interfaces and routes through a remote server) and P2P (two peers establish a direct bonded tunnel, with STUN-assisted NAT traversal and server-relay fallback).

Desmos targets system administrators, homelab operators, remote workers on unstable links, site-to-site network operators, and embedded router firmware users (OpenWrt, pfSense) who need deterministic, auditable, self-hosted bonding without the complexity of MPTCP kernel patches or the lock-in of proprietary SaaS products.

### 1.2 Target Audience

- **Remote workers on unreliable connectivity** (home Wi-Fi + LTE hotspot) who need a single stable tunnel that survives link failure.
- **Self-hosters and homelab operators** who want an open, auditable bonding VPN they fully control.
- **Small-office / branch-office admins** running pfSense or OpenWrt routers bonding two ISPs for WAN aggregation or failover.
- **Site-to-site network engineers** bonding leased lines with commodity broadband for cost-effective redundant links.
- **Security-conscious developers** who reject large dependency trees (tokio, hyper) in security-sensitive code and want a minimal, hand-written codebase they can fully audit.

### 1.3 Key Differentiators

- **Minimal dependency surface.** Exactly 5 external crates (`ring`, `blake3`, `socket2`, `wintun`, `argon2`). Everything else — async runtime, TOML parser, CLI parser, HTTP server, WebSocket, logging, JSON — is hand-rolled, making the codebase fully auditable.
- **Single static binary per platform.** Distribution with no runtime, interpreter, or shared library dependencies. Linux musl build target yields a glibc-free executable.
- **Six-platform support from day one.** Linux, macOS, Windows, FreeBSD, OpenWrt, pfSense — all in the same codebase via a platform-agnostic TUN trait and per-platform event loop backend (epoll/kqueue/IOCP).
- **Four pluggable bonding strategies.** Round-Robin, Weighted, Latency-Adaptive (default), and Redundant. Users pick the strategy that matches their link topology at runtime, hot-switchable via CLI or Web UI.
- **Sub-second failover.** Interface loss > 20% or RTT > 500ms for 5 consecutive probes triggers immediate redistribution to healthy interfaces, target < 1 second end-to-end.
- **Self-contained Web UI.** Vite-built React dashboard embedded in the binary at compile time via `include_dir!`, served by the hand-rolled HTTP server on localhost by default. No external web stack required at runtime.

### 1.4 Competitive Landscape

| Feature                      | Desmos                  | Speedify      | OpenMPTCProuter | WireGuard           |
|------------------------------|-------------------------|---------------|-----------------|---------------------|
| Connection bonding           | Yes                     | Yes           | Yes (MPTCP)     | No                  |
| Encryption                   | ChaCha20-Poly1305       | Proprietary   | OpenVPN / WG    | ChaCha20-Poly1305   |
| Open source                  | Yes (MIT)               | No            | Yes             | Yes                 |
| Single binary                | Yes                     | No            | No              | Yes (kernel module) |
| P2P mode                     | Yes                     | No            | No              | Yes                 |
| Embedded Web UI              | Yes                     | Desktop app   | Yes             | No                  |
| OpenWrt support              | Yes                     | No            | Yes             | Yes                 |
| pfSense support              | Yes                     | No            | No              | Yes                 |
| Windows client               | Yes                     | Yes           | No              | Yes                 |
| Minimal dependencies         | Yes (5 crates)          | N/A           | No              | Yes (in-kernel)     |
| Self-hosted server           | Yes                     | No (SaaS)     | Yes             | Yes                 |
| Multiple bonding strategies  | 4 strategies            | Adaptive only | MPTCP scheduler | N/A                 |

---

## 2. Core Concepts

| Concept                 | Definition                                                                                                                                |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| **Interface**           | A physical or logical network adapter on the host (e.g. `eth0`, `wlan0`, `wwan0`) that Desmos binds a dedicated UDP socket to.            |
| **Link**                | A logical UDP flow between one client-side interface and the server endpoint, identified by `(interface_id, session_id)`.                 |
| **Tunnel**              | The aggregate of all active links for a single session, presented to the OS as a TUN device (`desmos0`) carrying IP traffic.              |
| **Session**             | An authenticated, keyed relationship between two Desmos peers, surviving individual link failures and rekeys.                             |
| **Bonding Engine**      | The scheduler + reorder buffer + failover controller that decides how tunnel packets are distributed across links and reassembled.        |
| **Bonding Strategy**    | A named algorithm for distributing packets: Round-Robin, Weighted, Latency-Adaptive, or Redundant.                                        |
| **Link Score**          | A composite metric combining RTT, loss rate, jitter, and throughput used by Latency-Adaptive scheduling to weight link selection.         |
| **Link Quality Probe**  | A small DWP probe packet sent every 500ms per link to measure RTT, loss, and jitter.                                                      |
| **Reorder Window**      | The maximum time (default 50ms) the receiver buffers out-of-order packets before delivering the next in-order packet or marking it lost.  |
| **DWP**                 | Desmos Wire Protocol — the custom UDP-based packet format with 16-byte header, encrypted payload, and 128-bit auth tag.                   |
| **Handshake**           | The Noise IK exchange performed once per session to derive symmetric keys; X25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE3 hash.      |
| **Rekey**               | Periodic rotation of symmetric keys, triggered after 2³² packets or 120 seconds since last rekey, whichever is first.                     |
| **Degraded Interface**  | An interface with > 20% loss or > 500ms RTT for 5 consecutive probes; still used but weight reduced.                                      |
| **Dead Interface**      | An interface with no probe response for 3 seconds; traffic immediately redistributed and recovery delayed.                                |
| **Probation**           | A 10-second window a recovered interface spends at reduced weight before full reintegration, preventing flap amplification.               |
| **Session ID**          | A 16-bit identifier scoped per server, assigned during handshake, carried in every DWP header.                                            |
| **Interface ID**        | An 8-bit index identifying the source interface of a DWP packet, used for per-link statistics and duplicate suppression.                  |
| **Sequence Number**     | A 32-bit monotonic counter per session used by the reorder buffer and anti-replay sliding window.                                         |
| **Anti-Replay Window**  | A sliding bitmap tracking recently-seen sequence numbers; rejects duplicates and out-of-window old packets.                               |
| **Privilege Drop**      | The act of starting as root/admin to create the TUN device and bind sockets, then switching to the unprivileged `desmos:desmos` user.     |

---

## 3. Functional Requirements

### 3.1 Tunnel Lifecycle

#### 3.1.1 Client Tunnel Establishment

**User Story:** As a remote user, I want to start the Desmos client with my config file so that a bonded encrypted tunnel is brought up across all my interfaces.

**Description:** The client reads its config file, validates it, loads its static keypair, enumerates the configured interfaces, binds one UDP socket per interface, performs a Noise IK handshake with the server over the first healthy interface, then brings up the local TUN device and starts forwarding IP traffic.

**Acceptance Criteria:**
- [ ] `desmos up -c <path>` succeeds on a host with at least one healthy interface defined in the config.
- [ ] Handshake completes within 5 ms under local-network latency conditions.
- [ ] TUN device `desmos0` appears and accepts IP traffic after handshake.
- [ ] All enabled interfaces begin probing within 1 second of tunnel-up.
- [ ] Client returns non-zero exit code with a clear error if no configured interface is healthy.

**Edge Cases:**
- All configured interfaces are down at startup: retry with exponential backoff up to 60 s, then exit with error.
- Server rejects handshake (auth failure): surface "Authentication failed" and exit with code 2.
- Config file missing or unparseable: surface line number of error and exit with code 64.
- TUN device creation fails (missing privileges): surface platform-specific hint ("run with sudo" / "Administrator") and exit with code 77.

**Constraints:** Handshake must use 1-RTT (Noise IK). Client must not cache server public key — it is required in config.

#### 3.1.2 Server Tunnel Acceptance

**User Story:** As a VPN server operator, I want Desmos in server mode to accept multiple bonded clients simultaneously so that my users can share the server's uplink.

**Description:** Server binds one UDP listen socket on the configured address, accepts incoming Noise IK handshakes, authenticates the client via the configured method (PSK / pubkey / TOTP / mTLS), allocates a session, and begins multiplexing traffic to a single TUN device with NAT masquerade to the internet-facing interface.

**Acceptance Criteria:**
- [ ] Server accepts at least `max_clients` concurrent sessions without packet loss above 0.1%.
- [ ] Each client's traffic is correctly reassembled from arbitrary link combinations.
- [ ] Unauthenticated handshakes are rejected within 1 RTT without session allocation.
- [ ] Server enforces per-client rate limits configured in `desmos.toml`.
- [ ] NAT masquerade to the configured egress interface is active for all client traffic.

**Edge Cases:**
- `max_clients` reached: reject new handshakes with a typed DWP error and log the rejection.
- Client sends duplicate handshake under an existing session: treat as session reset, replace old session.
- Egress interface goes down: server continues accepting clients but returns a "degraded" status on the Web UI and REST API.
- Auth method misconfigured: startup fails with clear configuration error; server refuses to bind.

**Constraints:** Server must drop privileges after socket bind and TUN creation.

#### 3.1.3 Tunnel Teardown

**User Story:** As an operator, I want `desmos down` to cleanly tear down the tunnel so that no stale TUN devices, sockets, or firewall rules remain.

**Acceptance Criteria:**
- [ ] `desmos down` removes the TUN device.
- [ ] All UDP sockets are closed and bound ports released.
- [ ] Any NAT / masquerade rules installed on startup are removed.
- [ ] The server-side session is explicitly closed via a DWP Control(FIN) packet.
- [ ] Shutdown completes within 2 seconds of command invocation.

**Edge Cases:** If the server is unreachable, local teardown still completes within 2 seconds.

### 3.2 Bonding Engine

#### 3.2.1 Scheduler Selection

**User Story:** As an operator, I want to choose between four bonding strategies so that I can match the algorithm to my link topology.

**Acceptance Criteria:**
- [ ] The four strategies from §4.1 of the PRD are all implemented and selectable via config and CLI.
- [ ] `desmos bonding set-strategy <name>` hot-switches the active strategy without dropping the tunnel.
- [ ] The active strategy is reported by `desmos status` and the Web UI `/api/v1/bonding` endpoint.
- [ ] Weighted strategy honors per-interface `weight` from config.
- [ ] Latency-Adaptive weights are recomputed on every completed probe cycle.

**Edge Cases:**
- Strategy name unknown: CLI rejects with a list of valid options.
- Hot-switch during active bulk transfer: no packet loss allowed beyond transient reordering within the reorder window.

#### 3.2.2 Link Quality Probing

**User Story:** As the bonding engine, I need continuous link quality metrics so that scheduling decisions reflect current conditions.

**Acceptance Criteria:**
- [ ] A probe packet is sent per enabled interface every `probe_interval` (default 500 ms).
- [ ] Per-interface RTT, loss rate, jitter, and throughput are exposed via REST and CLI `status`.
- [ ] Link score = `w1 * (1/RTT_avg) + w2 * (1 - loss_rate) + w3 * (1/jitter) + w4 * throughput` with configurable weights `w1..w4`.
- [ ] Rolling window for loss and jitter is the last 100 packets per interface.

**Edge Cases:**
- Probe response lost: counted as loss in the rolling window; RTT unchanged.
- Clock skew between peers: timestamps are peer-relative (client includes its send time, peer echoes it).

#### 3.2.3 Packet Reordering

**User Story:** As a receiver, I need out-of-order packets from different links reassembled in sequence so that upstream IP traffic looks coherent.

**Acceptance Criteria:**
- [ ] The reorder buffer holds packets for up to `reorder_window_ms` (default 50 ms).
- [ ] In-order packets are delivered immediately with zero additional latency.
- [ ] Gap-hole packets are delivered as soon as the missing sequence arrives or the window expires.
- [ ] Duplicate packets (same `session_id + sequence`) are dropped; the interface that already delivered the copy is preferred.
- [ ] 99th-percentile added latency from reordering is < 1 ms under normal conditions.

**Edge Cases:**
- Sequence wraparound at 2³²: handled by sliding window comparison (`seq_gt` modular arithmetic).
- Window-exhausted gaps: the missing sequence is skipped and counted as a loss.

#### 3.2.4 Failover and Recovery

**User Story:** As a user mid-transfer, I want an interface failure to not drop my tunnel so that my work continues uninterrupted.

**Acceptance Criteria:**
- [ ] An interface with > 20% loss OR > 500 ms RTT for 5 consecutive probes is marked `degraded`.
- [ ] An interface with no probe response for 3 seconds is marked `dead`; traffic is redistributed within 1 second.
- [ ] A recovered interface enters `probation` at reduced weight for 10 seconds before full reintegration.
- [ ] Tunnel-level throughput drop during a single-interface failover does not exceed the removed link's share.

**Edge Cases:**
- All interfaces dead simultaneously: tunnel stays up in a "disconnected" state for up to 60 seconds awaiting recovery before shutting down.
- Rapid flap: probation prevents re-degradation cascades.

### 3.3 Authentication Methods

#### 3.3.1 Pre-Shared Key (PSK)

**Acceptance Criteria:**
- [ ] Server and client share a `psk` string in config.
- [ ] PSK is mixed into the Noise IK handshake via the `psk` modifier.
- [ ] PSK failure produces a single DWP error and session is not allocated.

#### 3.3.2 Public Key (pubkey)

**Acceptance Criteria:**
- [ ] Server maintains an authorized-key list in `/etc/desmos/authorized_keys`.
- [ ] Client's static public key is verified against the list during handshake.
- [ ] Unauthorized key produces a DWP auth error.

#### 3.3.3 TOTP

**Acceptance Criteria:**
- [ ] Server accepts a 6-digit TOTP code passed as part of the handshake payload.
- [ ] Code window is ±1 period (default 30 s).
- [ ] Replay within the same period is rejected.

#### 3.3.4 mTLS

**Acceptance Criteria:**
- [ ] Server validates client certificate against the configured CA during a pre-DWP TLS layer on the handshake socket.
- [ ] Certificate CN is mapped to a session identity.
- [ ] Revoked or expired certificates are rejected.

### 3.4 CLI Management

#### 3.4.1 Subcommand Surface

The CLI provides the following subcommands (see PRD §6.2 for full spec):

- `up`, `down`, `status`, `interfaces`, `keygen`, `config`, `webui`
- Client: `bonding set-strategy`, `bonding enable`, `bonding disable`, `interfaces --monitor`
- Server: `clients`, `clients kick`, `stats`

**Acceptance Criteria:**
- [ ] Every subcommand supports `--json` output for machine consumption.
- [ ] `--help` on any subcommand returns a focused usage block, not the global help.
- [ ] Unknown subcommands return exit code 64 and a suggestion for the closest match.
- [ ] Global flags `-c/--config`, `-v/--verbose`, `-q/--quiet`, `--no-color` work everywhere.

### 3.5 Web UI

#### 3.5.1 Dashboard

**User Story:** As an operator, I want a live dashboard so that I can see tunnel health at a glance.

**Acceptance Criteria:**
- [ ] Live throughput graph updates at ≥ 1 Hz via WebSocket.
- [ ] Per-interface bandwidth bars show rx/tx in bytes per second.
- [ ] Tunnel status badge reflects one of: `up`, `degraded`, `down`, `connecting`.
- [ ] Dashboard loads within 200 ms on localhost.

#### 3.5.2 Interface Management

**Acceptance Criteria:**
- [ ] Each interface row shows name, state, RTT, loss, jitter, enable/disable toggle.
- [ ] Toggling an interface applies within 500 ms and reflects in `status`.
- [ ] Interface stats update at ≥ 2 Hz via WebSocket.

#### 3.5.3 Bonding Configuration

**Acceptance Criteria:**
- [ ] Strategy dropdown lets the user hot-switch between the four strategies.
- [ ] Weight sliders for Weighted strategy apply within 500 ms.
- [ ] Reorder buffer statistics (current depth, drops, max latency) are shown live.

#### 3.5.4 Server Client Page

**Acceptance Criteria:**
- [ ] (Server mode only) Table of connected clients with session ID, auth identity, bandwidth.
- [ ] "Kick" button disconnects a client via `DELETE /api/v1/clients/:session_id`.
- [ ] New client connections appear within 1 second.

#### 3.5.5 Logs Page

**Acceptance Criteria:**
- [ ] Live log stream via WebSocket with level filter (trace / debug / info / warn / error).
- [ ] Buffer of last 500 lines is retained server-side for replay on page load.

#### 3.5.6 Settings Page

**Acceptance Criteria:**
- [ ] Config editor validates TOML before accepting `PUT /api/v1/config`.
- [ ] `PUT /api/v1/config` hot-reloads the running instance without dropping the tunnel where possible.
- [ ] Keypair management page lets the user generate or regenerate keys.

### 3.6 P2P Mode

#### 3.6.1 STUN-Assisted Direct Tunnel

**User Story:** As two remote peers, we want a direct encrypted bonded tunnel without a central server so that our site-to-site traffic stays private and low-latency.

**Acceptance Criteria:**
- [ ] Each peer resolves its public address via STUN to the configured STUN servers.
- [ ] Peers exchange candidates through a rendezvous mechanism (out-of-band in v1.0: user copy-paste of the `peer_endpoint` in config).
- [ ] UDP hole punching establishes a direct link over each interface pair.
- [ ] Once a direct link is established, the standard bonding engine takes over.

**Edge Cases:** If hole punching fails on all interfaces, fall back to relaying through any reachable Desmos server acting as a relay (`[p2p].relay_servers` list).

---

## 4. Architecture Overview

### 4.1 System Components

| Component            | Responsibility                                                                                                                |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Runtime**          | Per-platform event loop backend (epoll / kqueue / IOCP) wrapping UDP sockets, TUN fds/handles, timers, and WebSocket sockets. |
| **TUN**              | Platform-agnostic TUN device trait with Linux, macOS, Windows, FreeBSD, and OpenWrt backends.                                 |
| **Net**              | Interface discovery and monitoring, per-interface UDP socket creation with binding, STUN client, minimal DNS resolver.        |
| **Crypto**           | Noise IK state machine, ChaCha20-Poly1305 AEAD wrapper, X25519 key exchange, BLAKE3 hashing and HKDF.                         |
| **Protocol**         | DWP wire format encoding/decoding, session lifecycle, keepalive, rekey scheduling, anti-replay window.                        |
| **Bonding Engine**   | Scheduler implementations, packet reorder buffer, link quality probe processor, failover controller.                          |
| **Server**           | Multi-client listener, per-session state, NAT/masquerade configuration, rate limiting, client authentication backends.       |
| **Web UI Backend**   | Hand-rolled HTTP/1.1 server, hand-rolled WebSocket upgrade, REST endpoint dispatcher, stats and log broadcasters.             |
| **Web UI Frontend**  | Vite-built React SPA, embedded in binary via `include_dir!`, served from `/` and `/static/*`.                                 |
| **CLI**              | Hand-rolled argument parser, subcommand dispatcher, JSON output formatter, IPC to a running daemon via the Web UI REST API.   |
| **Config**           | Hand-rolled TOML subset parser, schema validation, hot-reload dispatcher.                                                     |
| **Logging**          | Hand-rolled structured logger with level filtering and ring buffer for Web UI streaming.                                      |

### 4.2 Component Interactions

```
+------------+    +-----+    +-----+    +----------+    +-----+    +----------+
|   Network  | -> | Net | -> | TUN | -> | Protocol | -> | CLI | <- | Operator |
| Interfaces |    +-----+    +-----+    +----------+    +-----+    +----------+
+------------+       |          |            |              ^
                     v          v            v              |
                  +----------------------------+            |
                  |      Runtime (event loop) |            |
                  +----------------------------+            |
                           ^                                |
                           |                                |
                  +----------------+                        |
                  | Bonding Engine |                        |
                  +----------------+                        |
                           ^                                |
                           |                                |
                    +------+------+                         |
                    |   Crypto    |                         |
                    +-------------+                         |
                                                            |
                  +----------------+    +------------+      |
                  |  Web UI HTTP   | <->| Web UI SPA | <----+
                  +----------------+    +------------+
```

Synchronous control flow (config load, CLI dispatch, teardown) runs on the main thread. Data-plane flow (TUN read, crypto, schedule, UDP write) runs on dedicated worker threads communicating via lock-free ring buffers. The Web UI HTTP server runs on its own thread and reads shared metrics via atomics and snapshot copies.

### 4.3 External Integrations

| Integration           | Purpose                                                                                     | Fallback                                        |
|-----------------------|---------------------------------------------------------------------------------------------|-------------------------------------------------|
| **STUN servers**      | Public-address discovery for P2P hole punching.                                             | Desmos relay-server chain from config.          |
| **Wintun driver**     | Windows TUN device abstraction provided by the `wintun.dll` runtime.                        | None — Wintun is required on Windows.           |
| **UCI (OpenWrt)**     | System config integration for LuCI package (`/etc/config/desmos`).                         | Plain `desmos.toml` file if UCI not available.  |
| **pfSense pkg GUI**   | Package XML manifest integration for pfSense web GUI.                                       | Plain CLI usage on FreeBSD base.                |

---

## 5. Data Model

Desmos does not persist user-facing business data — there is no database. The data model covers in-memory runtime entities and on-disk configuration/key material.

### 5.1 Configuration Entities

#### ClientConfig

| Field                  | Type            | Required | Description                                      | Constraints                                |
|------------------------|-----------------|----------|--------------------------------------------------|--------------------------------------------|
| `server`               | string          | Yes      | Host:port of the Desmos server                   | Valid resolvable endpoint                  |
| `server_public_key`    | string (base64) | Yes      | Server static public key (X25519)                | 32 bytes decoded                           |
| `private_key_file`     | path            | Yes      | Path to client static private key                | File readable by daemon user               |
| `bonding_strategy`     | enum            | Yes      | `round-robin` / `weighted` / `latency-adaptive` / `redundant` | Default `latency-adaptive`       |
| `reorder_window_ms`    | u32             | No       | Maximum reorder buffer age                       | 1..1000, default 50                        |
| `dns_leak_protection`  | bool            | No       | Route DNS through tunnel                         | Default true                               |
| `dns_servers`          | [IP]            | No       | Upstream DNS servers when leak protection is on  | ≤ 4 entries                                |
| `interfaces`           | [Interface]     | Yes      | Network interfaces to bond                       | 1..8 entries                               |

#### Interface (config)

| Field     | Type    | Required | Description                   | Constraints                |
|-----------|---------|----------|-------------------------------|----------------------------|
| `name`    | string  | Yes      | OS interface name (`eth0`)    | Must exist at `up` time    |
| `weight`  | u16     | No       | Weight for weighted strategy  | 1..1000, default 100       |
| `enabled` | bool    | No       | Start enabled                 | Default true               |

#### ServerConfig

| Field               | Type            | Required | Description                     | Constraints                  |
|---------------------|-----------------|----------|---------------------------------|------------------------------|
| `listen`            | string          | Yes      | `host:port` UDP bind address    | Valid socket addr            |
| `public_key`        | string (base64) | Yes      | Advertised static public key    | 32 bytes decoded             |
| `private_key_file`  | path            | Yes      | Matching private key file       | File readable at startup     |
| `max_clients`       | u32             | No       | Concurrent session cap          | Default 100                  |
| `auth`              | AuthConfig      | Yes      | Authentication method + params  | See §3.3                     |

### 5.2 Runtime Entities

#### Session

| Field                | Type          | Description                                                         |
|----------------------|---------------|---------------------------------------------------------------------|
| `id`                 | u16           | 16-bit session identifier                                           |
| `peer_static`        | [u8; 32]      | Peer's static X25519 public key                                     |
| `send_key`           | [u8; 32]      | Current symmetric encryption key (rotated on rekey)                 |
| `recv_key`           | [u8; 32]      | Current symmetric decryption key                                    |
| `send_counter`       | u64           | Per-session send counter (nonce source)                             |
| `last_rekey`         | Instant       | Timestamp of last rekey                                             |
| `anti_replay_window` | SlidingBitmap | Sliding bitmap tracking recently-received sequence numbers          |
| `reorder_buffer`     | ReorderBuffer | Out-of-order packet staging area                                    |

#### Link

| Field            | Type                  | Description                                                      |
|------------------|-----------------------|------------------------------------------------------------------|
| `interface_id`   | u8                    | Local interface index                                            |
| `interface_name` | string                | Display name                                                     |
| `socket`         | UdpSocket             | Per-interface UDP socket                                         |
| `state`          | enum                  | `healthy` / `probation` / `degraded` / `dead`                    |
| `rtt_ewma_us`    | u32                   | Exponentially weighted moving average RTT                        |
| `loss_rate`      | f32                   | Rolling loss rate over last 100 packets                          |
| `jitter_us`      | u32                   | Stdev of RTT over rolling window                                 |
| `throughput_bps` | u64                   | Rolling throughput estimate                                      |
| `last_probe_at`  | Instant               | Last probe send time                                             |
| `last_resp_at`   | Instant               | Last probe response time                                         |
| `weight`         | u16                   | Effective scheduling weight                                      |

### 5.3 Data Lifecycle

- **Keys**: long-term static keypairs are generated via `desmos keygen`, stored as raw 32-byte files with `0600` permissions, loaded at startup, and never transmitted in plaintext.
- **Sessions**: created on successful handshake, destroyed on explicit FIN, 60-second dead-peer timeout, or `desmos clients kick`.
- **Link metrics**: kept in-memory only. Persisted to the log ring buffer but never to disk.
- **Config**: loaded on startup, re-validated on `PUT /api/v1/config`, applied via a snapshot swap; old config is discarded after the new one is committed.
- **Logs**: held in a bounded in-memory ring buffer (default 500 lines) plus optional write-through to a file configured in `[log]`.

---

## 6. API Surface

### 6.1 API Style

REST over HTTP/1.1 with JSON bodies for control operations. WebSocket for real-time stats and log streams. The API is served by the embedded Web UI HTTP server bound to `127.0.0.1:8080` by default.

### 6.2 Endpoint Overview

| Method | Path                             | Description                              | Auth     |
|--------|----------------------------------|------------------------------------------|----------|
| GET    | `/api/v1/status`                 | Tunnel status snapshot                   | Required |
| GET    | `/api/v1/interfaces`             | Interface list with live metrics         | Required |
| PUT    | `/api/v1/interfaces/:name`       | Enable / disable / reweight an interface | Required |
| GET    | `/api/v1/bonding`                | Current strategy + bonding metrics       | Required |
| PUT    | `/api/v1/bonding/strategy`       | Hot-switch active bonding strategy       | Required |
| GET    | `/api/v1/stats`                  | Throughput / packet / error counters (JSON by default; Prometheus text format when `Accept: text/plain; version=0.0.4` or `?format=prometheus`) | Required |
| GET    | `/api/v1/clients`                | (Server) Connected clients table         | Required |
| DELETE | `/api/v1/clients/:session_id`    | (Server) Kick a client                   | Required |
| GET    | `/api/v1/config`                 | Current config (secrets redacted)        | Required |
| PUT    | `/api/v1/config`                 | Update config with hot-reload            | Required |
| GET    | `/api/v1/logs?level=info&n=100`  | Recent log entries                       | Required |
| WS     | `/api/v1/ws/stats`               | Real-time metrics stream                 | Required |
| WS     | `/api/v1/ws/logs`                | Real-time log stream                     | Required |
| GET    | `/`                              | Web UI SPA entry point                   | Required |
| GET    | `/static/*`                      | Web UI static assets                     | Required |

### 6.3 Authentication & Authorization

- Web UI bound to `127.0.0.1` by default. Binding to a public address requires explicit configuration and triggers a warning at startup.
- HTTP basic auth with username + Argon2-hashed password from `[webui]` config section, credentials transmitted over localhost only.
- All `/api/v1/*` endpoints require authentication except a single `GET /api/v1/health` unauthenticated liveness probe.
- No user roles in v1.0: a successful auth grants full read/write to all endpoints (single-operator model).

### 6.4 Rate Limiting

- The Web UI applies a soft per-source limit of 100 requests per 10 seconds; exceeding returns `429 Too Many Requests`.
- Server-side DWP handshake endpoint enforces a 5-handshakes-per-10-seconds-per-source-IP limit with cookie-based anti-amplification.

### 6.5 Error Format

```json
{
  "error": {
    "code": "MACHINE_READABLE_CODE",
    "message": "Human-readable explanation",
    "details": {}
  }
}
```

Standard codes: `unauthorized`, `forbidden`, `not_found`, `rate_limited`, `invalid_config`, `interface_not_found`, `session_not_found`, `internal_error`.

---

## 7. User Interface

### 7.1 Interface Type

Two first-class surfaces: a terminal CLI (primary for automation and headless deployments) and an embedded Web UI (primary for visual monitoring and one-off operations).

### 7.2 Key Screens (Web UI)

- **Dashboard** — Live throughput graph, per-interface bandwidth bars, tunnel status badge. Actions: none (read-only overview).
- **Interfaces** — Table of interfaces with RTT/loss/jitter/throughput and enable/disable toggle. Actions: toggle, reweight.
- **Bonding** — Strategy dropdown, weight sliders, reorder buffer live stats. Actions: strategy switch, weight update.
- **Connections** (server mode only) — Table of connected clients with kick action. Actions: kick.
- **Logs** — Live log stream with level filter. Actions: filter, pause, clear buffer view.
- **Settings** — Config editor (TOML), keypair management, auth settings. Actions: save config, regenerate keys, change password.

### 7.3 Responsive Requirements

- Desktop-first. Minimum supported viewport: 1024 × 768.
- Mobile: readable and usable at 375 px width, collapsed navigation; not a primary target.
- Accessibility: WCAG 2.1 AA where practical (keyboard navigation, ARIA labels for live regions, no color-only indicators).
- Dark mode default, light mode available via toggle.

---

## 8. Security Model

### 8.1 Authentication

- **Tunnel peers** authenticate via one of PSK, pubkey, TOTP, or mTLS during the Noise IK handshake (see §3.3).
- **Web UI operators** authenticate via HTTP basic auth with Argon2id password hashing.
- Session cookies for the Web UI are not used in v1.0; every request carries basic auth headers over localhost.

### 8.2 Authorization

- **Tunnel layer**: a successful handshake grants full routing through the tunnel. No per-packet authorization.
- **Web UI layer**: single-operator model; successful auth grants full access to all endpoints.
- **Server multi-tenant note**: each client has an isolated session; no client can observe another client's traffic or metrics.

### 8.3 Data Protection

- **In transit**: all DWP data packets are encrypted with ChaCha20-Poly1305 AEAD. Handshake uses Noise IK with X25519.
- **At rest**: static private keys stored as raw 32-byte files with `0600` permissions (root-owned). Web UI password hashed with Argon2id.
- **Perfect forward secrecy**: ephemeral keys in handshake, periodic rekey after 2³² packets or 120 seconds.
- **Anti-replay**: 128-bit sliding window per session, indexed by DWP sequence number.

### 8.4 Input Validation

- TOML config is fully validated on load and on hot-reload; invalid configs are rejected without affecting the running instance.
- REST endpoints validate payload shape before mutation; malformed input returns `400 Bad Request` with the standard error format.
- DWP packets with malformed headers, unknown versions, unknown types, or failed AEAD are silently dropped and counted in error metrics.

---

## 9. Deployment Model

### 9.1 Target Environments

- **Linux** (servers, desktops, SBCs) — glibc and musl static builds.
- **macOS** (Intel + Apple Silicon) — `.pkg` and Homebrew.
- **Windows 10+** — `.msi` installer, requires Wintun driver bundled. Runs as a **Windows Service** under `LocalSystem`, auto-started at boot.
- **FreeBSD 13+** and **pfSense** — pkg.
- **OpenWrt 22.03+** (x86_64, ARM64, ARM, MIPS, MIPS LE) — ipk package with LuCI integration.

### 9.2 Distribution Method

- **Primary**: single static binary per `(os, arch)` target downloaded from GitHub Releases.
- **Secondary**: platform package managers — Homebrew tap, AUR, `winget`, opkg feed, pfSense pkg, FreeBSD ports (post-v1.0).
- **Tertiary**: Docker image for the server role (Linux only) published to GHCR.

### 9.3 Configuration

- Primary: TOML file at `/etc/desmos/desmos.toml` (Linux/BSD), `C:\ProgramData\desmos\desmos.toml` (Windows), `~/Library/Preferences/desmos/desmos.toml` (macOS user installs).
- CLI global flag `-c/--config <path>` overrides the default location.
- Hot-reload via `PUT /api/v1/config` or `SIGHUP` signal (Unix only).
- Platform-specific integration layers: UCI (`/etc/config/desmos`) on OpenWrt, pfSense package XML on pfSense.

### 9.4 System Requirements

| Resource  | Minimum                                                              |
|-----------|----------------------------------------------------------------------|
| CPU       | Any 64-bit ARM or x86; MIPS for OpenWrt Tier 2 targets               |
| RAM       | 32 MB for client, 256 MB for server with 100 clients                 |
| Disk      | 10 MB for the binary; 50 MB for logs and transient state             |
| Kernel    | Linux 4.9+, macOS 11+, Windows 10+, FreeBSD 13+, OpenWrt 22.03+      |
| Drivers   | `CAP_NET_ADMIN` on Linux, `wintun.dll` on Windows, admin on macOS/BSD|

---

## 10. Performance Requirements

### 10.1 Response Time Targets

| Operation                      | Target    |
|--------------------------------|-----------|
| Handshake completion           | < 5 ms (1 RTT)                           |
| Failover (interface down)      | < 1 s from dead detection to redistribution |
| Reorder-buffer added latency   | < 1 ms p99 under normal conditions       |
| Web UI dashboard load          | < 200 ms on localhost                    |
| Hot-switch bonding strategy    | < 500 ms                                 |

### 10.2 Throughput Targets

| Metric                               | Target                 |
|--------------------------------------|------------------------|
| Single-core tunnel throughput        | ≥ 2 Gbps               |
| Bonding overhead vs raw aggregate    | < 3%                   |
| Concurrent server clients            | 100 with default tuning; 1000 with raised `max_clients` |

### 10.3 Resource Limits

| Resource                     | Budget                           |
|------------------------------|----------------------------------|
| Client RSS (3 interfaces)    | < 20 MB steady-state             |
| Server RSS (100 clients)     | < 200 MB steady-state            |
| Binary size (stripped)       | < 5 MB Linux x86_64 musl         |
| CPU overhead per 1 Gbps      | < 15% single core on x86_64 with SIMD |

---

## 11. Constraints & Non-Goals

### 11.1 Technical Constraints

- Language: Rust (Edition 2021, MSRV pinned via `rust-toolchain.toml`).
- Exactly 5 external crates: `ring`, `blake3`, `socket2`, `wintun`, `argon2`. No additional dependencies may be added without removing one.
- No `tokio`, `async-std`, `hyper`, `reqwest`, `clap`, `serde`, `serde_json`, `toml`, `log`, `tracing`, or similar. Everything not in the approved list is hand-rolled.
- Single static binary per platform; no runtime dependencies beyond `wintun.dll` on Windows.
- Client must drop privileges after socket bind and TUN creation.
- Platform-specific sandboxing: seccomp-bpf on Linux, pledge/unveil on FreeBSD, sandbox profile on macOS.
- **v1.0 is IPv4-only** at the tunnel transport layer; internal types must remain address-family-agnostic so v1.1 can add IPv6 without a breaking change.

### 11.2 Non-Goals

- **iOS and Android clients** — future version; platform TUN APIs differ significantly.
- **Full mesh VPN** (Tailscale / Nebula style) — v1.0 is strictly single-tunnel client-server or pairwise P2P.
- **Hosted public relay infrastructure** — relay fallback uses any Desmos server the operator runs, not a company-managed relay.
- **WireGuard or OpenVPN protocol compatibility** — DWP is a distinct, incompatible wire protocol.
- **MPTCP kernel support** — application-level bonding only in v1.0.
- **Split tunneling** — all OS traffic goes through the TUN; per-app/per-IP exclusion is v1.1+.
- **Traffic shaping per application** — v1.1+.
- **GUI desktop system-tray client** — Web UI is the only visual management in v1.0.
- **Multi-user RBAC on the Web UI** — single-operator model in v1.0.
- **Built-in certificate authority** — mTLS assumes an externally-managed CA.
- **IPv6 tunnel transport** — v1.0 underlay is IPv4-only; IPv6 (dual-stack and IPv6-only) lands in v1.1. Traffic carried *inside* the tunnel may still be IPv4 or IPv6 since the TUN device is L3-agnostic.
- **OS keyring integration for secrets** — v1.0 uses plaintext `0600` key files; OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) lands in v1.1.

### 11.3 Assumptions

- The operator has access to a server with a public IP (client-server mode) or STUN-reachable public address (P2P mode).
- All peers run matching major versions; cross-version negotiation is minimal (version field enforces equality in v1.0).
- Operators can generate keypairs and distribute server public keys out-of-band.
- Wintun driver is present or installable on Windows hosts.
- The operating system supports non-blocking UDP sockets on IPv4 (IPv6 underlay is v1.1).

### 11.4 Resolved Decisions (formerly TBD, resolved 2026-04-10)

- **IPv6 support**: v1.0 is **IPv4-only**. Full IPv6 (dual-stack and IPv6-only) is deferred to v1.1. Sockets, config parsing, and wire format must still be IPv6-ready (no hard-coded `sockaddr_in`) to keep the v1.1 addition non-breaking.
- **Windows daemon model**: v1.0 ships as a **Windows Service** (boot-time) installed by the MSI. No user-session-only mode. The service runs under `LocalSystem` for TUN and socket privileges.
- **Config secrets at rest**: v1.0 stores PSK and static private keys as **plaintext files with `0600` permissions, root-owned**. OS keyring integration (macOS Keychain, Windows Credential Manager, Linux Secret Service) is deferred to v1.1.
- **Prometheus metrics**: `/api/v1/stats` is **dual-format** — returns JSON by default and Prometheus text format when the request sends `Accept: text/plain; version=0.0.4` or a `?format=prometheus` query parameter. No separate endpoint, no new dependencies.

---

## 12. Future Considerations

- **v1.1** — iOS and Android clients via per-platform TUN APIs; full mesh mode with multiple peers; split tunneling for per-app routing; full IPv6 support (dual-stack and IPv6-only); OS keyring integration for secrets at rest.
- **v1.2** — Traffic shaping and per-application bandwidth allocation; native GUI desktop client with system tray; hosted relay directory (opt-in).
- **v2.0** — MPTCP transport backend where kernel support exists, used as an alternative underlay to UDP bonding; plugin system for custom bonding strategies and auth backends.
