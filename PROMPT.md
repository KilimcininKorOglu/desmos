# Desmos — Claude Code Implementation Prompt

> **Read this entire file before taking any action.** Then read the four companion documents at the CWD root — `SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`, `BRANDING.md` — and keep them open as the source of truth. This prompt is the orchestrator; those documents supply the exhaustive detail. Do not invent decisions that are already made in them, and do not silently deviate from any decision they state. If you find a contradiction between this prompt and one of those documents, pause and flag it explicitly to the user.

---

## 1. Project Overview

Desmos is an open-source connection bonding VPN written in Rust. It combines Wi-Fi, Ethernet, LTE, and any other network interface into a single encrypted tunnel that is simultaneously faster and more reliable than any link alone. It ships as a single static binary on Linux, macOS, Windows, FreeBSD, OpenWrt, and pfSense. Operating modes are Client-Server (primary) and P2P (STUN-assisted with server-relay fallback). The codebase is hand-rolled except for **exactly five** runtime crates: `ring`, `blake3`, `socket2`, `wintun`, `argon2`.

The name comes from the Greek δεσμός ("bond"). License is MIT. Author is KilimcininKorOglu. Full requirements are in `SPECIFICATION.md`; full technical blueprint in `IMPLEMENTATION.md`; ordered tasks in `TASKS.md`; identity in `BRANDING.md`.

---

## 2. Absolute Constraints (Non-Negotiable)

These constraints override any other instinct you have about "best practices" or "the Rust ecosystem standard". They are the product.

1. **Exactly 5 runtime crates:** `ring`, `blake3`, `socket2`, `wintun` (Windows only), `argon2`. Nothing else. No `tokio`, `async-std`, `hyper`, `reqwest`, `clap`, `serde`, `serde_json`, `toml`, `log`, `tracing`, `rustls`, `anyhow`, `thiserror`, `tower`, `axum`, `warp`, `mio`, `async-trait`, `once_cell`, `parking_lot`, `crossbeam`, `arc-swap`, `zeroize`, `base64`, `hex`, `num`, `libc` (use `std::os::raw` or declare syscall numbers locally), or any transitive addition. Dev-dependencies allowed: `proptest`, `criterion`, `insta` — these never land in release artifacts.
2. **Cargo workspace with 7 crates:** `desmos-proto`, `desmos-rt`, `desmos-core`, `desmos-http`, `desmos-webui`, `desmos-cli`, `desmos`. See §4 for the dependency DAG.
3. **Edition 2021, MSRV 1.75.0**, pinned via `rust-toolchain.toml`. No nightly features.
4. **Hand-rolled everything else:** async runtime (epoll/kqueue/IOCP), TOML parser, CLI parser, HTTP server, WebSocket, JSON codec, logger, timer wheel, ring buffers.
5. **Single static binary per platform.** musl for Linux to eliminate glibc. Runtime dependencies: only `wintun.dll` on Windows.
6. **6 platforms, not 1:** Linux, macOS, Windows, FreeBSD, OpenWrt, pfSense. Platform-specific code lives only inside `desmos-rt` behind trait objects.
7. **IPv4-only transport in v1.0.** All types must remain address-family-agnostic so v1.1 can add IPv6 non-breaking.
8. **Windows Service model.** The Windows distribution installs as a Windows Service running under `LocalSystem`, not a user-session daemon.
9. **Config secrets at rest:** plaintext 0600 files, root-owned. No OS keyring integration in v1.0.
10. **Prometheus stats as a dual-format endpoint**, not a separate route.
11. **Privilege drop after TUN and socket init.** Enforced by a typestate `Privileged` → `Unprivileged`.
12. **Typestate for session lifecycle:** `Session<Handshaking|Established|Rekeying|Closed>`. `encrypt_data` is only callable on `&Session<Established>`.
13. **Never** add any of these files to git under any circumstance: `AGENTS.md`, `CLAUDE.md`, `BUG-REPORT.md`, `.cursorrules`, `SKILL.md`, `GEMINI.md`. They are on a global gitignore and must stay off the project gitignore. Do not rename them.
14. **camelCase** for JS/TS identifiers in the Web UI. **snake_case** for Rust identifiers (standard Rust convention).

---

## 3. Tech Stack

| Layer              | Technology                  | Version                       |
|--------------------|-----------------------------|-------------------------------|
| Language           | Rust                        | Edition 2021, MSRV 1.75.0     |
| Workspace          | Cargo workspace (7 crates)  | Cargo 1.75+                   |
| Crypto             | `ring`                      | 0.17                          |
| Hash               | `blake3`                    | 1.5                           |
| Socket options     | `socket2`                   | 0.5                           |
| Windows TUN        | `wintun`                    | 0.5                           |
| Password hashing   | `argon2`                    | 0.5                           |
| Async runtime      | hand-rolled (`desmos-rt`)   | in-tree                       |
| HTTP / WebSocket   | hand-rolled (`desmos-http`) | in-tree                       |
| Frontend framework | React                       | 18.3                          |
| Frontend tooling   | Vite                        | 5.4                           |
| Frontend language  | TypeScript                  | 5.5                           |
| Frontend linting   | ESLint + @typescript-eslint | 9.x                           |
| Linting (Rust)     | `cargo clippy -- -D warnings` | toolchain-bundled           |
| Formatting         | `cargo fmt`                 | toolchain-bundled             |
| Testing (Rust)     | `cargo test` + `proptest` 1.5 + `criterion` 0.5 + `insta` 1.40 | dev-dependencies |
| CI/CD              | GitHub Actions              | —                             |
| Container          | Distroless Debian (server)  | latest                        |

---

## 4. Working Directory and Project Layout

**Working directory:** CWD is the project root. **Do NOT create a `desmos/` wrapper subfolder. Do NOT `cd` into a subfolder before scaffolding.** All paths below are relative to CWD.

**Planning docs already at CWD root — leave them untouched:** `SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`, `BRANDING.md`, `PROMPT.md`, `prd.md`.

The full directory tree is specified in `IMPLEMENTATION.md §3.1`. Consult it once before Task 1 and keep the shape consistent as you create files. Summary of top-level layout:

```
.
├── Cargo.toml                      # workspace manifest
├── Cargo.lock                      # committed
├── rust-toolchain.toml             # pinned 1.75.0
├── rustfmt.toml
├── clippy.toml
├── deny.toml                       # 5-crate allow-list
├── .gitignore
├── LICENSE                         # MIT
├── README.md
├── CHANGELOG.md
├── SPECIFICATION.md                # source of truth
├── IMPLEMENTATION.md               # source of truth
├── TASKS.md                        # ordered work
├── BRANDING.md                     # identity
├── PROMPT.md                       # this file
├── prd.md                          # original PRD
├── crates/
│   ├── desmos-proto/               # wire format, crypto, handshake — no I/O
│   ├── desmos-rt/                  # event loop, TUN, sockets, timer, ring
│   ├── desmos-core/                # bonding, session, config, log, server, p2p, auth
│   ├── desmos-http/                # HTTP/1.1, WebSocket, JSON, Basic Auth
│   ├── desmos-webui/               # REST handlers + embedded React SPA
│   ├── desmos-cli/                 # CLI parser + subcommand dispatcher
│   └── desmos/                     # binary crate — wires everything
├── packaging/
│   ├── linux/{debian,rpm,appimage,systemd}
│   ├── macos/{homebrew,pkg}
│   ├── windows/{wix,service}
│   ├── freebsd/pkg
│   ├── pfsense
│   └── openwrt/{Makefile,files,luci}
├── config/
│   └── desmos.toml.example
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   ├── cli.md
│   ├── webui.md
│   └── adr/
├── tests/
│   ├── e2e/
│   └── common/
├── benches/
├── scripts/
└── .github/workflows/{ci,release,openwrt,security}.yml
```

**Crate dependency DAG (strict — enforced by Cargo):**

```
ring, blake3  --> desmos-proto
socket2, wintun --> desmos-rt
desmos-proto, desmos-rt --> desmos-core
desmos-rt, argon2 --> desmos-http
desmos-core, desmos-http --> desmos-webui
desmos-core --> desmos-cli
desmos-webui, desmos-cli, desmos-core --> desmos (binary)
```

`desmos-proto` is I/O-free (compiles in `#![no_std] + alloc` if needed). `desmos-rt` is the only crate with `unsafe` syscall FFI. Do not violate the DAG even if it seems convenient.

---

## 5. Initial Scaffolding Commands

Run these in CWD, not in a subfolder.

```bash
# Root workspace manifest + toolchain
# (you will write Cargo.toml, rust-toolchain.toml by hand, not via cargo init)

# Verify toolchain pin takes effect
rustup show

# Create each crate as a member (cargo new --lib inside crates/)
mkdir -p crates
cargo new --lib crates/desmos-proto
cargo new --lib crates/desmos-rt
cargo new --lib crates/desmos-core
cargo new --lib crates/desmos-http
cargo new --lib crates/desmos-webui
cargo new --lib crates/desmos-cli
cargo new --bin crates/desmos

# Edit each crate's Cargo.toml to declare the dependency DAG.

# Final sanity check
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 6. Root Configuration Files

### 6.1 `Cargo.toml` (workspace root)

```toml
[workspace]
resolver = "2"
members = [
    "crates/desmos-proto",
    "crates/desmos-rt",
    "crates/desmos-core",
    "crates/desmos-http",
    "crates/desmos-webui",
    "crates/desmos-cli",
    "crates/desmos",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
license = "MIT"
authors = ["KilimcininKorOglu"]
repository = "https://github.com/<org>/desmos"

[workspace.dependencies]
ring     = "0.17"
blake3   = "1.5"
socket2  = "0.5"
wintun   = "0.5"
argon2   = "0.5"
# dev only
proptest = "1.5"
criterion = "0.5"
insta    = "1.40"

[profile.release]
opt-level      = 3
lto            = "thin"
codegen-units  = 1
strip          = "debuginfo"
panic          = "abort"

[profile.bench]
inherits = "release"
```

### 6.2 `rust-toolchain.toml`

```toml
[toolchain]
channel = "1.75.0"
components = ["rustfmt", "clippy"]
targets = [
    "x86_64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
]
profile = "minimal"
```

### 6.3 `rustfmt.toml`

```toml
edition = "2021"
max_width = 100
use_small_heuristics = "Max"
imports_granularity = "Item"
group_imports = "StdExternalCrate"
reorder_imports = true
trailing_comma = "Vertical"
```

### 6.4 `clippy.toml`

```toml
msrv = "1.75.0"
```

### 6.5 `deny.toml` (hard allow-list of the 5 runtime crates)

```toml
[advisories]
vulnerability = "deny"
unmaintained  = "warn"
yanked        = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "ISC", "CC0-1.0", "BSD-3-Clause", "OpenSSL"]

[bans]
multiple-versions = "deny"
# The five-crate runtime allow-list. Any other direct dependency is an error.
deny = [
    { name = "tokio" },
    { name = "async-std" },
    { name = "mio" },
    { name = "hyper" },
    { name = "reqwest" },
    { name = "clap" },
    { name = "serde" },
    { name = "serde_json" },
    { name = "toml" },
    { name = "log" },
    { name = "tracing" },
    { name = "rustls" },
    { name = "anyhow" },
    { name = "thiserror" },
    { name = "arc-swap" },
    { name = "once_cell" },
    { name = "parking_lot" },
    { name = "crossbeam" },
    { name = "zeroize" },
    { name = "base64" },
    { name = "hex" },
]
```

### 6.6 `.gitignore`

```
target/
**/*.rs.bk
Cargo.lock       # NB: Cargo.lock IS committed (binary project). Un-comment only if this ever becomes pure library.
!Cargo.lock
node_modules/
dist/
.DS_Store
.idea/
.vscode/
*.swp
*.swo
*.pem
*.key
!packaging/**/*.key.example
.env
```

**Important:** Do NOT add `AGENTS.md`, `CLAUDE.md`, `BUG-REPORT.md`, `.cursorrules`, `SKILL.md`, or `GEMINI.md` to this file. They are on a global gitignore.

### 6.7 `LICENSE`

MIT, standard text, `Copyright (c) 2026 KilimcininKorOglu`.

### 6.8 `CHANGELOG.md`

```markdown
# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding.
```

---

## 7. Implementation Order — Follow `TASKS.md` Exactly

The task list in `TASKS.md` is **69 tasks across 9 phases** and is the authoritative work order. Execute tasks in numeric order. Do not jump ahead. Do not merge tasks.

**Phase roadmap at a glance:**

| Phase | Tasks | Exit Criterion                                                    |
|-------|-------|-------------------------------------------------------------------|
| 0 Scaffolding            | T1-T6   | Workspace compiles, CI green on Tier 1                |
| 1 Protocol Foundation    | T7-T14  | Plaintext Linux tunnel works (`ping` through `desmos0`) |
| 2 Crypto + Bonding v1    | T15-T24 | Noise IK + RR bonding + reorder + probe              |
| 3 Advanced Bonding       | T25-T29 | 4 strategies, failover under 1 s, PMTUD              |
| 4 Server Mode            | T30-T36 | Multi-client server, 4 auth methods                  |
| 5 P2P + NAT Traversal    | T37-T39 | STUN + hole punch + relay fallback                   |
| 6 Cross-Platform         | T40-T49 | All 6 platforms, priv drop, MSI, IPK, pkg            |
| 7 Web UI + Polish        | T50-T64 | Full dashboard, dual-format stats, DNS leak prot.    |
| Release                  | T65-T69 | Docs, benches, packaging, v1.0.0 tag                 |

For each task:

1. **Read the task block in `TASKS.md` fully** — it names every file to create, the acceptance criteria, the effort estimate, and the SPEC/IMPL cross-references.
2. **Read the referenced SPEC / IMPL sections** to recover the context.
3. **Create or modify only the files the task names.** Do not touch other files.
4. **Write tests first** where the task specifies them.
5. **Run the quality gate** (see §10) before moving to the next task.
6. **Update `CHANGELOG.md`** with an `Unreleased` bullet that describes the change.

---

## 8. Design Patterns to Apply

Consult `IMPLEMENTATION.md §2` for the code sketches of these patterns. Apply them throughout the codebase; do not reinvent them:

- **Hexagonal / Ports & Adapters** — `Tun`, `Reactor`, `Socket` traits in `desmos-core`; per-platform impls in `desmos-rt`.
- **Strategy pattern** — `BondingStrategy` trait (4 impls) and `Authenticator` trait (4 impls). Hot-swappable at runtime.
- **Typestate** — `Session<S>` with `Handshaking`, `Established`, `Rekeying`, `Closed`; `Privileged` / `Unprivileged` for the privilege gate. Both must be compile-time enforced.
- **State Machine** — `LinkStateMachine` for `Healthy` / `Probation` / `Degraded` / `Dead`.
- **Packet Pipeline** — 4-stage outbound and inbound pipelines connected by SPSC rings on dedicated threads.
- **SPSC Ring Buffer** — lock-free ring with cache-padded head/tail. Only `unsafe` lives in `desmos-rt`.
- **Observer (broadcast)** — `Broadcast<T>` for stats and log fan-out to WebSocket subscribers.
- **Chain of Responsibility** — CLI dispatcher walks a `Vec<Box<dyn Command>>` until one claims the subcommand.
- **Circuit Breaker (framing)** — the failover state machine is conceptually a circuit breaker over flaky links.
- **Atomic Metrics** — counters via `AtomicU64::fetch_add(_, Relaxed)` on the hot path; snapshots via `load(Relaxed)` on the read path. No locks, no allocations.

---

## 9. Core Reference Sheets (Inlined to Avoid Context-Switching)

### 9.1 DWP Wire Format (from IMPLEMENTATION.md §4.1)

16-byte unencrypted header, then encrypted payload, then a 16-byte AEAD tag.

```
Offset  Size  Field
 0      0.5B  version (4 bits high) | type (4 bits low)
 1      1B    flags                (FIN|ACK|FRAG|REDUNDANT|PRIORITY)
 2      2B    session_id           (big-endian u16)
 4      4B    sequence             (big-endian u32)
 8      4B    timestamp_us         (big-endian u32)
12      2B    payload_len          (big-endian u16)
14      1B    interface_id
15      1B    reserved
16      N     encrypted payload
16+N   16B    AEAD auth tag (128 bits)
```

Packet types: `0=Data`, `1=Handshake`, `2=Keepalive`, `3=Probe`, `4=Control`.

### 9.2 Session Typestate (Rust sketch)

```rust
pub struct Session<S> { id: SessionId, state: S }

pub struct Handshaking  { initiator: bool, noise: NoiseState }
pub struct Established  {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    counter:  AtomicU64,
    anti_replay: AntiReplayWindow,
}
pub struct Rekeying { old: Established, new_pending: NoiseState }
pub struct Closed;

impl Session<Handshaking> {
    pub fn advance(self, msg: &[u8]) -> Result<HandshakeOutcome, HandshakeError>;
}

impl Session<Established> {
    pub fn encrypt_data(&self, plaintext: &[u8], out: &mut [u8]) -> usize;
    pub fn decrypt_data(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, CryptoError>;
}
```

A `compile_fail` doctest must demonstrate that `encrypt_data` is unreachable from `Session<Handshaking>`.

### 9.3 Bonding Strategy (Rust sketch)

```rust
pub trait BondingStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn schedule<'a>(&self, packet: &PacketMeta, links: &'a LinkTable) -> LinkSelection<'a>;
}

pub enum LinkSelection<'a> {
    One(&'a Link),
    All(&'a [Arc<Link>]),  // Redundant strategy
}
```

### 9.4 Privilege Gate (Rust sketch)

```rust
pub struct Privileged   { /* pre-drop state */ }
pub struct Unprivileged { /* post-drop state */ }

impl Privileged {
    pub fn new() -> io::Result<Self>;
    pub fn create_tun(&mut self, name: &str) -> io::Result<Arc<dyn Tun>>;
    pub fn bind_socket(&mut self, iface: &str, addr: SocketAddr) -> io::Result<UdpSocket>;
    pub fn drop_privileges(self) -> io::Result<Unprivileged>;
}
```

Main must call `drop_privileges()` before entering any main loop. Enforcement is by type consumption — `Privileged` is dropped, only `Unprivileged` remains.

### 9.5 Auth Methods (from SPECIFICATION.md §3.3)

- **PSK** — shared secret, mixed into Noise IK via the `psk` modifier.
- **Public key** — server's `authorized_keys` file lists client static pubkeys.
- **TOTP** — RFC 6238, ±1 period, hand-rolled HMAC-SHA1 via `ring`, replay-rejected within the same period.
- **mTLS** — minimal TLS 1.3 client cert verification via `ring` signature ops; CN mapped to identity.

### 9.6 REST API Surface (from IMPLEMENTATION.md §5.1)

| Method | Path                          | Description                               | Auth |
|--------|-------------------------------|-------------------------------------------|------|
| GET    | `/api/v1/status`              | Tunnel status snapshot                    | Yes  |
| GET    | `/api/v1/interfaces`          | Interface list + metrics                  | Yes  |
| PUT    | `/api/v1/interfaces/:name`    | Enable / disable / reweight interface     | Yes  |
| GET    | `/api/v1/bonding`             | Current strategy + metrics                | Yes  |
| PUT    | `/api/v1/bonding/strategy`    | Hot-switch strategy                       | Yes  |
| GET    | `/api/v1/stats`               | Dual-format: JSON or Prometheus           | Yes  |
| GET    | `/api/v1/clients`             | Server: connected clients                 | Yes  |
| DELETE | `/api/v1/clients/:session_id` | Server: kick client                       | Yes  |
| GET    | `/api/v1/config`              | Current config (secrets redacted)         | Yes  |
| PUT    | `/api/v1/config`              | Hot-reload config                         | Yes  |
| GET    | `/api/v1/logs`                | Recent log entries                        | Yes  |
| GET    | `/api/v1/health`              | Unauthenticated liveness probe            | No   |
| GET    | `/api/v1/ws/stats`            | WebSocket stats stream                    | Yes  |
| GET    | `/api/v1/ws/logs`             | WebSocket log stream                      | Yes  |
| GET    | `/`                           | Web UI SPA entry                          | Yes  |
| GET    | `/static/*`                   | Web UI static assets                      | Yes  |

**Prometheus content negotiation:** `/api/v1/stats` returns JSON by default; returns `text/plain; version=0.0.4` when `?format=prometheus` or `Accept: text/plain; version=0.0.4`.

**Response envelope (JSON):**

```json
{
  "data": { ... },
  "meta": { "request_id": "0x...", "generated_at_us": 1744291200123456 }
}
```

**Error envelope:**

```json
{
  "error": {
    "code": "interface_not_found",
    "message": "No configured interface named 'eth5'",
    "details": { "name": "eth5" }
  },
  "meta": { "request_id": "0x..." }
}
```

### 9.7 Error Code Catalog

`unauthorized`, `forbidden`, `not_found`, `rate_limited`, `invalid_config`, `interface_not_found`, `session_not_found`, `strategy_unknown`, `handshake_failed`, `auth_failed`, `internal_error`.

### 9.8 Config Schema (minimal reference — full example in `config/desmos.toml.example`, which Task 4 creates)

```toml
[general]
mode = "client"                       # client | server | p2p
log_level = "info"                    # trace | debug | info | warn | error
tunnel_mtu = 1400

[server]
listen = "0.0.0.0:4900"
public_key = "<base64>"
private_key_file = "/etc/desmos/server.key"
max_clients = 100

[server.auth]
method = "psk"                        # psk | pubkey | totp | mtls
psk = "..."

[client]
server = "vpn.example.com:4900"
server_public_key = "<base64>"
private_key_file = "~/.config/desmos/client.key"
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

[webui]
enabled = true
listen = "127.0.0.1:8080"
username = "admin"
password_hash = "<argon2id encoded>"

[p2p]
peer_public_key = "<base64>"
peer_endpoint = "peer.example.com:4900"
stun_servers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
relay_servers = []
```

### 9.9 Environment Variables

| Variable             | Required | Default                      | Description                         |
|----------------------|----------|------------------------------|-------------------------------------|
| `DESMOS_CONFIG`      | No       | OS-specific default path     | Override config file location       |
| `DESMOS_LOG_LEVEL`   | No       | `info`                       | Log level                           |
| `DESMOS_MODE`        | No       | (from config)                | `client` / `server` / `p2p`         |
| `NO_COLOR`           | No       | (unset)                      | Disable ANSI colors in CLI output   |

### 9.10 Standard Config File Paths

| OS      | Path                                                      |
|---------|-----------------------------------------------------------|
| Linux   | `/etc/desmos/desmos.toml`                                 |
| FreeBSD | `/usr/local/etc/desmos/desmos.toml`                       |
| macOS   | `/Library/Preferences/desmos/desmos.toml`                 |
| Windows | `C:\ProgramData\desmos\desmos.toml`                       |
| OpenWrt | `/etc/config/desmos` (UCI) translated to TOML by the shim |

### 9.11 Performance Targets (SPECIFICATION.md §10)

- Single-core tunnel throughput ≥ **2 Gbps**
- Bonding overhead vs raw aggregate < **3%**
- Handshake latency < **5 ms** (1-RTT)
- Failover time < **1 s**
- Reorder buffer p99 added latency < **1 ms**
- Client RSS (3 interfaces) < **20 MB**
- Server RSS (100 clients) < **200 MB**
- Stripped binary (Linux x86_64 musl) < **5 MB**

---

## 10. Quality Gate (Run After Every Task)

Run this block before moving to the next task. Any failure must be fixed before proceeding.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace
cargo deny check
```

After frontend is scaffolded (Task 59+), additionally run:

```bash
cd crates/desmos-webui/web && npm run lint && npm run typecheck && npm run build && cd -
```

At the end of every phase, run the full end-to-end integration suite:

```bash
cargo test --workspace --test '*'
```

---

## 11. Verification Checkpoints

Stop and verify at each checkpoint. Do not proceed if any item fails.

### Checkpoint A — After Task 6 (Phase 0 complete)
- [ ] `cargo check --workspace` zero warnings
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo deny check` passes (only the 5 runtime crates allowed)
- [ ] CI workflow runs green on all 7 Tier 1 targets
- [ ] `cargo run -p desmos` prints the CLI help text

### Checkpoint B — After Task 14 (Phase 1 complete)
- [ ] `desmos up --mode plaintext` creates `desmos0`, ping round-trips through the UDP loop
- [ ] DWP header codec passes `proptest` with 1000 cases
- [ ] No fd leaks after 1000 register/deregister cycles on epoll

### Checkpoint C — After Task 24 (Phase 2 complete)
- [ ] Encrypted single-interface tunnel: `iperf3` > 500 Mbps on localhost
- [ ] Noise IK handshake < 5 ms on localhost
- [ ] 2-veth RR bonding: `iperf3` ≥ 1.5× single-interface baseline
- [ ] `encrypt_data` on `Session<Handshaking>` is a compile-error (verified by `compile_fail` doctest)

### Checkpoint D — After Task 29 (Phase 3 complete)
- [ ] All 4 bonding strategies work (hot-switch under load drops zero packets)
- [ ] 3-interface failover: kill one mid-`iperf3` → tunnel stays up, failover < 1 s
- [ ] PMTUD converges < 3 s per link

### Checkpoint E — After Task 36 (Phase 4 complete — MVP reached)
- [ ] Two clients connect simultaneously to one server with different auth methods
- [ ] NAT / masquerade rules installed on start, removed on stop
- [ ] Handshake rate limit: 6th attempt within 10 s from same IP rejected
- [ ] `desmos clients kick <id>` disconnects the target

### Checkpoint F — After Task 39 (Phase 5 complete)
- [ ] STUN resolves the host public IP
- [ ] Two cone-NAT peers establish a direct P2P tunnel
- [ ] Symmetric-NAT pair falls back to relay within 3 s

### Checkpoint G — After Task 49 (Phase 6 complete)
- [ ] Phase 1-3 test suite passes on **Linux, macOS, Windows, FreeBSD** native CI runners
- [ ] `desmos` drops privileges and post-drop cannot open a new TUN (verified by seccomp denial on Linux)
- [ ] OpenWrt IPK installs and runs on a test image
- [ ] pfSense pkg installs on pfSense 2.7+
- [ ] Windows MSI installs the service, `sc query Desmos` reports `RUNNING`

### Checkpoint H — After Task 64 (Phase 7 complete)
- [ ] All 6 Web UI screens load and display live data
- [ ] Dual-format `/api/v1/stats` returns valid Prometheus text under `?format=prometheus`
- [ ] Config hot-reload works for reload-safe fields and rejects unsafe changes with a typed error
- [ ] DNS leak protection on/off correctly updates system resolver config and restores on teardown
- [ ] `cargo build --no-default-features -p desmos-webui` builds without Node (feature gate works)

### Checkpoint I — After Task 69 (v1.0.0 release)
- [ ] All performance targets from §9.11 met by `criterion` benches
- [ ] Pushing tag `v1.0.0` triggers the release workflow
- [ ] GitHub Release has artifacts for every Tier 1 + Tier 2 target with SHA-256 sums
- [ ] `scripts/smoke-test.sh` passes on a fresh Debian 12 VM

---

## 12. Branding and Voice (Applied to User-Visible Artifacts)

Consult `BRANDING.md` for the full catalog. For every user-visible string (CLI output, Web UI copy, README, docs, error messages), apply these rules:

- **Voice:** precise, terse, technical, trustworthy. No marketing copy, no hype words, no exclamation marks.
- **Emoji:** **never** in Markdown files, READMEs, code comments, CLI output, or Web UI copy.
- **Numbers:** always concrete. "≥ 2 Gbps" not "blazing fast". "< 1 s" not "fast failover".
- **Error messages:** `<component>: <what failed>. <why>. <how to fix>.`
- **Terminology:** prefer Bond, Link, Interface, Tunnel, Handshake, Session, Operator, Drop, Audit. Avoid Merge, Connection (for non-TCP), NIC, Pipe, User, Custom.
- **Colors:** Bond Teal `#14B8A6` primary, Signal Amber `#F59E0B` accent, dark mode default. Full palette in `BRANDING.md §3`.
- **Fonts:** Inter body/heading, JetBrains Mono code. Both self-hosted as WOFF2 in the Web UI.
- **CLI output:** colored by default, respects `NO_COLOR` and `--no-color`. Tables with box-drawing characters. `--json` disables all decoration.
- **README:** follow the skeleton in `BRANDING.md §9.1`. Emoji-free. No marketing bullets.

---

## 13. Git Workflow

- `main` is always green. All work in feature branches.
- Branch names: `feat/<scope>`, `fix/<scope>`, `chore/<scope>`, `docs/<scope>`, `refactor/<scope>`.
- Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`.
- **One task = one commit** (or a small number of commits if the task naturally decomposes). Never batch multiple tasks into a single commit.
- **Never bypass hooks.** No `--no-verify`, no `--no-gpg-sign`.
- **Never include bug IDs in commit messages.**
- If a bug fix requires a refactor, pause and ask the user before proceeding.

---

## 14. Non-Goals Reminder (Do Not Implement These in v1.0)

From `SPECIFICATION.md §11.2`:

- iOS / Android clients
- Full mesh VPN (Tailscale / Nebula style)
- WireGuard / OpenVPN protocol compatibility
- MPTCP kernel support
- Split tunneling
- Per-application traffic shaping
- GUI desktop system-tray client
- Multi-user RBAC on the Web UI
- Built-in certificate authority
- IPv6 tunnel transport (v1.1)
- OS keyring integration for secrets at rest (v1.1)
- Hosted public relay infrastructure

If you find yourself tempted to add any of these, stop and ask the user.

---

## 15. What to Do When You Get Stuck

1. **Re-read** the relevant `TASKS.md` task, plus its SPEC and IMPL cross-references.
2. **Check for file staleness** — if you are more than 10 messages into the conversation, `Read` the file you are about to edit again. The harness may have silently compacted stale context.
3. **Search with `grep`, not memory.** Rust type references, trait impls, and string literals all need separate searches. `grep` does not understand the AST.
4. **Ask the user** before any destructive action (`git reset --hard`, `git push --force`, `rm -rf`, dropping a DB, deleting an unfamiliar file). Never bypass this.
5. **Never silently deviate from a planning doc.** If a requirement is unclear or seems wrong, pause and raise it.
6. **Never substitute a forbidden dependency.** If you need a primitive that sounds like it should come from `tokio` or `serde`, it is already budgeted to be hand-rolled inside `desmos-rt`, `desmos-http`, or `desmos-core`. Write it.

---

## 16. Final Quality Checklist Before v1.0.0 Release

- [ ] All 69 tasks in `TASKS.md` are complete and committed
- [ ] All 9 checkpoints (A-I) pass
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check` all pass
- [ ] CI matrix green on all Tier 1 + Tier 2 targets
- [ ] `criterion` benches meet every performance target in §9.11
- [ ] Every SPEC §3 feature has at least one test
- [ ] Every SPEC §6.2 endpoint has a `curl` example in `docs/cli.md` or `docs/webui.md`
- [ ] ADRs for workspace layout, hand-rolled runtime, 5-crate budget, typestate are written
- [ ] README matches BRANDING.md voice and skeleton
- [ ] GitHub Release artifacts have SHA-256 sums
- [ ] Smoke test passes on a fresh Debian 12 VM
- [ ] CHANGELOG.md v1.0.0 entry is written
- [ ] License file is present and unmodified
- [ ] No forbidden file (`AGENTS.md`, `CLAUDE.md`, `BUG-REPORT.md`, `.cursorrules`, `SKILL.md`, `GEMINI.md`) has been added to git

---

**Begin with Task 1 from `TASKS.md`. Good luck.**
