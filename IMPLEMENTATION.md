# Desmos — Implementation Plan

> Technical blueprint derived from `SPECIFICATION.md`. Translates the "what" into a concrete "how" using a Cargo workspace, hand-rolled primitives, and a strict 5-crate external dependency budget.

**Cross-reference:** Section numbers `SPEC §X.Y` refer to `SPECIFICATION.md` sections.

---

## 1. Tech Stack

### 1.1 Stack Summary

| Layer              | Technology                          | Version                        | Rationale                                                                                      |
|--------------------|-------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------|
| Language           | Rust                                | Edition 2021, MSRV 1.75         | Zero-cost abstractions, `#![no_std]`-friendly core, fearless concurrency, stable ABI on all targets. PRD constraint. |
| Toolchain          | `rust-toolchain.toml` pinned        | 1.75.0                         | Reproducible builds, stable MSRV across all Tier 1 cross-compile targets.                     |
| Build              | `cargo` + `build.rs` (Web UI embed) | Cargo 1.75+                    | Native Rust workflow; no Make, no additional build system.                                    |
| Workspace Layout   | Cargo workspace (7 crates)          | —                              | Isolated testable units, minimal rebuilds, enforced layering.                                 |
| Crypto             | `ring`                              | 0.17.x                         | BoringSSL-backed, audited, constant-time ChaCha20-Poly1305 and X25519. SPEC §11.1 locked crate. |
| Hash               | `blake3`                            | 1.5.x                          | SIMD-optimized, single-purpose, official implementation. SPEC §11.1 locked crate.              |
| Socket options     | `socket2`                           | 0.5.x                          | `SO_BINDTODEVICE`, `IP_BOUND_IF`, per-interface socket binding. SPEC §11.1 locked crate.       |
| Windows TUN        | `wintun`                            | 0.5.x                          | Only stable FFI binding to the Wintun driver. SPEC §11.1 locked crate.                        |
| Password hashing   | `argon2`                            | 0.5.x                          | Memory-hard, RFC 9106 Argon2id for Web UI auth. SPEC §11.1 locked crate.                      |
| Async runtime      | Hand-rolled (`desmos-rt`)           | in-tree                        | SPEC §4.1 constraint: epoll/kqueue/IOCP without tokio/async-std.                               |
| Serialization      | Hand-rolled                         | in-tree                        | Tight TOML subset parser, JSON encoder/decoder, DWP binary codec.                              |
| HTTP / WebSocket   | Hand-rolled (`desmos-http`)         | in-tree                        | Small, auditable, no hyper/warp/axum.                                                          |
| CLI parser         | Hand-rolled (`desmos-cli`)          | in-tree                        | Subcommand dispatch + flag parsing in < 500 LOC.                                               |
| Frontend framework | React                               | 18.3.x                         | PRD §7.1 choice. Only at build-time — runtime is static assets.                                |
| Frontend tooling   | Vite                                | 5.4.x                          | Fast dev server, ESM-native, minimal config. Invoked from `build.rs`.                         |
| Frontend language  | TypeScript                          | 5.5.x                          | Type safety on the dashboard layer; compiled to static JS at build time.                      |
| Linting            | `cargo clippy -- -D warnings`       | toolchain-bundled              | Zero-warning policy. No ESLint for Rust.                                                       |
| Formatting         | `cargo fmt`                         | toolchain-bundled              | Enforced in CI.                                                                                |
| Testing (Rust)     | `cargo test` + `proptest` (dev-dep) | `proptest` 1.5.x               | `proptest` is a dev-dependency — does not count against the 5-crate budget.                   |
| Frontend linting   | `eslint` + `@typescript-eslint`     | 9.x                            | Dev-only, runs in `webui/web/`; not bundled into binary.                                       |
| CI/CD              | GitHub Actions                      | —                              | Free for public repos, broad OS runner coverage (Linux, macOS, Windows).                      |
| Container          | Distroless Debian (server image)    | latest                         | Minimal attack surface; server role only.                                                      |

**Dev-dependency policy:** `proptest`, `criterion`, and `insta` are allowed as `[dev-dependencies]` since they do not land in release artifacts. The 5-crate budget applies to runtime dependencies only.

### 1.2 Key Technical Decisions

#### Decision: Hand-Rolled Async Runtime

- **Context:** SPEC §4.1 and §11.1 forbid `tokio`, `async-std`, and any other async runtime crate. The data plane needs a single event loop per thread with sub-microsecond dispatch overhead on Linux.
- **Options Considered:**
  1. **`tokio`** — Pros: ecosystem, ergonomics. Cons: forbidden by SPEC, huge dependency tree.
  2. **`mio` alone** — Pros: thin. Cons: still a non-approved crate, and we still write an event loop on top.
  3. **Direct syscalls** (`epoll`, `kqueue`, `CreateIoCompletionPort`) — Pros: zero runtime dependencies, full control. Cons: three platform backends, more code to audit.
- **Choice:** Direct syscalls via raw FFI + safe wrappers inside `desmos-rt`.
- **Rationale:** SPEC constraint is hard. Three backends behind one `Reactor` trait is ~600 LOC total and fully auditable. Gives us control over buffer lifecycle (zero-copy), timer wheel integration, and priority queues for handshake vs data packets.
- **Consequences:** Extra initial implementation cost. Platform-specific bugs must be caught per backend in CI. No async/await ergonomics — we use state machines + poll-based I/O. **SPEC §11.1 locked.**

#### Decision: Workspace with 7 Crates

- **Context:** SPEC and PRD define a large feature surface (wire protocol, crypto, bonding, server, web UI, CLI, 6 platforms). A single crate would be a 20k-LOC monolith with slow incremental builds and tangled test boundaries.
- **Options Considered:**
  1. **Single crate** with modules — Simple layout, fastest initial setup. Cons: slow rebuilds, no enforced layering, impossible to unit-test with real test binaries.
  2. **3 crates** (core, webui, bin) — Moderate split. Cons: `core` still too broad, bonding + TUN + crypto mingle.
  3. **7 crates** (proto, rt, core, http, webui, cli, bin) — Clean dependency DAG, parallel builds, enforced boundaries.
- **Choice:** 7 crates (see §3.1).
- **Rationale:** Gives us `desmos-proto` as an I/O-free pure logic crate (ideal for `proptest` wire-format testing), `desmos-rt` as the only crate that touches unsafe syscalls (ideal audit boundary), `desmos-http` as a general-purpose plumbing crate, and `desmos-webui` / `desmos-cli` as thin composition layers over `desmos-core`.
- **Consequences:** Workspace-level `Cargo.toml` with shared `[profile.release]` and dep-version pinning. Slightly longer initial compile. Slower `cargo run` from a cold cache, but much faster incremental development.

#### Decision: Strategy Pattern for Bonding + Auth

- **Context:** SPEC §3.2 requires 4 bonding strategies, all hot-switchable. SPEC §3.3 requires 4 auth methods. Both are runtime-selectable and must share a common interface.
- **Choice:** Rust trait objects behind an `Arc<dyn Strategy>` for bonding and `Box<dyn Authenticator>` for auth. Strategy swap is an atomic pointer swap on the engine's `active_strategy` field.
- **Rationale:** `Arc` + atomic swap avoids locking on the hot path. Each strategy is a leaf implementation that owns no state beyond configuration — the engine passes the link set per schedule call.
- **Consequences:** One dynamic dispatch per packet scheduled. At 2 Gbps × 1400 B MTU ≈ 180 k packets/s on a single core, this is ~180 kcalls/s of dynamic dispatch — negligible compared to AEAD cost.

#### Decision: React Frontend with Vite, Embedded via `build.rs`

- **Context:** SPEC §7.2 requires a dashboard, interface table, bonding controls, logs viewer, settings editor. Hand-rolling that UI in vanilla JS is possible but creates maintenance pain.
- **Options Considered:**
  1. **Vanilla JS/HTML** — No Node dependency. Cons: 6+ screens of state sync by hand.
  2. **Pre-built React dist in repo** — Git-tracked JS bloat.
  3. **Vite + React, `build.rs` invokes `npm run build`** — Node required only during release builds; `include_dir!` bakes the `dist/` into the binary.
- **Choice:** Option 3 (decided during elicitation).
- **Rationale:** Developer ergonomics for six screens + live WebSocket wiring; zero runtime Node dependency. `build.rs` checks if `dist/` is newer than the source to avoid unnecessary `npm` invocations.
- **Consequences:** Contributors need Node.js 20+ to build from source. CI caches `node_modules` per target. `desmos-webui` Cargo metadata carries a `feature = "embed"` flag so `cargo build --no-default-features` skips the Node step for pure-backend developers.

#### Decision: Dual-Format `/api/v1/stats` Endpoint

- **Context:** SPEC §6.2 (updated) states stats must be served as JSON by default and as Prometheus text format when requested, without adding a dependency.
- **Choice:** Single handler that introspects `Accept` header and `?format=prometheus` query. Prometheus formatter is a ~60 LOC function in `desmos-webui::prometheus`.
- **Rationale:** Zero new crates. Operators get Grafana integration for free. Tests are simple string comparisons.

#### Decision: Privilege Drop via `setuid`/`setgid` + Post-Init Hooks

- **Context:** SPEC §11.1 requires dropping privileges after TUN creation and socket binding on all Unix platforms.
- **Choice:** Main thread performs privileged operations, then calls a `platform::drop_privileges()` function which branches to per-platform impls (Linux `setresuid`, FreeBSD `pledge` + `unveil`, macOS sandbox init).
- **Consequences:** Every privileged operation must happen before `main_loop()` is entered. This is enforced by a typestate pattern: `Privileged` wraps initialization, `Unprivileged` wraps the main loop, and the transition consumes the former.

#### Decision: Typestate for Session Lifecycle

- **Context:** SPEC §3.1 defines a session lifecycle: `Handshaking → Established → Rekeying → Closed`. Invalid state transitions must be compile-time errors, not runtime panics.
- **Choice:** Typestate pattern — `Session<Handshaking>`, `Session<Established>`, `Session<Closed>`. Data-plane traffic is only reachable via `&Session<Established>` references.
- **Rationale:** Eliminates entire classes of state-machine bugs. The compiler refuses to let us call `encrypt_data()` on a `Session<Handshaking>`.

#### Decision: Shared Workspace `[profile.release]`

- **Context:** Performance targets (SPEC §10) require SIMD, LTO, and small binary size.
- **Choice:**
  ```toml
  [profile.release]
  opt-level = 3
  lto = "thin"
  codegen-units = 1
  strip = "debuginfo"
  panic = "abort"
  ```
- **Rationale:** `lto = "thin"` keeps link time reasonable but still inlines across crates. `panic = "abort"` removes unwinding tables — saves binary size and simplifies signal-handling interaction. `strip = "debuginfo"` for release artifacts (symbols preserved for debug builds). `codegen-units = 1` is slow but maximizes throughput-critical inlining.

### 1.3 Dependency Inventory

| Package    | Kind       | Purpose                            | License       | Justification                                                                      |
|------------|------------|------------------------------------|---------------|------------------------------------------------------------------------------------|
| `ring`     | runtime    | ChaCha20-Poly1305 AEAD, X25519     | ISC           | SPEC §11.1 locked. Rolling our own crypto is forbidden.                            |
| `blake3`   | runtime    | BLAKE3 hashing, HKDF               | CC0 / Apache  | SPEC §11.1 locked. Official SIMD implementation.                                   |
| `socket2`  | runtime    | `SO_BINDTODEVICE`, `IP_BOUND_IF`   | Apache-2.0    | SPEC §11.1 locked. The only portable abstraction over advanced socket options.    |
| `wintun`   | runtime    | Windows TUN driver FFI             | MIT           | SPEC §11.1 locked. Wintun is the only supported Windows TUN ecosystem.             |
| `argon2`   | runtime    | Web UI password hashing            | MIT / Apache  | SPEC §11.1 locked. Security-critical, not worth hand-rolling.                      |
| `proptest` | dev-only   | Property-based tests (DWP codec)   | MIT / Apache  | Dev-dependency, not shipped. Out of budget.                                        |
| `criterion`| dev-only   | Benchmarks                         | MIT / Apache  | Dev-dependency, not shipped. Out of budget.                                        |
| `insta`    | dev-only   | Snapshot tests (CLI output, JSON)  | Apache-2.0    | Dev-dependency, not shipped. Out of budget.                                        |

**Dependency philosophy:** Stdlib-first with a hard cap of 5 runtime crates. Any proposal to add a 6th runtime crate requires removing one. Hand-rolled alternatives documented inline so reviewers understand the trade-offs.

---

## 2. Design Patterns

### 2.1 Hexagonal / Ports & Adapters

**Why:** SPEC §4.1 requires 6 platform backends for TUN and 3 for the async runtime. Business logic (bonding, protocol, session) must remain independent of platform syscalls so it can be unit-tested deterministically.

**Application:** `desmos-core` defines ports as traits (`Tun`, `Reactor`, `Socket`). `desmos-rt` provides per-platform adapters that implement these traits. The bonding engine and session manager only see trait objects — they never call a syscall directly.

**Code Sketch:**

```rust
// crates/desmos-core/src/ports.rs
pub trait Tun: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    fn mtu(&self) -> u32;
}

pub trait Reactor: Send {
    fn register_udp(&mut self, sock: UdpSocket, tag: Tag) -> Token;
    fn register_tun(&mut self, tun: Arc<dyn Tun>, tag: Tag) -> Token;
    fn poll(&mut self, timeout: Duration) -> Vec<Event>;
}

// crates/desmos-rt/src/linux/tun.rs
pub struct LinuxTun { fd: RawFd }
impl Tun for LinuxTun { /* ioctl + read/write */ }

// crates/desmos-rt/src/windows/tun.rs
pub struct WintunTun { session: wintun::Session }
impl Tun for WintunTun { /* Wintun FFI */ }
```

### 2.2 Strategy Pattern (Bonding Strategies)

**Why:** SPEC §3.2.1 requires 4 bonding strategies, hot-switchable at runtime without dropping the tunnel. SPEC §3.3 needs 4 auth strategies at handshake time.

**Application:** A `BondingStrategy` trait with 4 implementations. The engine holds an `ArcSwap<dyn BondingStrategy>` so the Web UI can swap strategies atomically without locking the hot path.

**Code Sketch:**

```rust
// crates/desmos-core/src/bonding/strategy.rs
pub trait BondingStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    /// Select one or more links for this packet. Redundant returns all; others return one.
    fn schedule<'a>(&self, packet: &PacketMeta, links: &'a LinkTable) -> LinkSelection<'a>;
}

pub struct RoundRobin { next: AtomicUsize }
pub struct Weighted  { cursor: AtomicU64 }
pub struct LatencyAdaptive { weights: RwLock<Vec<f32>> }
pub struct Redundant;

impl BondingStrategy for RoundRobin {
    fn name(&self) -> &'static str { "round-robin" }
    fn schedule<'a>(&self, _p: &PacketMeta, links: &'a LinkTable) -> LinkSelection<'a> {
        let healthy = links.healthy();
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % healthy.len().max(1);
        LinkSelection::One(&healthy[idx])
    }
}
```

### 2.3 Typestate Pattern (Session Lifecycle + Privilege Gate)

**Why:** SPEC §3.1 requires that data packets are only sent on an `Established` session. SPEC §11.1 requires privilege drop before entering the main loop. Both invariants should be compile-time enforced.

**Code Sketch:**

```rust
// crates/desmos-core/src/session/mod.rs
pub struct Session<S> { id: SessionId, state: S }
pub struct Handshaking { initiator: bool, noise: NoiseState }
pub struct Established { send_key: [u8; 32], recv_key: [u8; 32], counter: AtomicU64 }
pub struct Rekeying { old: Established, new_pending: NoiseState }
pub struct Closed;

impl Session<Handshaking> {
    pub fn advance(self, msg: &[u8]) -> Result<HandshakeOutcome, HandshakeError> { /* ... */ }
}

impl Session<Established> {
    // encrypt_data is ONLY available in Established state.
    pub fn encrypt_data(&self, plaintext: &[u8], out: &mut [u8]) -> usize { /* ... */ }
}

// Privilege gate:
pub struct Privileged { /* root-only state */ }
pub struct Unprivileged { /* dropped state */ }

impl Privileged {
    pub fn create_tun(&mut self, name: &str) -> io::Result<Arc<dyn Tun>> { /* ... */ }
    pub fn drop_privileges(self) -> io::Result<Unprivileged> { /* setresuid etc. */ }
}
```

### 2.4 State Machine (Link Health)

**Why:** SPEC §3.2.4 defines link states (`Healthy`, `Probation`, `Degraded`, `Dead`) with specific transition rules. A hand-written `match` block becomes error-prone as conditions accumulate.

**Code Sketch:**

```rust
// crates/desmos-core/src/bonding/link_state.rs
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkState { Healthy, Probation { until: Instant }, Degraded, Dead }

pub struct LinkStateMachine { state: LinkState }

impl LinkStateMachine {
    pub fn on_probe(&mut self, sample: ProbeSample, now: Instant) -> Option<Transition> {
        let next = match (self.state, sample.status()) {
            (LinkState::Healthy,   ProbeStatus::HighLoss(5))   => LinkState::Degraded,
            (LinkState::Healthy,   ProbeStatus::NoResponse(3)) => LinkState::Dead,
            (LinkState::Degraded,  ProbeStatus::Good(3))       => LinkState::Probation { until: now + Duration::from_secs(10) },
            (LinkState::Dead,      ProbeStatus::Good(3))       => LinkState::Probation { until: now + Duration::from_secs(10) },
            (LinkState::Probation { until }, _) if now >= until => LinkState::Healthy,
            (s, _) => s,
        };
        if next != self.state {
            let t = Transition { from: self.state, to: next };
            self.state = next;
            Some(t)
        } else { None }
    }
}
```

### 2.5 Middleware / Packet Pipeline

**Why:** SPEC §4.2 describes a data flow from TUN → bonding → crypto → UDP (and reverse). Each stage transforms packets and passes them along. Straight-line code would couple all stages.

**Application:** The outbound pipeline is composed of four stages connected by lock-free SPSC ring buffers. Each stage lives on a dedicated thread. Inbound pipeline mirrors outbound.

**Code Sketch:**

```rust
// crates/desmos-core/src/pipeline/mod.rs
pub struct OutboundPipeline {
    tun_reader:   Arc<TunReader>,
    scheduler:    Arc<Scheduler>,
    encryptor:    Arc<Encryptor>,
    udp_writer:   Arc<UdpFanOut>,
    tun_to_sched: SpscRing<PacketBuf>,
    sched_to_crypt: SpscRing<(LinkId, PacketBuf)>,
    crypt_to_udp: SpscRing<(LinkId, PacketBuf)>,
}

impl OutboundPipeline {
    pub fn spawn(self) -> JoinHandle<()> { /* 4 threads, 3 rings, no locks */ }
}
```

### 2.6 Ring Buffer / Worker Pool

**Why:** PRD §9.2 and SPEC §4.2 mandate a 5-thread model with lock-free SPSC/MPSC rings between stages. Shared mutation on the hot path is disallowed.

**Code Sketch:**

```rust
// crates/desmos-rt/src/ring.rs
pub struct SpscRing<T> {
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    head: CachePadded<AtomicUsize>, // producer
    tail: CachePadded<AtomicUsize>, // consumer
}

impl<T> SpscRing<T> {
    pub fn try_push(&self, v: T) -> Result<(), T> { /* wait-free */ }
    pub fn try_pop(&self) -> Option<T> { /* wait-free */ }
}
```

### 2.7 Observer Pattern (Stats + Log Broadcast)

**Why:** SPEC §3.5.1 and §7.2 need the Web UI to receive stats and log events at up to 2 Hz per page. Multiple WebSocket subscribers may exist simultaneously.

**Application:** A broadcast channel with ring-buffer semantics. Publishers never block; slow subscribers drop older events.

**Code Sketch:**

```rust
// crates/desmos-core/src/broadcast.rs
pub struct Broadcast<T: Clone> { inner: Arc<BroadcastInner<T>> }
impl<T: Clone> Broadcast<T> {
    pub fn publish(&self, v: T) { /* non-blocking ring append */ }
    pub fn subscribe(&self) -> Subscriber<T> { /* tail cursor */ }
}

// desmos-webui uses it:
let stats_bus = core.stats_broadcast();
websocket_handler.serve(async_iter(stats_bus.subscribe()));
```

### 2.8 Chain of Responsibility (CLI Dispatch)

**Why:** SPEC §3.4 has a dozen subcommands with shared global flags and per-subcommand flags.

**Code Sketch:**

```rust
// crates/desmos-cli/src/dispatch.rs
pub trait Command {
    fn name(&self) -> &'static str;
    fn run(&self, args: &ParsedArgs, ctx: &Context) -> Result<i32, CliError>;
}

pub struct Dispatcher { commands: Vec<Box<dyn Command>> }
impl Dispatcher {
    pub fn new() -> Self { Self { commands: vec![
        Box::new(Up), Box::new(Down), Box::new(Status), Box::new(Interfaces),
        Box::new(Keygen), Box::new(ConfigCmd), Box::new(Webui),
        Box::new(BondingCmd), Box::new(ClientsCmd), Box::new(StatsCmd),
    ] } }
    pub fn dispatch(&self, argv: &[String]) -> i32 { /* find + run */ }
}
```

### 2.9 Circuit Breaker Variant (Failover)

**Why:** SPEC §3.2.4 prescribes degraded → dead → probation transitions that are effectively a circuit breaker over a flaky network link. §2.4 shows the state machine; the pattern naming clarifies intent for readers.

Pattern maps: `Healthy ≡ Closed`, `Dead ≡ Open`, `Probation ≡ Half-Open`. No additional code — this is the conceptual framing of §2.4.

### 2.10 Observer-Free Metrics via Atomics

**Why:** SPEC §10 sets a < 3% bonding overhead target. Metric updates must not allocate, lock, or branch-mispredict on the hot path.

**Code Sketch:**

```rust
// crates/desmos-core/src/metrics.rs
pub struct LinkMetrics {
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub packets_rx: AtomicU64,
    pub rtt_ewma_us: AtomicU32,
}
// Hot path: metrics.bytes_tx.fetch_add(len as u64, Ordering::Relaxed)
// Snapshot path (web UI / status): .load(Ordering::Relaxed)
```

---

## 3. Project Structure

### 3.1 Directory Layout

> **Root = CWD** (`/path/to/desmos`). Planning docs (`SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`, `BRANDING.md`, `PROMPT.md`) live at the CWD root and must not be moved. `docs/` is reserved for runtime project docs.

```
.                                       # CWD — project root
├── Cargo.toml                          # workspace root manifest
├── Cargo.lock                          # committed (binary project)
├── rust-toolchain.toml                 # MSRV pin (channel = "1.75.0")
├── rustfmt.toml                        # formatting rules
├── clippy.toml                         # clippy lints config
├── deny.toml                           # cargo-deny policy: 5-crate allow-list
├── LICENSE                             # MIT
├── README.md                           # project overview (see BRANDING.md)
├── CHANGELOG.md                        # keepachangelog.com format
├── SPECIFICATION.md                    # (this planning set)
├── IMPLEMENTATION.md                   # (this file)
├── TASKS.md                            # (this planning set)
├── BRANDING.md                         # (this planning set)
├── PROMPT.md                           # (this planning set)
├── prd.md                              # original requirements (preserved)
│
├── crates/
│   ├── desmos-proto/                   # Wire format, crypto, handshake (pure logic)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # public re-exports
│   │       ├── wire.rs                 # DWP header codec (16-byte binary)
│   │       ├── packet.rs               # PacketBuf, PacketMeta types
│   │       ├── types.rs                # SessionId, InterfaceId, Seq, Timestamp
│   │       ├── flags.rs                # FIN / ACK / FRAG / REDUNDANT / PRIORITY
│   │       ├── handshake/
│   │       │   ├── mod.rs              # Noise IK state machine orchestrator
│   │       │   ├── noise.rs            # Noise IK pattern primitives (ring-backed)
│   │       │   └── cookie.rs           # Anti-amplification cookie
│   │       ├── crypto/
│   │       │   ├── mod.rs              # AEAD / KEM / HASH wrappers
│   │       │   ├── aead.rs             # ChaCha20-Poly1305 via ring
│   │       │   ├── x25519.rs           # X25519 via ring
│   │       │   ├── hkdf.rs             # HKDF-BLAKE3
│   │       │   └── blake3.rs           # BLAKE3 helpers
│   │       ├── antireplay.rs           # Sliding bitmap (128-bit window)
│   │       └── errors.rs
│   │   └── tests/                      # proptest for codec round-trip
│   │
│   ├── desmos-rt/                      # Async runtime: event loop + TUN + sockets
│   │   ├── Cargo.toml
│   │   ├── build.rs                    # platform detection (cfg gating)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── reactor.rs              # Reactor trait
│   │       ├── event.rs                # Event, Token, Tag
│   │       ├── timer.rs                # Timer wheel (hierarchical, 32 slots × 4 levels)
│   │       ├── ring.rs                 # SpscRing + MpscRing
│   │       ├── tun.rs                  # Tun trait
│   │       ├── socket.rs               # UdpSocket wrapper over socket2
│   │       ├── linux/
│   │       │   ├── mod.rs
│   │       │   ├── reactor.rs          # epoll backend
│   │       │   ├── tun.rs              # /dev/net/tun ioctl TUNSETIFF
│   │       │   └── bind_device.rs      # SO_BINDTODEVICE wrapper
│   │       ├── bsd/
│   │       │   ├── mod.rs              # shared kqueue base
│   │       │   ├── reactor.rs          # kqueue + kevent
│   │       │   ├── macos_tun.rs        # utun via PF_SYSTEM
│   │       │   └── freebsd_tun.rs      # /dev/tunN
│   │       ├── windows/
│   │       │   ├── mod.rs
│   │       │   ├── reactor.rs          # IOCP
│   │       │   └── tun.rs              # wintun-rs wrapper
│   │       └── priv_drop/
│   │           ├── mod.rs              # Privileged / Unprivileged typestate
│   │           ├── linux.rs            # setresuid + seccomp-bpf
│   │           ├── freebsd.rs          # pledge + unveil
│   │           └── macos.rs            # sandbox_init
│   │
│   ├── desmos-core/                    # Domain: bonding, sessions, config, logs
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config/
│   │       │   ├── mod.rs              # Config struct + validation
│   │       │   ├── schema.rs           # TOML subset parser (hand-rolled)
│   │       │   ├── lexer.rs            # Tokenizer for TOML subset
│   │       │   └── diff.rs             # Config hot-reload diff
│   │       ├── log/
│   │       │   ├── mod.rs              # macro-based structured logger
│   │       │   ├── ring.rs             # in-memory bounded ring buffer
│   │       │   └── sink.rs             # stderr / file / broadcast sinks
│   │       ├── session/
│   │       │   ├── mod.rs              # Session<State> typestate
│   │       │   ├── manager.rs          # Session table + lookup
│   │       │   ├── rekey.rs            # rekey scheduler + state transition
│   │       │   └── keepalive.rs
│   │       ├── bonding/
│   │       │   ├── mod.rs              # Engine orchestrator
│   │       │   ├── strategy.rs         # BondingStrategy trait + 4 impls
│   │       │   ├── probe.rs            # Link quality probe scheduler
│   │       │   ├── reorder.rs          # Reorder buffer + gap timeout
│   │       │   ├── link_state.rs       # State machine (Healthy/Probation/Degraded/Dead)
│   │       │   └── score.rs            # Link scoring function
│   │       ├── pipeline/
│   │       │   ├── mod.rs
│   │       │   ├── outbound.rs         # TUN→schedule→crypt→UDP
│   │       │   └── inbound.rs          # UDP→decrypt→reorder→TUN
│   │       ├── net/
│   │       │   ├── mod.rs              # interface enum + monitoring
│   │       │   ├── iface.rs            # NetworkInterface discovery
│   │       │   ├── stun.rs             # STUN client (RFC 5389 subset)
│   │       │   └── dns.rs              # Minimal UDP DNS resolver
│   │       ├── auth/
│   │       │   ├── mod.rs              # Authenticator trait
│   │       │   ├── psk.rs
│   │       │   ├── pubkey.rs
│   │       │   ├── totp.rs             # RFC 6238 (hand-rolled)
│   │       │   └── mtls.rs             # minimal TLS 1.3 client cert verify
│   │       ├── server/
│   │       │   ├── mod.rs              # multi-client listener
│   │       │   ├── nat.rs              # iptables / pf / netsh NAT setup
│   │       │   ├── ratelimit.rs        # token bucket per IP
│   │       │   └── clients.rs          # client session table
│   │       ├── p2p/
│   │       │   ├── mod.rs
│   │       │   ├── holepunch.rs
│   │       │   └── relay.rs            # fallback through Desmos relay
│   │       ├── ports.rs                # Tun / Reactor / Socket traits (re-exports)
│   │       ├── metrics.rs              # atomic counters
│   │       ├── broadcast.rs            # Broadcast<T> for WebSocket fan-out
│   │       └── errors.rs
│   │
│   ├── desmos-http/                    # Hand-rolled HTTP/1.1 + WebSocket + JSON
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs               # listener + connection loop
│   │       ├── request.rs              # request parser (zero-alloc for headers)
│   │       ├── response.rs             # response builder
│   │       ├── headers.rs              # typed header wrappers
│   │       ├── method.rs
│   │       ├── router.rs               # path-based + method-based
│   │       ├── json.rs                 # JSON encoder + decoder (subset: no deep nesting > 32)
│   │       ├── basic_auth.rs           # HTTP Basic + Argon2 verification
│   │       ├── websocket/
│   │       │   ├── mod.rs              # upgrade + framing
│   │       │   ├── frame.rs            # RFC 6455 frame codec
│   │       │   └── handshake.rs
│   │       └── errors.rs
│   │
│   ├── desmos-webui/                   # REST handlers + embedded React SPA
│   │   ├── Cargo.toml
│   │   ├── build.rs                    # runs `npm ci && npm run build` on web/
│   │   ├── web/                        # Vite + React project (not compiled by Cargo)
│   │   │   ├── package.json
│   │   │   ├── vite.config.ts
│   │   │   ├── tsconfig.json
│   │   │   ├── index.html
│   │   │   ├── eslint.config.js
│   │   │   └── src/
│   │   │       ├── main.tsx
│   │   │       ├── app.tsx
│   │   │       ├── api.ts              # fetch wrappers + WebSocket client
│   │   │       ├── pages/
│   │   │       │   ├── Dashboard.tsx
│   │   │       │   ├── Interfaces.tsx
│   │   │       │   ├── Bonding.tsx
│   │   │       │   ├── Connections.tsx
│   │   │       │   ├── Logs.tsx
│   │   │       │   └── Settings.tsx
│   │   │       ├── components/
│   │   │       │   ├── ThroughputChart.tsx
│   │   │       │   ├── InterfaceTable.tsx
│   │   │       │   ├── StrategyDropdown.tsx
│   │   │       │   └── LogStream.tsx
│   │   │       └── styles/
│   │   │           ├── tokens.css       # design tokens → see BRANDING.md
│   │   │           └── global.css
│   │   └── src/
│   │       ├── lib.rs                  # start(), stop()
│   │       ├── embed.rs                # include_dir!("web/dist") + static serve
│   │       ├── routes.rs               # REST route table
│   │       ├── handlers/
│   │       │   ├── mod.rs
│   │       │   ├── status.rs
│   │       │   ├── interfaces.rs
│   │       │   ├── bonding.rs
│   │       │   ├── stats.rs            # JSON + Prometheus dual-format
│   │       │   ├── clients.rs
│   │       │   ├── config.rs
│   │       │   ├── logs.rs
│   │       │   └── ws.rs               # stats + log WS endpoints
│   │       ├── dto.rs                  # response shapes
│   │       ├── prometheus.rs           # text-format encoder
│   │       └── auth.rs                 # Argon2id verifier wrapper
│   │
│   ├── desmos-cli/                     # CLI argument parser + subcommand dispatch
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── parser.rs               # arg parser (long/short/--)
│   │       ├── dispatch.rs             # Dispatcher + Command trait
│   │       ├── output.rs               # colored + JSON output modes
│   │       ├── commands/
│   │       │   ├── mod.rs
│   │       │   ├── up.rs
│   │       │   ├── down.rs
│   │       │   ├── status.rs
│   │       │   ├── interfaces.rs
│   │       │   ├── keygen.rs
│   │       │   ├── config.rs
│   │       │   ├── webui.rs
│   │       │   ├── bonding.rs
│   │       │   ├── clients.rs
│   │       │   └── stats.rs
│   │       └── errors.rs
│   │
│   └── desmos/                         # Binary crate — wires everything
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                 # dispatch to desmos-cli
│
├── packaging/
│   ├── linux/
│   │   ├── debian/                     # deb build files
│   │   ├── rpm/                        # rpm spec
│   │   ├── appimage/                   # AppImage recipe
│   │   └── systemd/
│   │       └── desmos.service
│   ├── macos/
│   │   ├── homebrew/                   # formula template
│   │   └── pkg/                        # .pkg postinstall
│   ├── windows/
│   │   ├── wix/                        # WiX MSI sources
│   │   └── service/                    # Windows Service wrapper config
│   ├── freebsd/
│   │   └── pkg/                        # FreeBSD pkg manifest
│   ├── pfsense/
│   │   └── pkg-plist.xml
│   └── openwrt/
│       ├── Makefile                    # OpenWrt build recipe
│       ├── files/
│       │   ├── etc/config/desmos
│       │   └── etc/init.d/desmos
│       └── luci/                       # luci-app-desmos
│
├── config/
│   └── desmos.toml.example             # fully commented example config
│
├── docs/                               # runtime project docs
│   ├── architecture.md
│   ├── protocol.md                     # DWP wire format reference
│   ├── cli.md                          # CLI reference
│   ├── webui.md
│   └── adr/                            # architecture decision records
│
├── tests/                              # workspace-level integration tests
│   ├── e2e/
│   │   ├── client_server.rs            # veth pair client↔server roundtrip
│   │   ├── multi_iface.rs              # 3-interface bonding with tc netem
│   │   └── failover.rs                 # bring interface down mid-transfer
│   └── common/
│       └── mod.rs                      # test harness helpers
│
├── benches/
│   ├── bonding.rs                      # criterion benches for scheduler hot path
│   ├── crypto.rs                       # AEAD throughput
│   └── reorder.rs
│
├── scripts/
│   ├── gen-keypair.sh
│   ├── build-all-targets.sh
│   └── release.sh
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                      # lint + test + build (Tier 1 matrix)
    │   ├── release.yml                 # tagged release: build all targets + publish
    │   ├── openwrt.yml                 # Tier 2 cross-compile (Phase 6+)
    │   └── security.yml                # cargo-audit + cargo-deny
    └── ISSUE_TEMPLATE/
        ├── bug_report.md
        └── feature_request.md
```

**Structural philosophy:**

- **Crate boundaries = layering boundaries.** Cargo enforces the dependency DAG at compile time; we cannot accidentally pull `desmos-http` into `desmos-proto`.
- **`desmos-proto` is I/O-free.** It has no OS dependency and compiles in `#![no_std] + alloc` mode, making it portable and property-testable.
- **`desmos-rt` is the only crate with `unsafe`.** All syscalls, FFI, and raw pointer work are here. Review concentration.
- **Tests co-located with modules** (Rust convention) for unit tests, plus workspace-level `tests/e2e/` for integration.
- **`packaging/` is an OS artifact tree**, not compiled by Cargo.

### 3.2 Module Breakdown

| Crate             | Responsibility                                                                                  | Depends On                                            |
|-------------------|--------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| `desmos-proto`    | DWP wire format, Noise IK handshake, AEAD wrappers, anti-replay window. Pure logic, no I/O.     | `ring`, `blake3`                                       |
| `desmos-rt`       | Event loop, TUN trait + backends, UDP sockets, timer wheel, ring buffers, privilege drop.       | `socket2`, `wintun` (Windows only)                    |
| `desmos-core`     | Bonding engine, session manager, config, logging, server, P2P, auth, pipelines, metrics.       | `desmos-proto`, `desmos-rt`                           |
| `desmos-http`     | Hand-rolled HTTP/1.1 server, WebSocket, JSON codec, Basic Auth.                                 | `desmos-rt`, `argon2`                                 |
| `desmos-webui`    | REST handlers, embedded React SPA, Prometheus stats format, `build.rs` frontend build.         | `desmos-core`, `desmos-http`                          |
| `desmos-cli`      | CLI parser, subcommand dispatch, colored/JSON output.                                          | `desmos-core`                                         |
| `desmos`          | Binary entry point. Parses args, loads config, dispatches to CLI, runs main loop.              | `desmos-cli`, `desmos-webui`, `desmos-core`           |

### 3.3 Module Dependency Graph

```
                                 +-------------+
                                 |    ring     |
                                 |   blake3    |
                                 +------+------+
                                        |
                                        v
+------------+   +-------------+   +----+-----------+
|  socket2   |   |   wintun    |   |  desmos-proto  |
+-----+------+   +------+------+   +----+-----------+
      |                 |               |
      v                 v               |
+-----+-----------------+-----+         |
|         desmos-rt          |          |
+------+---------------------+          |
       |                                |
       |           +--------------------+
       |           |
       v           v
     +-+-----------+----+       +-----------+
     |    desmos-core   |<------+   argon2  |
     +----+---+---------+       +-----+-----+
          |   |                       |
          |   |   +-------------------+
          |   |   |
          |   v   v
          | +-+---+------+
          | | desmos-http |
          | +------+------+
          |        |
          v        v
     +----+--------+----+
     |  desmos-webui    |
     +--------+---------+
              |
              |    +-------------+
              |    | desmos-cli  |
              |    +------+------+
              |           |
              v           v
            +-+-----------+-+
            |    desmos     |  (binary)
            +---------------+
```

No cycles. `desmos-proto` and `desmos-rt` are leaves at the bottom of the DAG. `desmos-core` is the hub. Web and CLI compose on top.

---

## 4. Data Layer

Desmos has no database. The data layer covers **wire protocol codec**, **in-memory session/link tables**, and **on-disk config + keys**.

### 4.1 DWP Wire Format Codec

Exact binary layout from SPEC §3.1 of the PRD (mirrored here for convenience):

```
Offset  Size  Field
 0      0.5B  version (4 bits) | type (4 bits)
 1      1B    flags
 2      2B    session_id      (big-endian u16)
 4      4B    sequence        (big-endian u32)
 8      4B    timestamp_us    (big-endian u32)
12      2B    payload_len     (big-endian u16)
14      1B    interface_id
15      1B    reserved
16      N     encrypted payload
16+N   16B    AEAD auth tag (128 bits)
```

**Codec signature:**

```rust
// crates/desmos-proto/src/wire.rs
pub struct Header {
    pub version: u8,
    pub ptype: PacketType,
    pub flags: Flags,
    pub session_id: SessionId,
    pub seq: u32,
    pub timestamp_us: u32,
    pub payload_len: u16,
    pub interface_id: u8,
}

impl Header {
    pub const SIZE: usize = 16;
    pub fn encode(&self, out: &mut [u8; 16]);
    pub fn decode(buf: &[u8]) -> Result<Self, WireError>;
}
```

`proptest` verifies `encode(decode(x)) == x` for all random valid headers.

### 4.2 In-Memory Session Table

| Structure            | Type                                          | Concurrency                         |
|----------------------|-----------------------------------------------|-------------------------------------|
| `SessionTable`       | `RwLock<HashMap<SessionId, Arc<SessionSlot>>>`| Read-heavy; RwLock on manager.      |
| `SessionSlot`        | `Mutex<Session<AnyState>>`                    | Per-session fine-grained lock.      |
| `LinkTable`          | `ArcSwap<Vec<Arc<Link>>>`                     | Hot-swap on interface change.       |
| `ReorderBuffer`      | Per-session `BTreeMap<u32, PacketBuf>` with gap timer | Single-threaded per session (inbound pipeline). |
| `AntiReplayWindow`   | 128-bit sliding bitmap, single writer         | Single-threaded per session (inbound pipeline). |

**Note:** `ArcSwap` is a pattern, not the `arc-swap` crate — we implement the two-operation atomic swap by hand using `AtomicPtr` + epoch-based reclamation (or a simple `RwLock<Arc<_>>` if profiling shows lock contention is negligible).

### 4.3 Configuration Storage

- **Format:** TOML subset (tables, arrays, inline strings, numbers, booleans, arrays of tables). No dotted keys in value position, no inline tables, no multi-line literal strings.
- **Parser:** Single-pass recursive descent in `desmos-core::config::schema`. Hand-rolled, ~600 LOC target.
- **Schema validation:** After parsing into `Value`, the schema module walks into a strongly-typed `Config` struct and returns the first validation error with `path.to.field: reason`.
- **Hot reload:** `PUT /api/v1/config` passes the new TOML text to the parser → validator → diff → apply. Fields that cannot be hot-reloaded (e.g., listening port) reject with a typed error.

### 4.4 Key Material Storage

- Static private keys: `/etc/desmos/server.key`, `~/.config/desmos/client.key`. Raw 32-byte binary. `0600`, root-owned (root) / user-owned (client) at rest.
- Public keys: base64-encoded in config files. No central keystore.
- Ephemeral session keys: never touch disk. Live in `Session<Established>` state, zeroized on drop via `zeroize`-style manual wipe (we don't pull in `zeroize` crate — write a local `secure_zero` helper using volatile writes).

---

## 5. API Implementation

### 5.1 Route Structure

| Method | Path                               | Handler                         | Middleware            | Auth |
|--------|------------------------------------|---------------------------------|-----------------------|------|
| GET    | `/api/v1/status`                   | `handlers::status::get`         | `basic_auth`          | Yes  |
| GET    | `/api/v1/interfaces`               | `handlers::interfaces::list`    | `basic_auth`          | Yes  |
| PUT    | `/api/v1/interfaces/:name`         | `handlers::interfaces::update`  | `basic_auth`          | Yes  |
| GET    | `/api/v1/bonding`                  | `handlers::bonding::get`        | `basic_auth`          | Yes  |
| PUT    | `/api/v1/bonding/strategy`         | `handlers::bonding::set`        | `basic_auth`          | Yes  |
| GET    | `/api/v1/stats`                    | `handlers::stats::get`          | `basic_auth`, `fmt`   | Yes  |
| GET    | `/api/v1/clients`                  | `handlers::clients::list`       | `basic_auth`          | Yes  |
| DELETE | `/api/v1/clients/:session_id`      | `handlers::clients::kick`       | `basic_auth`          | Yes  |
| GET    | `/api/v1/config`                   | `handlers::config::get`         | `basic_auth`          | Yes  |
| PUT    | `/api/v1/config`                   | `handlers::config::put`         | `basic_auth`          | Yes  |
| GET    | `/api/v1/logs`                     | `handlers::logs::list`          | `basic_auth`          | Yes  |
| GET    | `/api/v1/health`                   | `handlers::health`              | —                     | No   |
| GET    | `/api/v1/ws/stats`                 | `handlers::ws::stats`           | `basic_auth`, upgrade | Yes  |
| GET    | `/api/v1/ws/logs`                  | `handlers::ws::logs`            | `basic_auth`, upgrade | Yes  |
| GET    | `/`                                | `embed::spa_root`               | `basic_auth`          | Yes  |
| GET    | `/static/*`                        | `embed::spa_static`             | `basic_auth`          | Yes  |

### 5.2 Request / Response Contract

**Success:**

```json
{
  "data": {
    "tunnel_state": "up",
    "session_id": 17,
    "uptime_s": 42310,
    "strategy": "latency-adaptive",
    "interfaces": [{ "name": "eth0", "state": "healthy", "rtt_us": 4210 }]
  },
  "meta": { "request_id": "0x1a2b3c4d", "generated_at_us": 1744291200123456 }
}
```

**Error:**

```json
{
  "error": {
    "code": "interface_not_found",
    "message": "No configured interface named 'eth5'",
    "details": { "name": "eth5" }
  },
  "meta": { "request_id": "0x1a2b3c4d" }
}
```

**Prometheus (when `?format=prometheus`):**

```
# HELP desmos_bytes_tx Total bytes transmitted through the tunnel
# TYPE desmos_bytes_tx counter
desmos_bytes_tx{interface="eth0"} 1234567890
desmos_bytes_tx{interface="wlan0"}  987654321

# HELP desmos_link_rtt_us Current RTT in microseconds
# TYPE desmos_link_rtt_us gauge
desmos_link_rtt_us{interface="eth0"} 4210
```

### 5.3 Validation Approach

- **Request parsing:** `desmos-http::request` rejects malformed HTTP at the wire level.
- **JSON decoding:** hand-rolled decoder returns typed errors on the first invalid character or schema violation.
- **Business validation:** handlers call into `desmos-core::config::schema` or typed setters that return `Result<(), ValidationError>`.
- Errors are converted to the error envelope by a single `IntoErrorResponse` adapter.

### 5.4 Authentication Flow (Web UI)

```
1. Client sends GET /api/v1/status with `Authorization: Basic <b64>`
2. basic_auth middleware decodes -> (user, pass)
3. Compares user against [webui].username
4. argon2::verify(pass, stored_hash) in constant time
5. On success -> proceeds to handler; on failure -> 401 + WWW-Authenticate header
6. Rate limiter tracks failed attempts per source IP (see §5.5)
```

### 5.5 Rate Limiting

- Per-source IP token bucket in `desmos-core::server::ratelimit` (reused by the Web UI layer).
- Web UI bucket: 100 tokens, refills at 10/s.
- Handshake bucket (server role): 5 tokens, refills at 0.5/s per source IP, cookie-based anti-amplification on top.

---

## 6. Frontend Implementation

### 6.1 Component Architecture

- **Pages** are route-level containers that own data-fetching logic via custom hooks.
- **Components** are presentational, receive props, no direct API calls.
- **Hooks** (`useStatus`, `useInterfaces`, `useWsStream`) encapsulate REST and WebSocket logic.

```
src/
├── pages/           # route containers
├── components/      # presentational
├── hooks/           # data fetching
├── api.ts           # fetch + WebSocket wrappers
└── styles/          # design tokens + global
```

### 6.2 State Management

- **No Redux / Zustand / React Query.** Local `useState` + `useReducer` only.
- **Data fetching:** plain `fetch` wrapped in a typed client (`api.ts`). A tiny custom hook `useFetch<T>(url, deps)` handles loading/error/data states.
- **Real-time streams:** `useWsStream<T>(path)` opens a WebSocket on mount, parses JSON frames, and exposes the latest value + history.

Rationale: the app has 6 pages and shallow state. Global state would be premature.

### 6.3 Routing

Simple hash routing (`#/dashboard`, `#/interfaces`, etc.) in ~30 LOC. No `react-router` dependency. The root `App` component inspects `window.location.hash` and renders the matching page.

### 6.4 Styling

- Plain CSS with CSS custom properties (design tokens). See BRANDING.md for the token catalog.
- Dark mode default; `[data-theme="light"]` override on `<html>`.
- No Tailwind, no styled-components. Keeps the Vite bundle small (< 150 KB target).

---

## 7. Error Handling Strategy

### 7.1 Error Classification

| Category          | Example                                   | HTTP Code | Logged As | User Sees                         |
|-------------------|-------------------------------------------|-----------|-----------|-----------------------------------|
| Wire format       | Malformed DWP header                      | —         | Debug     | Drop, metric increment            |
| Crypto            | AEAD tag mismatch                         | —         | Warn      | Drop, metric increment            |
| Replay            | Sequence in anti-replay window            | —         | Debug     | Drop, metric increment            |
| Config validation | Invalid TOML or schema violation          | 400       | Info      | Field-level error message         |
| Auth (Web UI)     | Wrong password                            | 401       | Warn      | "Invalid credentials"             |
| Auth (tunnel)     | PSK mismatch, bad signature               | —         | Warn      | Handshake rejected, error logged  |
| Not found         | Unknown interface                         | 404       | Debug     | "interface_not_found"             |
| Rate limited      | Exceeded Web UI bucket                    | 429       | Info      | "Too many requests"               |
| Internal          | Thread panic, syscall EIO                 | 500       | Error     | "Internal error, check logs"      |
| Platform          | TUN create failed, missing CAP_NET_ADMIN  | —         | Error     | Startup exit with hint            |

### 7.2 Error Propagation

All errors are typed enums per crate:

```rust
#[derive(Debug)]
pub enum CoreError {
    Config(config::Error),
    Session(session::Error),
    Auth(auth::Error),
    Bonding(bonding::Error),
    Net(net::Error),
    Rt(rt::Error),
}
```

Errors flow `rt → proto → core → http → webui` via `From` impls. The CLI and Web UI layers render them into user-facing messages or HTTP error envelopes.

---

## 8. Configuration

### 8.1 Config Sources

Priority (high → low):

1. CLI flags (`-c <path>`, `-v`, `--listen`, etc.)
2. Environment variables (`DESMOS_CONFIG`, `DESMOS_LOG_LEVEL`)
3. Config file at the standard path per OS
4. Built-in defaults

### 8.2 Config Schema (abbreviated; see `config/desmos.toml.example` for the full file)

| Key                            | Type    | Default            | Env Var              | Description                                   |
|--------------------------------|---------|--------------------|----------------------|-----------------------------------------------|
| `general.mode`                 | enum    | —                  | `DESMOS_MODE`        | `client` / `server` / `p2p`                   |
| `general.log_level`            | enum    | `info`             | `DESMOS_LOG_LEVEL`   | `trace` / `debug` / `info` / `warn` / `error` |
| `general.tunnel_mtu`           | u32     | 1400               | —                    | Tunnel MTU                                    |
| `server.listen`                | addr    | `0.0.0.0:4900`     | —                    | UDP listen endpoint                           |
| `server.max_clients`           | u32     | 100                | —                    | Session cap                                   |
| `server.auth.method`           | enum    | `psk`              | —                    | `psk` / `pubkey` / `totp` / `mtls`            |
| `client.server`                | string  | —                  | —                    | `host:port` of the remote                     |
| `client.bonding_strategy`      | enum    | `latency-adaptive` | —                    | Bonding strategy                              |
| `client.reorder_window_ms`     | u32     | 50                 | —                    | Reorder buffer depth                          |
| `client.dns_leak_protection`   | bool    | true               | —                    | Route DNS through tunnel                      |
| `client.interfaces`            | array   | —                  | —                    | Per-interface config rows                     |
| `webui.enabled`                | bool    | true               | —                    | Enable embedded Web UI                        |
| `webui.listen`                 | addr    | `127.0.0.1:8080`   | —                    | Web UI bind address                           |
| `webui.username`               | string  | `admin`            | —                    | Web UI username                               |
| `webui.password_hash`          | string  | —                  | —                    | Argon2id hash                                 |

---

## 9. Testing Strategy

### 9.1 Test Pyramid

| Level       | Tool                    | Scope                                                                     | Target            |
|-------------|-------------------------|---------------------------------------------------------------------------|-------------------|
| Unit        | `cargo test`            | Per-module functions: codec, crypto, parser, reorder buffer, state machines | ≥ 85% lines      |
| Property    | `proptest`              | DWP codec round-trip, anti-replay bitmap invariants, TOML parser          | 1000 cases / test |
| Integration | `cargo test` workspace  | Full tunnel client↔server on localhost veth pair                          | All user stories  |
| Network sim | `tests/e2e/` + `tc netem` | Packet loss, RTT variance, reordering                                    | Bonding scenarios |
| Benchmarks  | `criterion`             | AEAD throughput, scheduler hot path, reorder buffer                       | Regression gate   |
| Frontend    | `vitest` + `playwright` | Component render + one happy-path e2e (dashboard loads, shows data)       | Core screens      |

### 9.2 Test Patterns

- **Factories:** `test_helpers::make_session()`, `make_link()`, `make_probe_sample()` build valid fixtures.
- **In-memory backends:** `InMemoryTun`, `InMemoryReactor` implement the trait interfaces for deterministic unit tests without touching the OS.
- **Deterministic clocks:** `Clock` trait injected into modules that read time; `TestClock` advances on demand.

### 9.3 CI Pipeline (Phase 1: Linux; Phase 6: expand to Tier 1)

```
Push/PR -> fmt -> clippy -> build -> unit tests -> integration tests -> proptest -> e2e (Linux veth) -> cache artifacts
```

Matrix at launch: `ubuntu-latest x86_64-unknown-linux-musl`, `macos-14 x86_64-apple-darwin` + `aarch64-apple-darwin`, `windows-latest x86_64-pc-windows-msvc`, `freebsd` (via cross-rs + QEMU). OpenWrt MIPS/ARM targets join at Phase 6.

---

## 10. Security Implementation

### 10.1 Input Sanitization Points

- **Wire boundary:** `desmos-proto::wire::Header::decode` rejects unknown version / type / bad lengths.
- **Crypto boundary:** AEAD tag verification is constant-time via `ring`; any tamper drops the packet silently.
- **Config boundary:** TOML parser + schema validator reject malformed fields before anything is committed.
- **HTTP boundary:** request parser enforces method, header, and body size caps.
- **CLI boundary:** arg parser rejects unknown flags; `config validate` subcommand lets ops dry-run.

### 10.2 Secret Management

- Static private keys: `0600` files, root-owned on servers.
- Web UI password: Argon2id hash only — plaintext never stored.
- No secrets in logs: the logger filters `private_key`, `psk`, `password` field names and replaces values with `***`.
- No secrets in error envelopes: the REST API redacts secrets from returned config (`GET /api/v1/config` returns `"psk": "***"`).

### 10.3 Security Headers (Web UI)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Strict-Transport-Security: (only when binding to non-localhost)
Cache-Control: no-store (API responses)
```

---

## 11. Deployment

### 11.1 Build Commands

```bash
# Tier 1 release build (Linux x86_64 musl static)
cargo build --release --target x86_64-unknown-linux-musl

# macOS universal
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create target/x86_64-apple-darwin/release/desmos \
              target/aarch64-apple-darwin/release/desmos \
        -output target/desmos-macos-universal

# Windows MSVC
cargo build --release --target x86_64-pc-windows-msvc

# FreeBSD (cross via cross-rs + QEMU)
cross build --release --target x86_64-unknown-freebsd
```

### 11.2 Dockerfile (server image, Linux only)

```dockerfile
# Build stage
FROM rust:1.75-slim AS build
WORKDIR /src
RUN apt-get update && apt-get install -y musl-tools nodejs npm && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p desmos

# Runtime stage
FROM gcr.io/distroless/static-debian12
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/desmos /usr/local/bin/desmos
EXPOSE 4900/udp 8080/tcp
ENTRYPOINT ["/usr/local/bin/desmos", "up", "-c", "/etc/desmos/desmos.toml"]
```

### 11.3 Health Check

`GET /api/v1/health` (unauthenticated) returns:

```json
{ "status": "ok", "version": "1.0.0", "tunnel_state": "up", "uptime_s": 4210 }
```

HTTP 200 when tunnel is up or in `connecting` state, 503 when tunnel is down or degraded beyond threshold.

### 11.4 Monitoring

- **Logging:** structured JSON lines to stderr by default, optional file sink. Fields: `ts`, `level`, `target`, `msg`, and any structured kv pairs.
- **Metrics:** `GET /api/v1/stats?format=prometheus` for scraping.
- **Alerting:** out of scope for v1.0 — operators wire Prometheus/Grafana/Alertmanager themselves.

---

## 12. Development Workflow

### 12.1 Local Setup

```bash
# Prereqs: Rust 1.75 (pinned), Node 20+, Linux/macOS dev host
git clone <repo> desmos && cd desmos
rustup show  # reads rust-toolchain.toml
cargo check --workspace

# Web UI dev
cd crates/desmos-webui/web
npm ci
npm run dev        # Vite dev server on :5173
cd ../../..

# Run a local server
cp config/desmos.toml.example ./desmos-dev.toml
sudo ./target/debug/desmos up -c ./desmos-dev.toml
```

### 12.2 Code Standards

- `rustfmt.toml`: 100-column soft limit, trailing commas, one import per line.
- `clippy.toml`: `msrv = "1.75.0"`, `disallowed_types = ["std::sync::Mutex"]` (prefer parking-lot... wait, that's a crate. Use `std::sync::Mutex` but mark hot-path candidates with `#[allow]` + comment explaining why.)
- `cargo-deny` policy enforcing the 5-crate allow-list as part of CI.
- `cargo fmt --all --check` + `cargo clippy --workspace --all-targets -- -D warnings` gate CI.
- Frontend: `eslint` + `prettier`, runs only in `crates/desmos-webui/web/`.

### 12.3 Git Workflow

- `main` is always green. All work via feature branches.
- Branch naming: `feat/<scope>`, `fix/<scope>`, `chore/<scope>`, `docs/<scope>`.
- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`).
- Squash merge by default to keep `main` history linear.
- Every PR gates on: fmt, clippy, unit tests, integration tests, build of all Tier 1 targets, `cargo-deny`.

---

## Quality Checklist

- [x] Every tech choice has a project-specific rationale.
- [x] Directory structure is file-level complete.
- [x] Module breakdown covers every SPEC §3 feature group.
- [x] Design patterns include code sketches in Rust.
- [x] Wire codec signature captures full DWP.
- [x] API routes cover every SPEC §6.2 endpoint.
- [x] Error handling table covers wire, crypto, config, HTTP, platform errors.
- [x] Configuration is documented with defaults and env vars.
- [x] Testing strategy names concrete tools (`proptest`, `criterion`, `insta`, `vitest`, `playwright`).
- [x] Cross-references to SPECIFICATION.md sections are present.
- [x] A developer with SPEC + IMPL could start TASK #1 immediately.
