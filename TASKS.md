# Desmos — Tasks

> Ordered work breakdown derived from `IMPLEMENTATION.md`. Execute sequentially. Each task is self-contained, names its exact files, and is sized for a single Claude Code session (2-8 hours). Phase numbering mirrors PRD §12, with a new **Phase 0** for scaffolding.

## Summary

| Metric            | Value                          |
|-------------------|--------------------------------|
| Total Tasks       | 58                             |
| Phases            | 9 (Phase 0 + PRD Phases 1-7 + Release) |
| Estimated Effort  | ~26-32 weeks solo, 6-8 weeks with 3 devs |
| Foundation Complete | After Task 6                 |
| First Tunnel      | After Task 13 (Linux, single interface, no encryption) |
| First Encrypted Tunnel | After Task 22 (Noise IK + AEAD) |
| First Bonded Tunnel | After Task 28                 |
| MVP (Linux client+server, all 4 strategies) | After Task 40 |
| P2P Working       | After Task 44                  |
| All Platforms     | After Task 52                  |
| Full Release (v1.0) | After Task 58                 |

---

## Phase 0: Scaffolding

> Establishes the Cargo workspace, toolchain pin, lint configs, CI bootstrap, and empty crates. After this phase: `cargo check --workspace` passes with zero warnings on a blank skeleton.

### Task 1: Workspace Scaffolding

**Create the Cargo workspace skeleton with all 7 crates, toolchain pin, lint configs, and deny policy.**

> **Working directory:** CWD is the project root. Do not create a `desmos/` wrapper subfolder. `SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`, `BRANDING.md`, `PROMPT.md`, `prd.md` already live at the CWD root — leave them untouched.

**Files to create:**
- `Cargo.toml` — workspace root with `[workspace] members = [...]`, shared `[profile.release]`, pinned runtime dep versions
- `rust-toolchain.toml` — `channel = "1.75.0"`, `components = ["rustfmt", "clippy"]`, `targets = [...]`
- `rustfmt.toml` — 100-column soft limit, trailing commas
- `clippy.toml` — `msrv = "1.75.0"`
- `deny.toml` — allow-list: only `ring`, `blake3`, `socket2`, `wintun`, `argon2` (+ dev-deps `proptest`, `criterion`, `insta`)
- `.gitignore` — `target/`, `Cargo.lock` excluded for libraries / included for binaries (committed), `node_modules/`, `dist/`, `.DS_Store`, IDE files
- `LICENSE` — MIT
- `README.md` — minimal stub, name + tagline + "see SPECIFICATION.md"
- `CHANGELOG.md` — empty keepachangelog.com format
- `crates/desmos-proto/Cargo.toml`, `crates/desmos-proto/src/lib.rs` (empty `//!` docstring)
- `crates/desmos-rt/Cargo.toml`, `crates/desmos-rt/src/lib.rs`
- `crates/desmos-core/Cargo.toml`, `crates/desmos-core/src/lib.rs`
- `crates/desmos-http/Cargo.toml`, `crates/desmos-http/src/lib.rs`
- `crates/desmos-webui/Cargo.toml`, `crates/desmos-webui/src/lib.rs`
- `crates/desmos-cli/Cargo.toml`, `crates/desmos-cli/src/lib.rs`
- `crates/desmos/Cargo.toml`, `crates/desmos/src/main.rs` (`fn main() { println!("desmos"); }`)

**Commands to run:**
```bash
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

**Acceptance Criteria:**
- [ ] `cargo check --workspace` succeeds with zero warnings
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo run -p desmos` prints `desmos`
- [ ] `rustup show` confirms the pinned 1.75.0 toolchain is active

**Dependencies:** None
**Effort:** 2-3 hours
**Refs:** IMPLEMENTATION.md §1.1, §3.1

---

### Task 2: Core Error Types & Logging Skeleton

**Define the error taxonomy and a bare-bones structured logger.**

**Files to create:**
- `crates/desmos-core/src/errors.rs` — `CoreError` enum + `Result` alias
- `crates/desmos-core/src/log/mod.rs` — `log!(level, target, msg, k=v)` macro
- `crates/desmos-core/src/log/sink.rs` — stderr line-buffered sink
- `crates/desmos-core/src/log/ring.rs` — bounded ring buffer for Web UI streaming

**Code requirements:**
- Log entries are plain-text by default, JSON when `log.format = "json"` in config (implemented later; keep sink trait extensible).
- Log macro captures `ts_us`, `level`, `target`, `msg`, and zero-or-more key-value pairs.
- Ring buffer capacity: 500 lines default, configurable later.
- Secret-field filter skeleton (`redact_keys: ["psk", "password", "private_key"]`).

**Acceptance Criteria:**
- [ ] Unit test: `log!(info, "tunnel", "up", iface="eth0")` produces a line containing `level=info target=tunnel msg=up iface=eth0`.
- [ ] Unit test: ring buffer wraps at capacity, oldest entry evicted.
- [ ] Secret-field redactor replaces `psk=abc123` with `psk=***`.

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §7, §10.2

---

### Task 3: Hand-Rolled TOML Parser

**Implement a strict TOML subset parser sufficient for the Desmos config schema.**

**Files to create:**
- `crates/desmos-core/src/config/lexer.rs` — tokenizer (keys, strings, numbers, booleans, `[section]`, `[[array]]`)
- `crates/desmos-core/src/config/schema.rs` — recursive-descent parser producing a `Value` tree
- `crates/desmos-core/src/config/mod.rs` — parser entry point, error formatter with `path.to.field` trace

**Supported subset:**
- Tables, arrays of tables, basic strings (no multi-line), integers, floats, booleans, arrays of primitives.
- **Not supported:** inline tables, dotted keys in value position, multi-line literal strings.

**Acceptance Criteria:**
- [ ] Parses the full `config/desmos.toml.example` from IMPLEMENTATION.md §8.2 (stub the file with all fields).
- [ ] Rejects unknown top-level sections with `unknown_section: <name>`.
- [ ] Rejects type mismatches with `type_mismatch: <path>: expected <T>, got <U>`.
- [ ] `proptest` round-trips valid `Value` trees (`parse(encode(v)) == v`) for 1000 random cases.

**Dependencies:** Task 1, Task 2
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §4.3, §8

---

### Task 4: Config Schema Validation

**Turn the parsed `Value` tree into a strongly-typed `Config` struct with full validation.**

**Files to create:**
- `crates/desmos-core/src/config/validate.rs` — `Config::from_value(&Value) -> Result<Config, ValidationError>`
- `config/desmos.toml.example` — fully commented example at the CWD root

**Code requirements:**
- All fields from IMPLEMENTATION.md §8.2 populated with defaults.
- Validation rules: `mode` is one of `client|server|p2p`; `bonding_strategy` is one of 4 names; `interfaces` count 1..8; `listen` parses as `SocketAddr`.
- `webui.password_hash` validated as a parseable Argon2id encoded string (use `argon2` crate).

**Acceptance Criteria:**
- [ ] Parsing `config/desmos.toml.example` produces a `Config` with every field set.
- [ ] Removing a required field yields `missing_field: <path>`.
- [ ] Out-of-range values produce `out_of_range: <path>`.

**Dependencies:** Task 3
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §8, SPECIFICATION.md §5.1

---

### Task 5: Hand-Rolled CLI Parser

**Implement `desmos-cli` argument parser and subcommand dispatcher skeleton.**

**Files to create:**
- `crates/desmos-cli/src/parser.rs` — long/short flag parser, subcommand detection
- `crates/desmos-cli/src/dispatch.rs` — `Command` trait + `Dispatcher`
- `crates/desmos-cli/src/output.rs` — colored vs JSON output modes (no color crate; hand-rolled ANSI)
- `crates/desmos-cli/src/commands/mod.rs` — stubs for `up`, `down`, `status`, `interfaces`, `keygen`, `config`, `webui`, `bonding`, `clients`, `stats`
- `crates/desmos-cli/src/errors.rs`
- `crates/desmos/src/main.rs` — wire `desmos-cli::Dispatcher::dispatch`

**Acceptance Criteria:**
- [ ] `desmos --help` lists all subcommands.
- [ ] `desmos status --json` dispatches to the `status` stub and prints `{}`.
- [ ] Global flags `-c`, `-v`, `-q`, `--no-color`, `--json` are parsed into a `GlobalFlags` struct.
- [ ] Unknown subcommand returns exit code 64 and suggests the closest match (Levenshtein-ish).

**Dependencies:** Task 1, Task 2
**Effort:** 4-6 hours
**Refs:** IMPLEMENTATION.md §2.8, SPECIFICATION.md §3.4

---

### Task 6: CI Bootstrap (Tier 1 Matrix)

**Set up GitHub Actions CI running fmt, clippy, build, and test across all Tier 1 targets.**

**Files to create:**
- `.github/workflows/ci.yml` — matrix: `ubuntu-latest × (x86_64-unknown-linux-musl, x86_64-unknown-linux-gnu, aarch64-unknown-linux-musl via cross)`, `macos-14 × (x86_64-apple-darwin, aarch64-apple-darwin)`, `windows-latest × (x86_64-pc-windows-msvc)`, `ubuntu-latest × (x86_64-unknown-freebsd via cross)`
- `.github/workflows/security.yml` — `cargo-deny check`, `cargo-audit`
- `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`

**CI steps per job:**
```yaml
- checkout
- cache ~/.cargo, target/
- rustup show (pinned toolchain)
- cargo fmt --all --check
- cargo clippy --workspace --all-targets --target ${{ matrix.target }} -- -D warnings
- cargo build --workspace --target ${{ matrix.target }}
- cargo test --workspace --target ${{ matrix.target }}  # host targets only
```

**Acceptance Criteria:**
- [ ] A push to `main` triggers a matrix run on all 7 Tier 1 targets.
- [ ] Every target compiles cleanly.
- [ ] `cargo-deny` enforces the 5-crate runtime allow-list.
- [ ] Build artifacts cached between runs to stay under 10 minutes per job.

**Dependencies:** Task 1-5
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §9.3

---

## Phase 1: Protocol Foundation

> Matches PRD §12 Phase 1 — wire protocol, Linux TUN, UDP sockets, single-interface forward. After this phase: a plaintext packet loops from host A through a TUN device, over UDP, into host B.

### Task 7: DWP Header Codec

**Implement the 16-byte DWP header encode/decode with property tests.**

**Files to create:**
- `crates/desmos-proto/src/wire.rs` — `Header` struct + `encode(&self, &mut [u8; 16])` + `decode(&[u8]) -> Result<Header, WireError>`
- `crates/desmos-proto/src/flags.rs` — `Flags` bitfield (FIN, ACK, FRAG, REDUNDANT, PRIORITY)
- `crates/desmos-proto/src/types.rs` — `SessionId(u16)`, `InterfaceId(u8)`, `Seq(u32)`, `TimestampUs(u32)`
- `crates/desmos-proto/src/errors.rs`
- `crates/desmos-proto/tests/wire_roundtrip.rs` — `proptest` roundtrip

**Acceptance Criteria:**
- [ ] Header encodes to exactly 16 bytes big-endian layout from IMPLEMENTATION.md §4.1.
- [ ] Unknown version rejected with `WireError::UnsupportedVersion`.
- [ ] Payload length > MTU rejected.
- [ ] `proptest` runs 1000 cases: `decode(encode(h)) == h` for every valid `Header`.

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §4.1, PRD §3.1

---

### Task 8: PacketBuf and Zero-Copy Buffer Pool

**Define the packet buffer type used across the pipeline with a simple pool.**

**Files to create:**
- `crates/desmos-proto/src/packet.rs` — `PacketBuf` (owning `Box<[u8]>` with live length), `PacketMeta` (link id, seq, size)
- `crates/desmos-rt/src/pool.rs` — `PacketPool` (preallocated ring of `PacketBuf` with atomic recycle)

**Acceptance Criteria:**
- [ ] `PacketBuf::new(mtu)` allocates a buffer of tunnel MTU + 256 (crypto overhead + header).
- [ ] `PacketPool::acquire` returns an unused buffer or allocates a new one, `release` returns it.
- [ ] Benchmark shows pool hit rate > 99% on a 10k-iteration loop.

**Dependencies:** Task 7
**Effort:** 3 hours
**Refs:** IMPLEMENTATION.md §2.6, §4.1

---

### Task 9: SPSC Ring Buffer

**Implement the lock-free SPSC ring used between pipeline stages.**

**Files to create:**
- `crates/desmos-rt/src/ring.rs` — `SpscRing<T>` with `try_push` / `try_pop` and power-of-two capacity
- `crates/desmos-rt/tests/ring_spsc.rs` — two-thread stress test

**Acceptance Criteria:**
- [ ] Unit test: push 1M items from a producer thread, pop 1M items on consumer thread, order preserved.
- [ ] Cache-padded head/tail (`#[repr(align(64))]`).
- [ ] No `unsafe` outside a commented, audited block.

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §2.6

---

### Task 10: Linux epoll Reactor

**Implement the Linux event-loop backend behind the `Reactor` trait.**

**Files to create:**
- `crates/desmos-rt/src/reactor.rs` — `Reactor` trait, `Event`, `Token`, `Tag`
- `crates/desmos-rt/src/linux/mod.rs`
- `crates/desmos-rt/src/linux/reactor.rs` — `epoll_create1`, `epoll_ctl`, `epoll_wait` via `libc`-free raw FFI (declare syscall numbers locally) or use `syscalls` feature of `libc` (NB: `libc` is part of `std`, allowed)
- `crates/desmos-rt/src/event.rs`

**Note:** `libc` comes with the toolchain and is not counted as an external crate; we can call `libc::syscall`. If the team prefers to avoid even `libc`, declare raw syscall numbers.

**Acceptance Criteria:**
- [ ] Register a UDP socket, block on `poll`, receive a read-ready event when a packet arrives.
- [ ] Register a TUN fd, receive a read-ready event when an IP packet is injected.
- [ ] Deregister cleans up epoll state; no fd leaks under 1000 register/deregister cycles.
- [ ] Test uses a Tokio-free async primitive (direct blocking + helper thread).

**Dependencies:** Task 9
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §2.1, SPECIFICATION.md §4.1

---

### Task 11: Timer Wheel

**Implement a hierarchical timer wheel (4 levels × 32 slots) for keepalives, probes, and rekey.**

**Files to create:**
- `crates/desmos-rt/src/timer.rs` — `TimerWheel`, `Timer`, `TimerHandle`

**Acceptance Criteria:**
- [ ] `schedule(after, callback_id)` + `poll(now)` returns expired callback IDs.
- [ ] 1 ms tick granularity at level 0; 1 s at level 3.
- [ ] Benchmarks: 1M insertions + pops in < 200 ms on modern x86_64.

**Dependencies:** Task 10
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 12: Linux TUN Device

**Create and drop Linux TUN devices via `ioctl(TUNSETIFF)`.**

**Files to create:**
- `crates/desmos-rt/src/tun.rs` — `Tun` trait
- `crates/desmos-rt/src/linux/tun.rs` — `LinuxTun` impl
- `crates/desmos-rt/tests/tun_linux.rs` — integration test (requires `CAP_NET_ADMIN`, `#[ignore]` by default)

**Acceptance Criteria:**
- [ ] `LinuxTun::create("desmos0")` returns a `Tun` usable via `read`/`write`.
- [ ] On `Drop`, the TUN device is removed.
- [ ] Writing an IPv4 packet to the TUN results in the kernel routing it back through the process.

**Dependencies:** Task 10
**Effort:** 4-5 hours
**Refs:** SPECIFICATION.md §4.1

---

### Task 13: UDP Socket with `SO_BINDTODEVICE`

**Wrap `socket2::Socket` with per-interface binding and the reactor integration.**

**Files to create:**
- `crates/desmos-rt/src/socket.rs` — `UdpSocket`, `bind_to_device` helper
- `crates/desmos-rt/src/linux/bind_device.rs` — `SO_BINDTODEVICE` setsockopt

**Acceptance Criteria:**
- [ ] `UdpSocket::bind_on_interface("eth0")` produces a socket that only egresses via `eth0`.
- [ ] Integration test on a two-namespace setup confirms packets exit the chosen interface.
- [ ] Socket integrates with the reactor for non-blocking `recv` / `send`.

**Dependencies:** Task 10, Task 12
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 14: Single-Interface Plaintext Forwarder

**Wire TUN → UDP → TUN loop with no encryption as a smoke test for the runtime layer.**

**Files to create/modify:**
- `crates/desmos-core/src/pipeline/mod.rs`
- `crates/desmos-core/src/pipeline/outbound.rs` — stub that copies TUN bytes into UDP payload with a DWP header (Type=Data, no encryption, zero tag)
- `crates/desmos-core/src/pipeline/inbound.rs` — inverse
- `crates/desmos-cli/src/commands/up.rs` — wire it behind `desmos up --mode plaintext` (hidden dev flag)
- `tests/e2e/plaintext_loopback.rs` — spin up two instances on localhost via veth pair, ping through

**Acceptance Criteria:**
- [ ] `desmos up --mode plaintext` brings up a `desmos0` TUN.
- [ ] `ping 10.200.0.2` from inside the namespace round-trips through the UDP loop.
- [ ] Teardown removes TUN and closes sockets.

**Dependencies:** Task 7, Task 10-13
**Effort:** 5-6 hours
**Refs:** PRD §12 Phase 1 exit criteria

---

## Phase 2: Crypto and Bonding v1

> Matches PRD §12 Phase 2 — Noise IK handshake, ChaCha20-Poly1305 AEAD, session management, Round-Robin bonding, reorder buffer, probing. After this phase: an encrypted, multi-interface tunnel works with the default RR strategy.

### Task 15: Crypto Wrappers

**Wrap `ring` and `blake3` behind Desmos types.**

**Files to create:**
- `crates/desmos-proto/src/crypto/mod.rs`
- `crates/desmos-proto/src/crypto/aead.rs` — `Aead::seal / open` via `ring::aead::ChaCha20Poly1305`
- `crates/desmos-proto/src/crypto/x25519.rs` — keypair gen + DH via `ring::agreement::X25519`
- `crates/desmos-proto/src/crypto/hkdf.rs` — HKDF-BLAKE3
- `crates/desmos-proto/src/crypto/blake3.rs` — hash helpers
- `crates/desmos-proto/tests/aead_roundtrip.rs`

**Acceptance Criteria:**
- [ ] Seal/open round-trip for random plaintext.
- [ ] Wrong key fails open with a typed error.
- [ ] Tamper with the tag fails open.
- [ ] HKDF produces deterministic output against a test vector.

**Dependencies:** Task 1
**Effort:** 4 hours
**Refs:** IMPLEMENTATION.md §2.3, SPECIFICATION.md §8.3

---

### Task 16: Noise IK State Machine

**Implement the Noise IK handshake pattern used by Desmos.**

**Files to create:**
- `crates/desmos-proto/src/handshake/mod.rs` — `HandshakeState`, `HandshakeStep`
- `crates/desmos-proto/src/handshake/noise.rs` — IK-specific state machine (init → resp hello → first transport)
- `crates/desmos-proto/tests/noise_ik.rs`

**Acceptance Criteria:**
- [ ] Two handshake states converge to the same transport keys in < 2 message exchanges.
- [ ] Unknown server static key fails the responder.
- [ ] Test vector matches a reference Noise IK implementation (document the reference used).

**Dependencies:** Task 15
**Effort:** 8 hours
**Refs:** PRD §3.2

---

### Task 17: Session Typestate

**Define `Session<Handshaking|Established|Rekeying|Closed>` and the transition API.**

**Files to create:**
- `crates/desmos-core/src/session/mod.rs` — typestate structs
- `crates/desmos-core/src/session/manager.rs` — `SessionTable`
- `crates/desmos-core/src/session/keepalive.rs` — dead-peer detection
- `crates/desmos-core/src/session/rekey.rs` — rekey scheduling (2^32 pkts or 120 s)

**Acceptance Criteria:**
- [ ] `Session<Handshaking>::advance` consumes self and returns `Session<Established>` on success.
- [ ] `encrypt_data` is only callable on `&Session<Established>` (compile-time verified by a negative test `compile_fail`).
- [ ] Rekey triggers at 120 s simulated time and produces a fresh key pair.
- [ ] `SessionTable` insert/lookup/remove work under contention (`proptest`).

**Dependencies:** Task 16
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §2.3

---

### Task 18: Anti-Replay Window

**Implement the 128-bit sliding anti-replay window.**

**Files to create:**
- `crates/desmos-proto/src/antireplay.rs`
- `crates/desmos-proto/tests/antireplay.rs`

**Acceptance Criteria:**
- [ ] Accepts in-order sequences.
- [ ] Accepts out-of-order within window.
- [ ] Rejects duplicates.
- [ ] Rejects out-of-window old packets.
- [ ] `proptest` verifies no false accepts across 10k random sequence streams.

**Dependencies:** Task 7
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §10.1, PRD §10

---

### Task 19: Encrypted Pipeline Integration

**Replace the plaintext pipeline from Task 14 with full encrypted packet flow.**

**Files to modify:**
- `crates/desmos-core/src/pipeline/outbound.rs`
- `crates/desmos-core/src/pipeline/inbound.rs`
- `tests/e2e/encrypted_loopback.rs`

**Acceptance Criteria:**
- [ ] Handshake completes in < 5 ms localhost.
- [ ] `iperf3` through the tunnel achieves > 500 Mbps single-core (baseline, no bonding).
- [ ] Anti-replay window rejects replayed packets.
- [ ] Tamper with AEAD tag drops the packet and increments the error counter.

**Dependencies:** Task 14, Task 17, Task 18
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.5, PRD §12 Phase 2

---

### Task 20: Network Interface Discovery

**Enumerate and monitor host network interfaces.**

**Files to create:**
- `crates/desmos-core/src/net/iface.rs` — `NetworkInterface` type + `list()` + `watch()` for link state changes
- `crates/desmos-core/src/net/mod.rs`

**Acceptance Criteria:**
- [ ] `NetworkInterface::list()` returns every interface on the host with name, MAC, IPs.
- [ ] `watch()` emits an event when an interface goes up/down (Linux: netlink `RTMGRP_LINK`).
- [ ] `desmos interfaces` CLI command prints the list as a table.

**Dependencies:** Task 5, Task 10
**Effort:** 4 hours
**Refs:** PRD §5.1

---

### Task 21: Round-Robin Bonding Strategy

**Implement the first bonding strategy and wire it into the engine.**

**Files to create:**
- `crates/desmos-core/src/bonding/mod.rs` — `BondingEngine` orchestrator
- `crates/desmos-core/src/bonding/strategy.rs` — `BondingStrategy` trait + `RoundRobin` impl
- `crates/desmos-core/src/bonding/link.rs` — `Link` struct + `LinkTable`

**Acceptance Criteria:**
- [ ] `RoundRobin::schedule` returns each link in sequence.
- [ ] Engine holds an `ArcSwap<dyn BondingStrategy>` and supports hot swap.
- [ ] Multi-interface loopback test: 2 veth pairs, tunnel rotates packets.

**Dependencies:** Task 19, Task 20
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.2, PRD §4.1

---

### Task 22: Reorder Buffer

**Implement the out-of-order packet reorder buffer with gap timeout.**

**Files to create:**
- `crates/desmos-core/src/bonding/reorder.rs`
- `crates/desmos-core/tests/reorder.rs`

**Acceptance Criteria:**
- [ ] In-order packets pass through with zero added latency.
- [ ] Out-of-order within window re-emitted in sequence.
- [ ] Gap exceeds `reorder_window_ms`: missing packet skipped, marked lost.
- [ ] Duplicate (same `session+seq`) dropped.
- [ ] p99 added latency < 1 ms on 100k-packet benchmark (`criterion`).

**Dependencies:** Task 19
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.4, PRD §4.3

---

### Task 23: Link Quality Probing

**Send and process DWP Probe packets and compute RTT/loss/jitter.**

**Files to create:**
- `crates/desmos-core/src/bonding/probe.rs` — probe sender + RTT tracker
- `crates/desmos-core/src/bonding/score.rs` — link score computation

**Acceptance Criteria:**
- [ ] A probe is sent every `probe_interval_ms` (default 500).
- [ ] RTT EWMA updates on each response.
- [ ] Rolling loss rate computed over last 100 probes.
- [ ] Jitter = stdev of RTT over the rolling window.
- [ ] Score formula implemented exactly per PRD §4.2.

**Dependencies:** Task 21, Task 11
**Effort:** 5-6 hours
**Refs:** PRD §4.2

---

### Task 24: RR Tunnel End-to-End Test

**Verify the RR bonded tunnel works through a 2-interface simulated environment.**

**Files to create:**
- `tests/e2e/rr_bonding.rs` — 2 veth pairs + `tc` latency on one + `iperf3` roundtrip

**Acceptance Criteria:**
- [ ] Throughput ≥ 1.5 × single-interface baseline with 2 equal links.
- [ ] No packet reordering issues observed (packet loss < 0.1%).
- [ ] Test can be run in CI on Linux runners.

**Dependencies:** Task 21, Task 22
**Effort:** 3-4 hours
**Refs:** PRD §13.2

---

## Phase 3: Advanced Bonding & Failover

> Matches PRD §12 Phase 3. After this phase: all 4 strategies work, interface failover is sub-second, anti-replay is hardened, MTU discovery is automatic.

### Task 25: Weighted and Latency-Adaptive Strategies

**Add the two remaining weighted scheduling strategies.**

**Files to modify:**
- `crates/desmos-core/src/bonding/strategy.rs` — add `Weighted` and `LatencyAdaptive`

**Acceptance Criteria:**
- [ ] `Weighted::schedule` produces a distribution matching configured weights (χ² test over 10k packets).
- [ ] `LatencyAdaptive::schedule` recomputes weights from link scores on every probe cycle.
- [ ] Hot swap from RR to LatencyAdaptive under load drops zero packets.

**Dependencies:** Task 21, Task 23
**Effort:** 5 hours
**Refs:** PRD §4.1

---

### Task 26: Redundant Strategy

**Implement the ultra-reliability strategy that sends every packet on every healthy link.**

**Files to modify:**
- `crates/desmos-core/src/bonding/strategy.rs` — add `Redundant`
- `crates/desmos-core/src/pipeline/outbound.rs` — handle `LinkSelection::All`

**Acceptance Criteria:**
- [ ] With 3 links, a single packet is transmitted 3 times.
- [ ] The inbound reorder buffer deduplicates correctly (Task 22 still passes).
- [ ] Throughput equal to slowest link.

**Dependencies:** Task 25, Task 22
**Effort:** 3 hours
**Refs:** PRD §4.1

---

### Task 27: Link State Machine and Failover Controller

**Explicit state machine for link health transitions.**

**Files to create:**
- `crates/desmos-core/src/bonding/link_state.rs`
- `crates/desmos-core/tests/link_state.rs`

**Acceptance Criteria:**
- [ ] State transitions match PRD §4.4 and SPECIFICATION.md §3.2.4.
- [ ] Failover redistribution happens within 1 s of dead detection in simulation.
- [ ] Probation: recovered interface is reintegrated after 10 s at reduced weight.

**Dependencies:** Task 23
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.4, §2.9

---

### Task 28: PMTUD and DWP Fragmentation

**Implement Path MTU Discovery and in-protocol fragmentation for oversized payloads.**

**Files to create/modify:**
- `crates/desmos-proto/src/wire.rs` — `FRAG` flag handling
- `crates/desmos-core/src/net/pmtud.rs` — per-link MTU probe
- `crates/desmos-core/src/pipeline/outbound.rs` — fragment on MTU exceed

**Acceptance Criteria:**
- [ ] Fragment + reassemble roundtrip for payloads up to 4× tunnel MTU.
- [ ] PMTUD converges on the correct MTU within 3 s per link.
- [ ] Fallback MTU 1280 when discovery fails.

**Dependencies:** Task 25
**Effort:** 6 hours
**Refs:** PRD §3.3, §12 Phase 3

---

### Task 29: Failover End-to-End Test

**Simulate interface failure during bulk transfer and verify failover meets targets.**

**Files to create:**
- `tests/e2e/failover.rs`

**Acceptance Criteria:**
- [ ] 3-interface tunnel under `iperf3` load.
- [ ] Kill one interface mid-transfer; connection stays up.
- [ ] Throughput drop limited to the failed link's share.
- [ ] Failover completes in < 1 s end-to-end.

**Dependencies:** Task 27, Task 25
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §10.1

---

## Phase 4: Server Mode

> Matches PRD §12 Phase 4. After this phase: a multi-client server works on Linux with all 4 auth methods and NAT masquerade.

### Task 30: Multi-Client Server Listener

**Accept multiple concurrent client handshakes on a single UDP listener.**

**Files to create:**
- `crates/desmos-core/src/server/mod.rs` — `ServerListener`
- `crates/desmos-core/src/server/clients.rs` — client table
- `crates/desmos-cli/src/commands/up.rs` — `--mode server` branch

**Acceptance Criteria:**
- [ ] Two clients can connect simultaneously to the same server.
- [ ] Each client gets a distinct `SessionId`.
- [ ] Server exits cleanly on `desmos down`.

**Dependencies:** Task 19, Task 17
**Effort:** 5-6 hours
**Refs:** PRD §12 Phase 4

---

### Task 31: Linux NAT / Masquerade Setup

**Install and remove iptables NAT rules for server-side egress.**

**Files to create:**
- `crates/desmos-core/src/server/nat.rs` — Linux iptables wrapper via `std::process::Command` (or native netlink if feasible; iptables shell-out is pragmatic)

**Acceptance Criteria:**
- [ ] Server start installs `POSTROUTING MASQUERADE` + `FORWARD ACCEPT`.
- [ ] Server stop removes exactly the rules it installed.
- [ ] Test with `iperf3` from client to an external target through the server.

**Dependencies:** Task 30
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §3.1.2

---

### Task 32: PSK and Public-Key Authenticators

**First two auth backends integrated with the Noise IK handshake.**

**Files to create:**
- `crates/desmos-core/src/auth/mod.rs` — `Authenticator` trait
- `crates/desmos-core/src/auth/psk.rs`
- `crates/desmos-core/src/auth/pubkey.rs` — reads `/etc/desmos/authorized_keys`

**Acceptance Criteria:**
- [ ] PSK mismatch rejects handshake.
- [ ] Unauthorized public key rejected.
- [ ] Valid key grants a session.

**Dependencies:** Task 30, Task 16
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §3.3

---

### Task 33: TOTP and mTLS Authenticators

**Remaining two auth backends.**

**Files to create:**
- `crates/desmos-core/src/auth/totp.rs` — RFC 6238, hand-rolled HMAC-SHA1 via `ring`
- `crates/desmos-core/src/auth/mtls.rs` — minimal TLS 1.3 client-cert verification

**Acceptance Criteria:**
- [ ] TOTP accepts ±1 period, rejects replay within the same period.
- [ ] mTLS rejects expired or revoked certs.

**Dependencies:** Task 32
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §3.3

---

### Task 34: Rate Limiting and Handshake Cookies

**Per-source token bucket and anti-amplification cookie.**

**Files to create:**
- `crates/desmos-core/src/server/ratelimit.rs`
- `crates/desmos-proto/src/handshake/cookie.rs`

**Acceptance Criteria:**
- [ ] Handshake bucket: 5 tokens, refill 0.5/s per IP.
- [ ] 6th handshake within 10 s from same IP rejected.
- [ ] Cookie blocks amplification: server does not reply with large data until client echoes a valid cookie.

**Dependencies:** Task 30
**Effort:** 4-5 hours
**Refs:** SPECIFICATION.md §6.4, §8

---

### Task 35: Server CLI Commands

**Implement `desmos clients`, `desmos clients kick <id>`, `desmos stats`.**

**Files to modify:**
- `crates/desmos-cli/src/commands/clients.rs`
- `crates/desmos-cli/src/commands/stats.rs`

**Acceptance Criteria:**
- [ ] `desmos clients` prints a table.
- [ ] `desmos clients kick <id>` disconnects the target session.
- [ ] All commands support `--json`.

**Dependencies:** Task 30-34
**Effort:** 3 hours
**Refs:** SPECIFICATION.md §3.4

---

## Phase 5: P2P and NAT Traversal

> Matches PRD §12 Phase 5. After this phase: two peers behind NAT can establish a direct tunnel.

### Task 36: STUN Client

**Implement a minimal STUN client for public-address discovery.**

**Files to create:**
- `crates/desmos-core/src/net/stun.rs` — RFC 5389 subset (Binding Request/Response, XOR-MAPPED-ADDRESS)

**Acceptance Criteria:**
- [ ] Query `stun.l.google.com:19302` returns the host's public IP.
- [ ] Malformed responses rejected.

**Dependencies:** Task 13
**Effort:** 4-5 hours
**Refs:** PRD §12 Phase 5

---

### Task 37: UDP Hole Punching

**Establish bidirectional UDP flow through symmetric NATs using simultaneous open.**

**Files to create:**
- `crates/desmos-core/src/p2p/mod.rs`
- `crates/desmos-core/src/p2p/holepunch.rs`

**Acceptance Criteria:**
- [ ] Two peers with STUN-discovered public addresses successfully exchange DWP data without a relay on cone NATs.
- [ ] Fallback path exists for symmetric NATs (try multiple src ports).

**Dependencies:** Task 36
**Effort:** 6-8 hours
**Refs:** SPECIFICATION.md §3.6.1

---

### Task 38: Relay Fallback

**When direct P2P fails, route through any reachable Desmos server acting as relay.**

**Files to create:**
- `crates/desmos-core/src/p2p/relay.rs`

**Acceptance Criteria:**
- [ ] Failed hole-punch triggers a relay attempt within 3 s.
- [ ] Relay server forwards packets between the two peers transparently.
- [ ] Config `[p2p].relay_servers` accepts a list.

**Dependencies:** Task 37, Task 30
**Effort:** 5 hours
**Refs:** SPECIFICATION.md §3.6.1

---

## Phase 6: Cross-Platform

> Matches PRD §12 Phase 6. After this phase: the binary builds, runs, and passes integration tests on all 6 platforms. Privilege drop and sandboxing are in place.

### Task 39: macOS utun + kqueue Backend

**Implement macOS TUN device and kqueue event loop.**

**Files to create:**
- `crates/desmos-rt/src/bsd/mod.rs`
- `crates/desmos-rt/src/bsd/reactor.rs` — kqueue backend
- `crates/desmos-rt/src/bsd/macos_tun.rs` — utun via `PF_SYSTEM`
- `.github/workflows/ci.yml` — macOS job runs `tun_macos` integration test

**Acceptance Criteria:**
- [ ] All Phase 1-3 tests pass on macOS.
- [ ] `iperf3` tunnel throughput ≥ 500 Mbps single core on an M1.

**Dependencies:** Task 10-14, Task 19
**Effort:** 8-10 hours
**Refs:** PRD §5.1

---

### Task 40: Windows Wintun + IOCP Backend

**Implement Windows TUN via `wintun` crate and IOCP event loop.**

**Files to create:**
- `crates/desmos-rt/src/windows/mod.rs`
- `crates/desmos-rt/src/windows/reactor.rs` — IOCP
- `crates/desmos-rt/src/windows/tun.rs` — wintun wrapper

**Acceptance Criteria:**
- [ ] All Phase 1-3 tests pass on Windows.
- [ ] Binary links statically against `wintun.dll` at runtime from a bundled path.

**Dependencies:** Task 10-14, Task 19
**Effort:** 10-12 hours
**Refs:** PRD §5.1

---

### Task 41: FreeBSD `/dev/tunN` Backend

**Implement FreeBSD TUN device and reuse the BSD kqueue backend from Task 39.**

**Files to create:**
- `crates/desmos-rt/src/bsd/freebsd_tun.rs`

**Acceptance Criteria:**
- [ ] FreeBSD 13 CI job passes Phase 1-3 tests in QEMU.
- [ ] Privilege drop via `pledge` + `unveil` works.

**Dependencies:** Task 39
**Effort:** 5-6 hours
**Refs:** PRD §5.1

---

### Task 42: Privilege Drop and Sandboxing

**Typestate privilege gate + per-platform sandbox init.**

**Files to create:**
- `crates/desmos-rt/src/priv_drop/mod.rs`
- `crates/desmos-rt/src/priv_drop/linux.rs` — `setresuid` + seccomp-bpf filter
- `crates/desmos-rt/src/priv_drop/freebsd.rs` — `pledge` + `unveil`
- `crates/desmos-rt/src/priv_drop/macos.rs` — sandbox profile

**Acceptance Criteria:**
- [ ] `Privileged::drop_privileges()` consumes `self` and returns `Unprivileged`.
- [ ] Post-drop process cannot open new TUN devices (seccomp denies).
- [ ] Audit log records the drop event.

**Dependencies:** Task 39-41
**Effort:** 8 hours
**Refs:** IMPLEMENTATION.md §2.3, SPECIFICATION.md §11.1

---

### Task 43: OpenWrt Cross-Compile and Packaging

**Cross-compile for ARM/MIPS, build an IPK package, write UCI integration.**

**Files to create:**
- `packaging/openwrt/Makefile`
- `packaging/openwrt/files/etc/config/desmos`
- `packaging/openwrt/files/etc/init.d/desmos`
- `packaging/openwrt/luci/` — `luci-app-desmos`
- `.github/workflows/openwrt.yml`

**Acceptance Criteria:**
- [ ] `make package/desmos/compile` in an OpenWrt SDK produces an IPK.
- [ ] UCI config `/etc/config/desmos` is parsed by a shim that emits `desmos.toml`.
- [ ] init.d script starts/stops the daemon via procd.

**Dependencies:** Task 42
**Effort:** 10-12 hours
**Refs:** PRD §5.3

---

### Task 44: pfSense Packaging

**Build a FreeBSD pkg for pfSense with GUI integration stub.**

**Files to create:**
- `packaging/pfsense/pkg-plist.xml`
- `packaging/pfsense/desmos.xml` — pfSense package manifest
- `packaging/freebsd/pkg/` — pkg generation scripts

**Acceptance Criteria:**
- [ ] `pkg add desmos-1.0.0.pkg` installs on pfSense 2.7+.
- [ ] Service appears under Services menu.

**Dependencies:** Task 41
**Effort:** 6-8 hours
**Refs:** PRD §5.4

---

### Task 45: Windows Service Wrapper

**Install, start, stop Desmos as a Windows Service via MSI.**

**Files to create:**
- `packaging/windows/service/` — service main loop wrapper
- `packaging/windows/wix/` — WiX MSI sources
- `.github/workflows/release.yml` — MSI build step

**Acceptance Criteria:**
- [ ] MSI installs, registers the service, sets `LocalSystem`, auto-start.
- [ ] `sc query Desmos` returns `RUNNING` after install.
- [ ] Uninstall removes the service and files.

**Dependencies:** Task 40
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §11.4

---

## Phase 7: Web UI and Polish

> Matches PRD §12 Phase 7. After this phase: full Web UI, dual-format stats, hot-reload, docs, benchmarks, release-ready.

### Task 46: Hand-Rolled HTTP/1.1 Server

**Implement the bare HTTP/1.1 server in `desmos-http`.**

**Files to create:**
- `crates/desmos-http/src/server.rs`
- `crates/desmos-http/src/request.rs`
- `crates/desmos-http/src/response.rs`
- `crates/desmos-http/src/method.rs`
- `crates/desmos-http/src/headers.rs`
- `crates/desmos-http/src/router.rs`
- `crates/desmos-http/src/errors.rs`

**Acceptance Criteria:**
- [ ] Serves `GET /` with a static body.
- [ ] Parses chunked request bodies up to 1 MB.
- [ ] Router matches path + method.
- [ ] Handles 100 concurrent connections on a single thread via the reactor.

**Dependencies:** Task 10
**Effort:** 8-10 hours
**Refs:** IMPLEMENTATION.md §3.1 (`desmos-http`)

---

### Task 47: JSON Codec

**Hand-rolled JSON encoder and decoder for a constrained subset.**

**Files to create:**
- `crates/desmos-http/src/json.rs`
- `crates/desmos-http/tests/json.rs` — `proptest` roundtrip

**Acceptance Criteria:**
- [ ] Encode/decode roundtrip for numbers, strings, booleans, arrays, objects.
- [ ] Depth limit 32 enforced.
- [ ] Rejects NaN and Infinity in numbers.
- [ ] `proptest` verifies roundtrip for 1000 random trees.

**Dependencies:** Task 46
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §5.2

---

### Task 48: WebSocket Support

**Implement RFC 6455 upgrade and framing.**

**Files to create:**
- `crates/desmos-http/src/websocket/mod.rs`
- `crates/desmos-http/src/websocket/handshake.rs`
- `crates/desmos-http/src/websocket/frame.rs`

**Acceptance Criteria:**
- [ ] `GET /ws` with correct upgrade headers returns a 101 and transitions to WS framing.
- [ ] Text and binary frames roundtrip.
- [ ] Server sends pings, receives pongs, closes on idle > 60 s.

**Dependencies:** Task 46
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §6.2

---

### Task 49: Basic Auth + Argon2 Verification

**Gate all `/api/v1/*` endpoints behind HTTP Basic + Argon2id.**

**Files to create:**
- `crates/desmos-http/src/basic_auth.rs`
- `crates/desmos-webui/src/auth.rs`

**Acceptance Criteria:**
- [ ] Valid credentials pass through.
- [ ] Invalid credentials return 401 + `WWW-Authenticate`.
- [ ] `/api/v1/health` stays public.
- [ ] Constant-time comparison via `argon2::verify_encoded`.

**Dependencies:** Task 46
**Effort:** 3 hours
**Refs:** IMPLEMENTATION.md §5.4

---

### Task 50: REST Handlers and DTOs

**Implement every endpoint from IMPLEMENTATION.md §5.1.**

**Files to create:**
- `crates/desmos-webui/src/routes.rs`
- `crates/desmos-webui/src/dto.rs`
- `crates/desmos-webui/src/handlers/{status,interfaces,bonding,stats,clients,config,logs,ws,health}.rs`

**Acceptance Criteria:**
- [ ] Each endpoint in IMPLEMENTATION.md §5.1 returns the documented JSON shape on a running server.
- [ ] `GET /api/v1/config` redacts secrets.
- [ ] `PUT /api/v1/config` hot-reloads successfully for reload-safe fields.
- [ ] `PUT /api/v1/bonding/strategy` hot-switches strategies.

**Dependencies:** Task 46-49, Task 25, Task 27
**Effort:** 8-10 hours
**Refs:** IMPLEMENTATION.md §5, SPECIFICATION.md §6.2

---

### Task 51: Dual-Format Prometheus Stats

**Add Prometheus text-format output to `/api/v1/stats`.**

**Files to create:**
- `crates/desmos-webui/src/prometheus.rs`

**Acceptance Criteria:**
- [ ] `GET /api/v1/stats` returns JSON by default.
- [ ] `GET /api/v1/stats?format=prometheus` returns valid Prometheus text.
- [ ] `GET /api/v1/stats` with `Accept: text/plain; version=0.0.4` returns Prometheus text.
- [ ] Output includes counters for bytes/packets/errors and gauges for RTT/loss/jitter per interface.

**Dependencies:** Task 50
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §6.2 (resolved decision)

---

### Task 52: React Frontend Scaffolding

**Set up the Vite + React + TypeScript project and `build.rs` integration.**

**Files to create:**
- `crates/desmos-webui/web/package.json`
- `crates/desmos-webui/web/vite.config.ts`
- `crates/desmos-webui/web/tsconfig.json`
- `crates/desmos-webui/web/index.html`
- `crates/desmos-webui/web/eslint.config.js`
- `crates/desmos-webui/web/src/main.tsx`
- `crates/desmos-webui/web/src/app.tsx`
- `crates/desmos-webui/web/src/api.ts`
- `crates/desmos-webui/build.rs` — runs `npm ci && npm run build` with staleness check
- `crates/desmos-webui/src/embed.rs` — `include_dir!("web/dist")`

**Acceptance Criteria:**
- [ ] `cargo build -p desmos-webui` runs `npm run build` and embeds `dist/`.
- [ ] `cargo build --no-default-features -p desmos-webui` skips Node (feature flag).
- [ ] SPA loads from `GET /` through the embedded server.

**Dependencies:** Task 50
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §1.2 (React decision), §3.1

---

### Task 53: Dashboard, Interfaces, Bonding Pages

**Three primary read+control screens.**

**Files to create:**
- `crates/desmos-webui/web/src/pages/Dashboard.tsx`
- `crates/desmos-webui/web/src/pages/Interfaces.tsx`
- `crates/desmos-webui/web/src/pages/Bonding.tsx`
- `crates/desmos-webui/web/src/components/ThroughputChart.tsx`
- `crates/desmos-webui/web/src/components/InterfaceTable.tsx`
- `crates/desmos-webui/web/src/components/StrategyDropdown.tsx`
- `crates/desmos-webui/web/src/hooks/useWsStream.ts`
- `crates/desmos-webui/web/src/hooks/useFetch.ts`

**Acceptance Criteria:**
- [ ] Dashboard shows live throughput graph updating via WS.
- [ ] Interfaces table toggles links via `PUT /api/v1/interfaces/:name`.
- [ ] Bonding page hot-switches strategy.

**Dependencies:** Task 52
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §3.5

---

### Task 54: Connections, Logs, Settings Pages

**Remaining three screens.**

**Files to create:**
- `crates/desmos-webui/web/src/pages/Connections.tsx`
- `crates/desmos-webui/web/src/pages/Logs.tsx`
- `crates/desmos-webui/web/src/pages/Settings.tsx`
- `crates/desmos-webui/web/src/components/LogStream.tsx`

**Acceptance Criteria:**
- [ ] Connections page lists server clients, kick works.
- [ ] Logs page streams via `/api/v1/ws/logs` with level filter.
- [ ] Settings page edits config with TOML validation before submit.

**Dependencies:** Task 53
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §3.5

---

### Task 55: DNS Leak Protection

**Route DNS queries through the tunnel when `dns_leak_protection = true`.**

**Files to create:**
- `crates/desmos-core/src/net/dns.rs` — minimal DNS resolver
- `crates/desmos-core/src/net/resolver_hook.rs` — override system DNS via platform means (`resolv.conf` on Linux, `scutil` on macOS, netsh on Windows)

**Acceptance Criteria:**
- [ ] With the option on, `dig example.com` is served through the tunnel.
- [ ] With the option off, DNS behavior is unchanged.
- [ ] Teardown restores the original DNS configuration.

**Dependencies:** Task 42
**Effort:** 6 hours
**Refs:** SPECIFICATION.md §3 / PRD §12 Phase 7

---

### Task 56: Documentation Site

**Write user-facing docs: architecture, protocol, CLI, Web UI.**

**Files to create:**
- `docs/architecture.md`
- `docs/protocol.md` — DWP spec reference
- `docs/cli.md` — every subcommand with examples
- `docs/webui.md` — screenshots + flows
- `docs/adr/0001-workspace-layout.md`
- `docs/adr/0002-hand-rolled-runtime.md`
- `docs/adr/0003-5-crate-budget.md`
- `README.md` — full rewrite per BRANDING.md

**Acceptance Criteria:**
- [ ] `cargo doc --workspace --no-deps` succeeds with zero broken intra-doc links.
- [ ] Every CLI subcommand has an example in `docs/cli.md`.
- [ ] README matches BRANDING.md voice and style.

**Dependencies:** All previous
**Effort:** 6-8 hours
**Refs:** BRANDING.md

---

### Task 57: Benchmarks and Perf Validation

**`criterion` benches that gate release on perf targets.**

**Files to create:**
- `benches/crypto.rs`
- `benches/bonding.rs`
- `benches/reorder.rs`
- `benches/wire.rs`

**Acceptance Criteria:**
- [ ] AEAD throughput ≥ 2 Gbps/core on x86_64.
- [ ] Scheduler dispatch overhead < 200 ns/packet.
- [ ] Reorder buffer p99 added latency < 1 ms.
- [ ] CI publishes bench deltas on PRs.

**Dependencies:** All previous
**Effort:** 5-6 hours
**Refs:** SPECIFICATION.md §10

---

### Task 58: Release v1.0.0

**Tag, build all targets, publish binaries, update docs.**

**Files to create/modify:**
- `.github/workflows/release.yml` — builds + MSI + pkg + ipk + deb + rpm on tag push
- `CHANGELOG.md` — v1.0.0 entry
- `packaging/linux/debian/`, `packaging/linux/rpm/`, `packaging/macos/homebrew/`, `packaging/linux/appimage/`
- `scripts/release.sh`

**Acceptance Criteria:**
- [ ] Pushing tag `v1.0.0` triggers a release build that produces artifacts for every Tier 1 + Tier 2 target.
- [ ] GitHub Release attaches all artifacts with SHA-256 sums.
- [ ] Homebrew formula, AUR PKGBUILD, and winget manifest PRs queued.
- [ ] v1.0.0 smoke test: install the Linux binary on a fresh VM, run `desmos up`, verify tunnel.

**Dependencies:** Task 1-57
**Effort:** 6-8 hours
**Refs:** PRD §14

---

## Milestones

| Milestone          | After Task | What's Achieved                                                       | Demo-able?                          |
|--------------------|------------|-----------------------------------------------------------------------|-------------------------------------|
| Foundation         | 6          | Workspace compiles, CI green on Tier 1                                | `cargo build`                       |
| First Tunnel       | 14         | Plaintext Linux tunnel through TUN + UDP                              | `ping` through `desmos0`            |
| Encrypted Tunnel   | 19         | Noise IK + AEAD tunnel, single interface                              | `iperf3` with encryption            |
| Bonded Tunnel      | 24         | 2+ interfaces via Round-Robin, probing, reorder                       | `iperf3` faster than one link       |
| Advanced Bonding   | 29         | 4 strategies, failover, PMTUD                                         | Kill an interface mid-transfer      |
| Server Mode MVP    | 35         | Multi-client Linux server with 4 auth methods                         | Two clients share a server          |
| P2P                | 38         | STUN + hole punch + relay fallback                                    | Two NAT'd peers tunnel directly     |
| Cross-Platform     | 45         | All 6 platforms, privilege drop, sandboxing                           | Run on macOS, Windows, OpenWrt      |
| Web UI             | 54         | Full dashboard with all 6 screens                                     | Live demo in browser                |
| v1.0 Release       | 58         | All artifacts published, docs complete, perf targets met              | Download + install                  |

---

## Dependency Graph

```
[T1 Scaffold]
  → [T2 Log] → [T3 TOML] → [T4 Schema]
  → [T5 CLI] → [T6 CI]

Phase 1:
[T7 DWP] → [T8 PktBuf] → [T9 Ring] → [T10 epoll] → [T11 Timer]
                                         ↓
                                      [T12 TUN] → [T13 Socket]
                                                      ↓
                                                [T14 Plaintext E2E]

Phase 2:
[T15 Crypto] → [T16 Noise IK] → [T17 Session] → [T19 Encrypted Pipeline]
                                       ↓                ↑
                                [T18 Anti-replay] ──────┘
[T19] → [T20 Iface] → [T21 RR] → [T22 Reorder] → [T23 Probe] → [T24 E2E]

Phase 3:
[T23] → [T25 Weighted+LA] → [T26 Redundant]
           ↓
    [T27 Link SM] → [T28 PMTUD] → [T29 Failover E2E]

Phase 4:
[T19,T17] → [T30 Server] → [T31 NAT]
                 ↓
           [T32 PSK+Pub] → [T33 TOTP+mTLS]
                 ↓
           [T34 RateLimit] → [T35 CLI]

Phase 5:
[T13] → [T36 STUN] → [T37 Holepunch] → [T38 Relay]

Phase 6:
[T10-T19] → [T39 macOS] → [T41 FreeBSD]
                  ↓                ↓
             [T40 Windows]    [T42 Priv drop]
                                   ↓
                        [T43 OpenWrt] [T44 pfSense] [T45 Win Svc]

Phase 7:
[T10] → [T46 HTTP] → [T47 JSON] → [T48 WS] → [T49 BasicAuth]
                                                   ↓
                                             [T50 REST] → [T51 Prom]
                                                   ↓
                                             [T52 Vite] → [T53 Pages1] → [T54 Pages2]
[T42] → [T55 DNS]

Release:
ALL → [T56 Docs] → [T57 Bench] → [T58 v1.0.0]
```
