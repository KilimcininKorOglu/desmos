# Desmos — Tasks

> Ordered work breakdown derived from `IMPLEMENTATION.md`. Execute sequentially. Each task is self-contained, names its exact files, and is sized for a single Claude Code session (2-6 hours). Phase numbering mirrors PRD §12, with a new **Phase 0** for scaffolding.

## Summary

| Metric                 | Value                                              |
|------------------------|----------------------------------------------------|
| Total Tasks            | 69                                                 |
| Phases                 | 9 (Phase 0 + PRD Phases 1-7 + Release)             |
| Estimated Effort       | ~28-34 weeks solo, 7-9 weeks with 3 devs           |
| Foundation Complete    | After Task 6                                       |
| First Tunnel           | After Task 14 (plaintext Linux)                    |
| First Encrypted Tunnel | After Task 19 (Noise IK + AEAD)                    |
| First Bonded Tunnel    | After Task 24                                      |
| MVP (Linux, 4 strategies, server) | After Task 36                            |
| P2P Working            | After Task 39                                      |
| All Platforms          | After Task 49                                      |
| Web UI Complete        | After Task 63                                      |
| Full Release (v1.0)    | After Task 69                                      |

---

## Phase 0: Scaffolding

> Establishes the Cargo workspace, toolchain pin, lint configs, CI bootstrap, and empty crates. After this phase: `cargo check --workspace` passes with zero warnings on a blank skeleton.

### Task 1: Workspace Scaffolding

**Create the Cargo workspace skeleton with all 7 crates, toolchain pin, lint configs, and deny policy.**

> **Working directory:** CWD is the project root. Do not create a wrapper subfolder. Planning docs (`SPECIFICATION.md`, `IMPLEMENTATION.md`, `TASKS.md`, `BRANDING.md`, `PROMPT.md`, `prd.md`) already live at the CWD root — leave them untouched.

**Files to create:**
- `Cargo.toml` — workspace root, `[workspace] members`, shared `[profile.release]` (lto=thin, codegen-units=1, panic=abort, strip=debuginfo), pinned runtime dep versions
- `rust-toolchain.toml` — `channel = "1.75.0"`, `components = ["rustfmt", "clippy"]`, `targets = [<Tier 1 list>]`
- `rustfmt.toml` — 100-col soft limit, trailing commas, single-import-per-line
- `clippy.toml` — `msrv = "1.75.0"`
- `deny.toml` — allow-list: only `ring`, `blake3`, `socket2`, `wintun`, `argon2` runtime; `proptest`, `criterion`, `insta` dev-only
- `.gitignore` — `target/`, `node_modules/`, `dist/`, `.DS_Store`, IDE files; `Cargo.lock` committed (binary project)
- `LICENSE` — MIT
- `README.md` — minimal stub, name + tagline + pointer to SPECIFICATION.md
- `CHANGELOG.md` — empty keepachangelog.com format
- `crates/desmos-proto/{Cargo.toml,src/lib.rs}`
- `crates/desmos-rt/{Cargo.toml,src/lib.rs}`
- `crates/desmos-core/{Cargo.toml,src/lib.rs}`
- `crates/desmos-http/{Cargo.toml,src/lib.rs}`
- `crates/desmos-webui/{Cargo.toml,src/lib.rs}`
- `crates/desmos-cli/{Cargo.toml,src/lib.rs}`
- `crates/desmos/{Cargo.toml,src/main.rs}` — `fn main() { println!("desmos"); }`

**Acceptance Criteria:**
- [ ] `cargo check --workspace` succeeds with zero warnings
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo run -p desmos` prints `desmos`
- [ ] `rustup show` confirms pinned toolchain

**Dependencies:** None
**Effort:** 2-3 hours
**Refs:** IMPLEMENTATION.md §1.1, §3.1

---

### Task 2: Core Error Types & Logging Skeleton

**Define the error taxonomy and a bare-bones structured logger with a ring buffer for later Web UI streaming.**

**Files to create:**
- `crates/desmos-core/src/errors.rs` — `CoreError` enum + `Result` alias
- `crates/desmos-core/src/log/mod.rs` — `log!(level, target, msg, k=v, ...)` macro
- `crates/desmos-core/src/log/sink.rs` — stderr line-buffered sink, sink trait
- `crates/desmos-core/src/log/ring.rs` — bounded ring buffer (500 lines default)
- `crates/desmos-core/src/log/redact.rs` — secret-field filter (`psk`, `password`, `private_key`)

**Acceptance Criteria:**
- [ ] Unit test: `log!(info, "tunnel", "up", iface="eth0")` emits a line containing `level=info target=tunnel msg=up iface=eth0`
- [ ] Ring buffer wraps at capacity, oldest entry evicted
- [ ] Redactor replaces `psk=abc123` with `psk=***`

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §7, §10.2

---

### Task 3: Hand-Rolled TOML Subset Parser

**Implement a strict TOML subset parser sufficient for the Desmos config schema.**

**Files to create:**
- `crates/desmos-core/src/config/lexer.rs` — tokenizer
- `crates/desmos-core/src/config/schema.rs` — recursive-descent parser producing a `Value` tree
- `crates/desmos-core/src/config/mod.rs` — entry point, `path.to.field` error formatter

**Supported subset:** tables, arrays of tables, basic strings, integers, floats, booleans, arrays of primitives. Unsupported: inline tables, dotted keys in value position, multi-line literal strings.

**Acceptance Criteria:**
- [ ] Parses the full example config (Task 4 supplies the example).
- [ ] Unknown section returns `unknown_section: <name>`.
- [ ] Type mismatch returns `type_mismatch: <path>: expected <T>, got <U>`.
- [ ] `proptest` roundtrip on random valid `Value` trees (1000 cases).

**Dependencies:** Task 1, Task 2
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §4.3, §8

---

### Task 4: Config Schema Validation + Example File

**Turn the parsed `Value` tree into a strongly-typed `Config` with full validation. Supply the fully commented example.**

**Files to create:**
- `crates/desmos-core/src/config/validate.rs` — `Config::from_value(&Value) -> Result<Config, ValidationError>`
- `config/desmos.toml.example` — fully commented example at the CWD root

**Acceptance Criteria:**
- [ ] Parsing `config/desmos.toml.example` yields a populated `Config`.
- [ ] Missing required field returns `missing_field: <path>`.
- [ ] Out-of-range value returns `out_of_range: <path>`.
- [ ] `webui.password_hash` verified as a parseable Argon2id encoded string.

**Dependencies:** Task 3
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §8, SPECIFICATION.md §5.1

---

### Task 5: Hand-Rolled CLI Parser + Dispatcher

**Implement `desmos-cli` argument parser and subcommand dispatcher skeleton.**

**Files to create:**
- `crates/desmos-cli/src/parser.rs` — long/short flag parser, subcommand detection
- `crates/desmos-cli/src/dispatch.rs` — `Command` trait + `Dispatcher`
- `crates/desmos-cli/src/output.rs` — colored vs JSON output (hand-rolled ANSI)
- `crates/desmos-cli/src/commands/mod.rs` — stubs for all subcommands
- `crates/desmos-cli/src/errors.rs`
- `crates/desmos/src/main.rs` — wire `Dispatcher::dispatch`

**Acceptance Criteria:**
- [ ] `desmos --help` lists all subcommands.
- [ ] `desmos status --json` dispatches to the `status` stub and prints `{}`.
- [ ] Global flags `-c`, `-v`, `-q`, `--no-color`, `--json` parsed into `GlobalFlags`.
- [ ] Unknown subcommand returns exit code 64 with a closest-match suggestion.

**Dependencies:** Task 1, Task 2
**Effort:** 4-6 hours
**Refs:** IMPLEMENTATION.md §2.8, SPECIFICATION.md §3.4

---

### Task 6: CI Bootstrap (Tier 1 Matrix)

**Set up GitHub Actions CI running fmt, clippy, build, and test across all Tier 1 targets.**

**Files to create:**
- `.github/workflows/ci.yml` — matrix: `ubuntu-latest × (x86_64-unknown-linux-musl, x86_64-unknown-linux-gnu, aarch64-unknown-linux-musl)`, `macos-14 × (x86_64-apple-darwin, aarch64-apple-darwin)`, `windows-latest × (x86_64-pc-windows-msvc)`, `ubuntu-latest × (x86_64-unknown-freebsd via cross)`
- `.github/workflows/security.yml` — `cargo-deny check`, `cargo-audit`
- `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`

**Acceptance Criteria:**
- [ ] Push to `main` triggers the matrix on all 7 Tier 1 targets.
- [ ] Every target compiles cleanly.
- [ ] `cargo-deny` enforces the runtime allow-list.
- [ ] Each job stays under 10 min with caching.

**Dependencies:** Task 1-5
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §9.3

---

## Phase 1: Protocol Foundation

> Matches PRD §12 Phase 1 — wire protocol, Linux TUN, UDP sockets, single-interface forward. After this phase: a plaintext packet loops from host A through a TUN device, over UDP, into host B.

### Task 7: DWP Header Codec

**Implement the 16-byte DWP header encode/decode with property tests.**

**Files to create:**
- `crates/desmos-proto/src/wire.rs` — `Header` struct + `encode` + `decode`
- `crates/desmos-proto/src/flags.rs` — `Flags` bitfield
- `crates/desmos-proto/src/types.rs` — `SessionId`, `InterfaceId`, `Seq`, `TimestampUs`
- `crates/desmos-proto/src/errors.rs`
- `crates/desmos-proto/tests/wire_roundtrip.rs` — `proptest`

**Acceptance Criteria:**
- [ ] Encodes to exactly 16 bytes big-endian per IMPLEMENTATION.md §4.1.
- [ ] Unknown version returns `WireError::UnsupportedVersion`.
- [ ] `proptest` 1000 cases: `decode(encode(h)) == h`.

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §4.1

---

### Task 8: PacketBuf and Buffer Pool

**Owning packet buffer + preallocated recycling pool.**

**Files to create:**
- `crates/desmos-proto/src/packet.rs` — `PacketBuf`, `PacketMeta`
- `crates/desmos-rt/src/pool.rs` — `PacketPool`

**Acceptance Criteria:**
- [ ] `PacketBuf::new(mtu)` allocates `mtu + 256` bytes (crypto + header overhead).
- [ ] Pool `acquire` returns unused buffer or allocates; `release` returns it.
- [ ] Benchmark: pool hit rate > 99% in a 10k loop.

**Dependencies:** Task 7
**Effort:** 3 hours
**Refs:** IMPLEMENTATION.md §2.6

---

### Task 9: SPSC Ring Buffer

**Lock-free SPSC ring used between pipeline stages.**

**Files to create:**
- `crates/desmos-rt/src/ring.rs` — `SpscRing<T>` with `try_push` / `try_pop`, power-of-two capacity
- `crates/desmos-rt/tests/ring_spsc.rs` — two-thread stress test

**Acceptance Criteria:**
- [ ] 1M item push/pop across threads, order preserved.
- [ ] Cache-padded head/tail.
- [ ] All `unsafe` commented and audited.

**Dependencies:** Task 1
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §2.6

---

### Task 10: Linux epoll Reactor

**Linux event-loop backend behind the `Reactor` trait.**

**Files to create:**
- `crates/desmos-rt/src/reactor.rs` — `Reactor` trait, `Event`, `Token`, `Tag`
- `crates/desmos-rt/src/event.rs`
- `crates/desmos-rt/src/linux/mod.rs`
- `crates/desmos-rt/src/linux/reactor.rs` — `epoll_create1`, `epoll_ctl`, `epoll_wait`

**Acceptance Criteria:**
- [ ] Register a UDP socket, receive read-ready on incoming packet.
- [ ] Register a TUN fd, receive read-ready on injected IP packet.
- [ ] 1000 register/deregister cycles → no fd leaks.

**Dependencies:** Task 9
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 11: Timer Wheel

**Hierarchical timer wheel (4 levels × 32 slots) for keepalives, probes, rekey.**

**Files to create:**
- `crates/desmos-rt/src/timer.rs` — `TimerWheel`, `Timer`, `TimerHandle`

**Acceptance Criteria:**
- [ ] `schedule(after, id)` + `poll(now)` returns expired IDs.
- [ ] 1 ms tick granularity at level 0, 1 s at level 3.
- [ ] 1M insert+pop in < 200 ms (x86_64).

**Dependencies:** Task 10
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 12: Linux TUN Device

**Create and drop Linux TUN devices via `ioctl(TUNSETIFF)`.**

**Files to create:**
- `crates/desmos-rt/src/tun.rs` — `Tun` trait
- `crates/desmos-rt/src/linux/tun.rs` — `LinuxTun`
- `crates/desmos-rt/tests/tun_linux.rs` — `#[ignore]` by default (needs `CAP_NET_ADMIN`)

**Acceptance Criteria:**
- [ ] `LinuxTun::create("desmos0")` returns usable `Tun`.
- [ ] Drop removes the device.
- [ ] Writing an IPv4 packet to the TUN round-trips through the kernel.

**Dependencies:** Task 10
**Effort:** 4-5 hours
**Refs:** SPECIFICATION.md §4.1

---

### Task 13: UDP Socket with `SO_BINDTODEVICE`

**Per-interface UDP sockets integrated with the reactor.**

**Files to create:**
- `crates/desmos-rt/src/socket.rs` — `UdpSocket`, `bind_to_device`
- `crates/desmos-rt/src/linux/bind_device.rs`

**Acceptance Criteria:**
- [ ] `UdpSocket::bind_on_interface("eth0")` egresses only via `eth0`.
- [ ] Two-namespace integration test confirms the chosen interface.
- [ ] Non-blocking `recv` / `send` integrate with the reactor.

**Dependencies:** Task 10, Task 12
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 14: Single-Interface Plaintext Forwarder

**Wire TUN → UDP → TUN with no encryption as a runtime-layer smoke test.**

**Files to create:**
- `crates/desmos-core/src/pipeline/{mod,outbound,inbound}.rs`
- `crates/desmos-cli/src/commands/up.rs` — hidden `--mode plaintext`
- `tests/e2e/plaintext_loopback.rs` — two instances via veth pair

**Acceptance Criteria:**
- [ ] `desmos up --mode plaintext` creates `desmos0`.
- [ ] `ping 10.200.0.2` round-trips through UDP loop.
- [ ] Teardown removes TUN and closes sockets.

**Dependencies:** Task 7, Task 10-13
**Effort:** 5-6 hours
**Refs:** PRD §12 Phase 1

---

## Phase 2: Crypto and Bonding v1

> Matches PRD §12 Phase 2 — Noise IK, AEAD, sessions, Round-Robin, reorder, probing.

### Task 15: Crypto Wrappers

**Wrap `ring` and `blake3`.**

**Files to create:**
- `crates/desmos-proto/src/crypto/{mod,aead,x25519,hkdf,blake3}.rs`
- `crates/desmos-proto/tests/aead_roundtrip.rs`

**Acceptance Criteria:**
- [ ] Seal/open round-trip.
- [ ] Wrong key fails open with typed error.
- [ ] Tag tamper fails open.
- [ ] HKDF matches a test vector.

**Dependencies:** Task 1
**Effort:** 4 hours
**Refs:** IMPLEMENTATION.md §2.3

---

### Task 16: Noise IK State Machine

**Implement the Noise IK handshake pattern.**

**Files to create:**
- `crates/desmos-proto/src/handshake/{mod,noise}.rs`
- `crates/desmos-proto/tests/noise_ik.rs`

**Acceptance Criteria:**
- [ ] Two states converge to matching transport keys in ≤ 2 exchanges.
- [ ] Unknown server static key rejects on responder.
- [ ] Matches a documented reference test vector.

**Dependencies:** Task 15
**Effort:** 8 hours
**Refs:** PRD §3.2

---

### Task 17: Session Typestate + Manager

**`Session<Handshaking|Established|Rekeying|Closed>` + `SessionTable`.**

**Files to create:**
- `crates/desmos-core/src/session/{mod,manager,keepalive,rekey}.rs`

**Acceptance Criteria:**
- [ ] `Session<Handshaking>::advance` consumes self and returns `Session<Established>`.
- [ ] `encrypt_data` only callable on `&Session<Established>` (`compile_fail` test verifies).
- [ ] Rekey triggers at 120 s simulated time.
- [ ] `SessionTable` insert/lookup/remove verified by `proptest`.

**Dependencies:** Task 16
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §2.3

---

### Task 18: Anti-Replay Window

**128-bit sliding window.**

**Files to create:**
- `crates/desmos-proto/src/antireplay.rs`
- `crates/desmos-proto/tests/antireplay.rs`

**Acceptance Criteria:**
- [ ] Accepts in-order and out-of-order within window.
- [ ] Rejects duplicates and out-of-window.
- [ ] `proptest`: no false accepts across 10k random streams.

**Dependencies:** Task 7
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §10.1

---

### Task 19: Encrypted Pipeline Integration

**Replace plaintext pipeline with full encrypted flow.**

**Files to modify:**
- `crates/desmos-core/src/pipeline/{outbound,inbound}.rs`
- `tests/e2e/encrypted_loopback.rs`

**Acceptance Criteria:**
- [ ] Handshake completes < 5 ms on localhost.
- [ ] `iperf3` single-interface throughput > 500 Mbps.
- [ ] Anti-replay rejects replayed packets.
- [ ] Tag tamper drops + increments error counter.

**Dependencies:** Task 14, Task 17, Task 18
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.5

---

### Task 20: Network Interface Discovery

**Enumerate and monitor host interfaces.**

**Files to create:**
- `crates/desmos-core/src/net/iface.rs`
- `crates/desmos-core/src/net/mod.rs`

**Acceptance Criteria:**
- [ ] `list()` returns every interface with name, MAC, IPs.
- [ ] `watch()` emits events on link up/down via netlink on Linux.
- [ ] `desmos interfaces` prints a table.

**Dependencies:** Task 5, Task 10
**Effort:** 4 hours
**Refs:** PRD §5.1

---

### Task 21: Round-Robin Bonding Engine

**First bonding strategy + engine orchestrator.**

**Files to create:**
- `crates/desmos-core/src/bonding/{mod,strategy,link}.rs`

**Acceptance Criteria:**
- [ ] `RoundRobin::schedule` rotates through links.
- [ ] Engine holds `ArcSwap<dyn BondingStrategy>`, hot-swap safe.
- [ ] 2-veth test: tunnel rotates packets.

**Dependencies:** Task 19, Task 20
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.2, PRD §4.1

---

### Task 22: Reorder Buffer

**Out-of-order reorder buffer with gap timeout.**

**Files to create:**
- `crates/desmos-core/src/bonding/reorder.rs`
- `crates/desmos-core/tests/reorder.rs`

**Acceptance Criteria:**
- [ ] In-order passes with zero added latency.
- [ ] Out-of-order within window re-emitted in sequence.
- [ ] Gap exceeds window: missing packet skipped + counted lost.
- [ ] Duplicates dropped.
- [ ] p99 added latency < 1 ms on 100k-packet `criterion` bench.

**Dependencies:** Task 19
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.4

---

### Task 23: Link Quality Probing + Scoring

**Send Probe packets, compute RTT/loss/jitter, link score.**

**Files to create:**
- `crates/desmos-core/src/bonding/probe.rs`
- `crates/desmos-core/src/bonding/score.rs`

**Acceptance Criteria:**
- [ ] Probe sent every `probe_interval_ms` (default 500).
- [ ] RTT EWMA updates on response.
- [ ] Rolling loss over last 100 probes.
- [ ] Jitter = stdev over rolling window.
- [ ] Link score formula matches PRD §4.2 exactly.

**Dependencies:** Task 21, Task 11
**Effort:** 5-6 hours
**Refs:** PRD §4.2

---

### Task 24: RR Bonding End-to-End Test

**Validate bonded tunnel throughput and stability.**

**Files to create:**
- `tests/e2e/rr_bonding.rs` — 2 veth pairs, `tc` latency + `iperf3`

**Acceptance Criteria:**
- [ ] Throughput ≥ 1.5× single-interface baseline with equal links.
- [ ] Packet loss < 0.1%.
- [ ] Runs in Linux CI.

**Dependencies:** Task 21, Task 22
**Effort:** 3-4 hours
**Refs:** PRD §13.2

---

## Phase 3: Advanced Bonding & Failover

> Matches PRD §12 Phase 3.

### Task 25: Weighted and Latency-Adaptive Strategies

**Add the two weighted scheduling strategies.**

**Files to modify:**
- `crates/desmos-core/src/bonding/strategy.rs`

**Acceptance Criteria:**
- [ ] `Weighted` distribution matches configured weights (χ² over 10k packets).
- [ ] `LatencyAdaptive` recomputes weights on every probe cycle.
- [ ] Hot swap under load drops zero packets.

**Dependencies:** Task 21, Task 23
**Effort:** 5 hours
**Refs:** PRD §4.1

---

### Task 26: Redundant Strategy

**Send every packet on every healthy link.**

**Files to modify:**
- `crates/desmos-core/src/bonding/strategy.rs`
- `crates/desmos-core/src/pipeline/outbound.rs`

**Acceptance Criteria:**
- [ ] 3 links → every packet transmitted 3×.
- [ ] Reorder buffer deduplicates correctly.
- [ ] Throughput = slowest link (expected).

**Dependencies:** Task 25, Task 22
**Effort:** 3 hours
**Refs:** PRD §4.1

---

### Task 27: Link State Machine + Failover Controller

**Explicit state machine for link health transitions.**

**Files to create:**
- `crates/desmos-core/src/bonding/link_state.rs`
- `crates/desmos-core/tests/link_state.rs`

**Acceptance Criteria:**
- [ ] Transitions match PRD §4.4 exactly.
- [ ] Failover redistribution within 1 s of dead detection.
- [ ] Probation reintegrates recovered interface after 10 s at reduced weight.

**Dependencies:** Task 23
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.4

---

### Task 28: PMTUD + DWP Fragmentation

**Path MTU Discovery and in-protocol fragmentation.**

**Files to create/modify:**
- `crates/desmos-proto/src/wire.rs` — `FRAG` flag handling
- `crates/desmos-core/src/net/pmtud.rs`
- `crates/desmos-core/src/pipeline/outbound.rs`

**Acceptance Criteria:**
- [ ] Fragment + reassemble roundtrip for payloads up to 4× tunnel MTU.
- [ ] PMTUD converges within 3 s per link.
- [ ] Fallback MTU 1280 on discovery failure.

**Dependencies:** Task 25
**Effort:** 6 hours
**Refs:** PRD §3.3

---

### Task 29: Failover End-to-End Test

**Validate failover under bulk transfer.**

**Files to create:**
- `tests/e2e/failover.rs`

**Acceptance Criteria:**
- [ ] 3-interface tunnel under `iperf3` load.
- [ ] Kill one mid-transfer → tunnel stays up.
- [ ] Throughput drop limited to failed-link share.
- [ ] Failover end-to-end < 1 s.

**Dependencies:** Task 27, Task 25
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §10.1

---

## Phase 4: Server Mode

> Matches PRD §12 Phase 4.

### Task 30: Multi-Client Server Listener

**Accept concurrent client handshakes on one UDP listener.**

**Files to create:**
- `crates/desmos-core/src/server/{mod,clients}.rs`
- `crates/desmos-cli/src/commands/up.rs` — `--mode server` branch

**Acceptance Criteria:**
- [ ] Two clients connect simultaneously with distinct `SessionId`.
- [ ] Server exits cleanly on `desmos down`.
- [ ] `max_clients` enforced.

**Dependencies:** Task 19, Task 17
**Effort:** 5-6 hours
**Refs:** PRD §12 Phase 4

---

### Task 31: Linux NAT / Masquerade Setup

**Install and remove iptables NAT rules for server-side egress.**

**Files to create:**
- `crates/desmos-core/src/server/nat.rs` — Linux iptables wrapper via `std::process::Command`

**Acceptance Criteria:**
- [ ] Start installs `POSTROUTING MASQUERADE` + `FORWARD ACCEPT`.
- [ ] Stop removes exactly the installed rules.
- [ ] `iperf3` through server to external target works.

**Dependencies:** Task 30
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §3.1.2

---

### Task 32: PSK and Public-Key Authenticators

**First two auth backends.**

**Files to create:**
- `crates/desmos-core/src/auth/{mod,psk,pubkey}.rs`

**Acceptance Criteria:**
- [ ] PSK mismatch rejects handshake.
- [ ] Unauthorized public key rejected.
- [ ] Valid key grants session.

**Dependencies:** Task 30, Task 16
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §3.3

---

### Task 33: TOTP Authenticator

**RFC 6238 TOTP backend.**

**Files to create:**
- `crates/desmos-core/src/auth/totp.rs` — hand-rolled HMAC-SHA1 via `ring`
- `crates/desmos-core/tests/auth_totp.rs`

**Acceptance Criteria:**
- [ ] Accepts codes within ±1 period (default 30 s).
- [ ] Rejects replay within the same period.
- [ ] Matches RFC 6238 Appendix B test vectors.

**Dependencies:** Task 32
**Effort:** 4 hours
**Refs:** SPECIFICATION.md §3.3

---

### Task 34: mTLS Authenticator

**Minimal TLS 1.3 client-cert verification for mTLS auth.**

**Files to create:**
- `crates/desmos-core/src/auth/mtls.rs` — uses `ring` for signature verification + CA chain walking

**Acceptance Criteria:**
- [ ] Accepts certs signed by configured CA.
- [ ] Rejects expired / future-dated certs.
- [ ] Rejects revoked certs from the CRL file.
- [ ] CN mapped to session identity.

**Dependencies:** Task 33
**Effort:** 6-8 hours
**Refs:** SPECIFICATION.md §3.3

---

### Task 35: Rate Limiting + Handshake Cookies

**Per-source token bucket and anti-amplification cookie.**

**Files to create:**
- `crates/desmos-core/src/server/ratelimit.rs`
- `crates/desmos-proto/src/handshake/cookie.rs`

**Acceptance Criteria:**
- [ ] 5 tokens / 10 s refill per source IP; 6th rejected.
- [ ] Cookie blocks amplification until echoed.

**Dependencies:** Task 30
**Effort:** 4-5 hours
**Refs:** SPECIFICATION.md §6.4

---

### Task 36: Server CLI Commands

**`desmos clients`, `desmos clients kick`, `desmos stats`.**

**Files to modify:**
- `crates/desmos-cli/src/commands/{clients,stats}.rs`

**Acceptance Criteria:**
- [ ] `desmos clients` prints a table.
- [ ] Kick disconnects the session.
- [ ] All commands support `--json`.

**Dependencies:** Task 30-35
**Effort:** 3 hours
**Refs:** SPECIFICATION.md §3.4

---

## Phase 5: P2P and NAT Traversal

> Matches PRD §12 Phase 5.

### Task 37: STUN Client

**RFC 5389 subset for public-address discovery.**

**Files to create:**
- `crates/desmos-core/src/net/stun.rs`

**Acceptance Criteria:**
- [ ] Query `stun.l.google.com:19302` returns the host's public IP.
- [ ] Malformed responses rejected.

**Dependencies:** Task 13
**Effort:** 4-5 hours
**Refs:** PRD §12 Phase 5

---

### Task 38: UDP Hole Punching

**Establish bidirectional UDP flow through NATs.**

**Files to create:**
- `crates/desmos-core/src/p2p/{mod,holepunch}.rs`

**Acceptance Criteria:**
- [ ] Two peers with STUN-discovered addresses exchange DWP data over cone NATs.
- [ ] Symmetric-NAT fallback tries multiple src ports.

**Dependencies:** Task 37
**Effort:** 6-8 hours
**Refs:** SPECIFICATION.md §3.6.1

---

### Task 39: Relay Fallback

**Route through a Desmos server when direct P2P fails.**

**Files to create:**
- `crates/desmos-core/src/p2p/relay.rs`

**Acceptance Criteria:**
- [ ] Hole-punch failure triggers relay within 3 s.
- [ ] Relay forwards packets between peers transparently.
- [ ] `[p2p].relay_servers` list honored.

**Dependencies:** Task 38, Task 30
**Effort:** 5 hours
**Refs:** SPECIFICATION.md §3.6.1

---

## Phase 6: Cross-Platform

> Matches PRD §12 Phase 6.

### Task 40: BSD kqueue Reactor

**Shared BSD kqueue backend (used by macOS and FreeBSD).**

**Files to create:**
- `crates/desmos-rt/src/bsd/{mod,reactor}.rs` — `kqueue()` + `kevent()`

**Acceptance Criteria:**
- [ ] Register UDP socket + TUN fd → events delivered.
- [ ] 1000 register/deregister cycles → no leaks.
- [ ] Unit tests pass on macOS and FreeBSD runners.

**Dependencies:** Task 10 (trait), Task 9 (rings)
**Effort:** 5-6 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 41: macOS utun TUN Backend

**macOS utun device via `PF_SYSTEM`.**

**Files to create:**
- `crates/desmos-rt/src/bsd/macos_tun.rs`

**Acceptance Criteria:**
- [ ] `MacosTun::create()` returns a usable device.
- [ ] Phase 1-3 tests pass on macOS.
- [ ] `iperf3` ≥ 500 Mbps single core on an M1.

**Dependencies:** Task 40
**Effort:** 5-6 hours
**Refs:** PRD §5.1

---

### Task 42: Windows IOCP Reactor

**Windows IOCP event loop behind the `Reactor` trait.**

**Files to create:**
- `crates/desmos-rt/src/windows/{mod,reactor}.rs` — `CreateIoCompletionPort`, `GetQueuedCompletionStatus`

**Acceptance Criteria:**
- [ ] Register UDP socket → events delivered.
- [ ] Proper overlapped I/O handling (completion on write + read).
- [ ] Unit tests pass on `windows-latest`.

**Dependencies:** Task 10 (trait)
**Effort:** 6-8 hours
**Refs:** IMPLEMENTATION.md §2.1

---

### Task 43: Windows Wintun TUN Backend

**Windows TUN via the `wintun` crate.**

**Files to create:**
- `crates/desmos-rt/src/windows/tun.rs`

**Acceptance Criteria:**
- [ ] Create/drop TUN device via Wintun session API.
- [ ] Phase 1-3 tests pass on Windows.
- [ ] Binary locates `wintun.dll` from a bundled path.

**Dependencies:** Task 42
**Effort:** 5-6 hours
**Refs:** PRD §5.1

---

### Task 44: FreeBSD `/dev/tunN` Backend

**FreeBSD TUN reusing the BSD kqueue backend.**

**Files to create:**
- `crates/desmos-rt/src/bsd/freebsd_tun.rs`

**Acceptance Criteria:**
- [ ] FreeBSD 13 CI job (QEMU) passes Phase 1-3 tests.
- [ ] `iperf3` roundtrip works.

**Dependencies:** Task 40
**Effort:** 4-5 hours
**Refs:** PRD §5.1

---

### Task 45: Privilege Drop + Sandboxing

**Typestate privilege gate + per-platform sandbox init.**

**Files to create:**
- `crates/desmos-rt/src/priv_drop/{mod,linux,freebsd,macos}.rs`

**Acceptance Criteria:**
- [ ] `Privileged::drop_privileges()` consumes self and returns `Unprivileged`.
- [ ] Post-drop cannot open new TUN devices (seccomp denies on Linux).
- [ ] Audit log records the drop.
- [ ] FreeBSD: `pledge` + `unveil` applied.
- [ ] macOS: sandbox profile initialized.

**Dependencies:** Task 41, Task 43, Task 44
**Effort:** 8 hours
**Refs:** IMPLEMENTATION.md §2.3

---

### Task 46: OpenWrt Cross-Compile + IPK

**Cross-compile for MIPS/ARM OpenWrt targets and produce an IPK.**

**Files to create:**
- `packaging/openwrt/Makefile`
- `.github/workflows/openwrt.yml`
- `scripts/build-openwrt.sh`

**Acceptance Criteria:**
- [ ] `make package/desmos/compile` in an OpenWrt SDK produces an IPK for `mips_24kc`, `arm_cortex-a7`, `aarch64_cortex-a53`.
- [ ] IPK installs via `opkg install` on a test image.

**Dependencies:** Task 45
**Effort:** 6-8 hours
**Refs:** PRD §5.3

---

### Task 47: OpenWrt UCI + init.d + LuCI App

**UCI config bridge, procd init script, LuCI web config.**

**Files to create:**
- `packaging/openwrt/files/etc/config/desmos`
- `packaging/openwrt/files/etc/init.d/desmos`
- `packaging/openwrt/luci/luasrc/controller/desmos.lua`
- `packaging/openwrt/luci/luasrc/model/cbi/desmos.lua`
- `packaging/openwrt/luci/luasrc/view/desmos/*.htm`

**Acceptance Criteria:**
- [ ] UCI config parsed by a shim that emits `desmos.toml`.
- [ ] `service desmos start|stop|restart` works via procd.
- [ ] LuCI app page at `/cgi-bin/luci/admin/services/desmos` loads and saves config.

**Dependencies:** Task 46
**Effort:** 6-8 hours
**Refs:** PRD §5.3

---

### Task 48: pfSense Packaging

**FreeBSD pkg with pfSense GUI manifest.**

**Files to create:**
- `packaging/pfsense/pkg-plist.xml`
- `packaging/pfsense/desmos.xml` — pfSense package manifest
- `packaging/freebsd/pkg/` — pkg generation scripts

**Acceptance Criteria:**
- [ ] `pkg add desmos-1.0.0.pkg` installs on pfSense 2.7+.
- [ ] Service appears under Services menu.

**Dependencies:** Task 44
**Effort:** 6-8 hours
**Refs:** PRD §5.4

---

### Task 49: Windows Service Wrapper + MSI

**Install, start, stop Desmos as a Windows Service via MSI.**

**Files to create:**
- `packaging/windows/service/src/service_main.rs` — service main loop wrapper
- `packaging/windows/wix/desmos.wxs` — WiX MSI source
- `.github/workflows/release.yml` — MSI build step (skeleton; full wiring in Task 68)

**Acceptance Criteria:**
- [ ] MSI installs, registers the service as `LocalSystem`, auto-start.
- [ ] `sc query Desmos` reports `RUNNING`.
- [ ] Uninstall removes service and files.

**Dependencies:** Task 43
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §11.4 (Windows Service decision)

---

## Phase 7: Web UI and Polish

> Matches PRD §12 Phase 7.

### Task 50: HTTP Server Core (Server + Request + Response)

**Hand-rolled HTTP/1.1 server skeleton.**

**Files to create:**
- `crates/desmos-http/src/server.rs` — listener + connection loop integrated with reactor
- `crates/desmos-http/src/request.rs` — zero-alloc header parser, body reader
- `crates/desmos-http/src/response.rs` — response builder
- `crates/desmos-http/src/method.rs`
- `crates/desmos-http/src/headers.rs` — typed header wrappers
- `crates/desmos-http/src/errors.rs`

**Acceptance Criteria:**
- [ ] Serves a static `GET /` with a 200 response.
- [ ] Parses up to 1 MB request bodies (chunked and content-length).
- [ ] 100 concurrent connections handled on a single thread.

**Dependencies:** Task 10
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §3.1

---

### Task 51: HTTP Router + Middleware Chain

**Path + method routing with a chain-of-responsibility middleware.**

**Files to create:**
- `crates/desmos-http/src/router.rs`
- `crates/desmos-http/src/middleware.rs`

**Acceptance Criteria:**
- [ ] Exact-match and `:param` routes supported.
- [ ] Middleware chain runs before handlers and can short-circuit.
- [ ] 404 for unmatched routes.

**Dependencies:** Task 50
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §5.1

---

### Task 52: JSON Codec

**Hand-rolled JSON encoder/decoder for a constrained subset.**

**Files to create:**
- `crates/desmos-http/src/json.rs`
- `crates/desmos-http/tests/json.rs` — `proptest` roundtrip

**Acceptance Criteria:**
- [ ] Encode/decode roundtrip for numbers, strings, booleans, arrays, objects.
- [ ] Depth limit 32 enforced.
- [ ] Rejects NaN and Infinity.
- [ ] `proptest` roundtrip over 1000 random trees.

**Dependencies:** Task 50
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §5.2

---

### Task 53: WebSocket Support

**RFC 6455 upgrade + framing.**

**Files to create:**
- `crates/desmos-http/src/websocket/{mod,handshake,frame}.rs`

**Acceptance Criteria:**
- [ ] Upgrade handshake returns 101 on valid headers.
- [ ] Text and binary frames roundtrip.
- [ ] Ping/pong; server closes on > 60 s idle.

**Dependencies:** Task 51
**Effort:** 8 hours
**Refs:** SPECIFICATION.md §6.2

---

### Task 54: Basic Auth + Argon2 Verification

**Gate `/api/v1/*` behind HTTP Basic + Argon2id.**

**Files to create:**
- `crates/desmos-http/src/basic_auth.rs`
- `crates/desmos-webui/src/auth.rs`

**Acceptance Criteria:**
- [ ] Valid credentials pass through.
- [ ] Invalid credentials return 401 + `WWW-Authenticate`.
- [ ] `/api/v1/health` stays public.
- [ ] Constant-time verification via `argon2::verify_encoded`.

**Dependencies:** Task 51
**Effort:** 3 hours
**Refs:** IMPLEMENTATION.md §5.4

---

### Task 55: REST Read Endpoints

**All `GET` endpoints from IMPLEMENTATION.md §5.1.**

**Files to create:**
- `crates/desmos-webui/src/routes.rs`
- `crates/desmos-webui/src/dto.rs`
- `crates/desmos-webui/src/handlers/{status,interfaces,bonding,stats,clients,config,logs,health,mod}.rs` — GET handlers only

**Acceptance Criteria:**
- [ ] `GET /api/v1/status`, `/interfaces`, `/bonding`, `/stats`, `/clients`, `/config`, `/logs`, `/health` return the documented JSON shapes.
- [ ] `GET /api/v1/config` redacts secrets.
- [ ] All endpoints behind Basic Auth except `/health`.

**Dependencies:** Task 50-54, Task 25, Task 27
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §5

---

### Task 56: REST Write + Hot-Reload Endpoints

**All `PUT` / `DELETE` endpoints with config hot-reload.**

**Files to create/modify:**
- `crates/desmos-webui/src/handlers/{interfaces,bonding,config,clients}.rs` — PUT/DELETE handlers
- `crates/desmos-core/src/config/diff.rs` — hot-reload diff logic

**Acceptance Criteria:**
- [ ] `PUT /api/v1/interfaces/:name` enables/disables/reweights.
- [ ] `PUT /api/v1/bonding/strategy` hot-switches strategies with zero packet loss.
- [ ] `PUT /api/v1/config` hot-reloads reload-safe fields and rejects unsafe changes with a typed error.
- [ ] `DELETE /api/v1/clients/:session_id` kicks.

**Dependencies:** Task 55
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §5, SPECIFICATION.md §3.5.6

---

### Task 57: Dual-Format Prometheus Stats

**Add Prometheus text-format output to `/api/v1/stats`.**

**Files to create:**
- `crates/desmos-webui/src/prometheus.rs`

**Acceptance Criteria:**
- [ ] `GET /api/v1/stats` returns JSON by default.
- [ ] `?format=prometheus` returns Prometheus text.
- [ ] `Accept: text/plain; version=0.0.4` returns Prometheus text.
- [ ] Output: counters (bytes/packets/errors) + gauges (RTT/loss/jitter) per interface.

**Dependencies:** Task 55
**Effort:** 3 hours
**Refs:** SPECIFICATION.md §6.2

---

### Task 58: WebSocket Stats + Logs Endpoints

**`/api/v1/ws/stats` and `/api/v1/ws/logs` live streams.**

**Files to create:**
- `crates/desmos-webui/src/handlers/ws.rs`
- `crates/desmos-core/src/broadcast.rs` — `Broadcast<T>` ring

**Acceptance Criteria:**
- [ ] `ws/stats` emits JSON snapshots at ≥ 2 Hz.
- [ ] `ws/logs` emits new log entries as they occur, filtered by `?level=`.
- [ ] Multiple subscribers share the bus without blocking publishers.

**Dependencies:** Task 53, Task 55
**Effort:** 4-5 hours
**Refs:** IMPLEMENTATION.md §2.7

---

### Task 59: Vite + React + TypeScript Scaffolding

**Set up the frontend project.**

**Files to create:**
- `crates/desmos-webui/web/package.json`
- `crates/desmos-webui/web/vite.config.ts`
- `crates/desmos-webui/web/tsconfig.json`
- `crates/desmos-webui/web/index.html`
- `crates/desmos-webui/web/eslint.config.js`
- `crates/desmos-webui/web/src/main.tsx`
- `crates/desmos-webui/web/src/app.tsx`
- `crates/desmos-webui/web/src/api.ts`
- `crates/desmos-webui/web/src/hooks/{useFetch,useWsStream}.ts`
- `crates/desmos-webui/web/src/styles/{tokens,global}.css` — placeholder, filled by BRANDING.md

**Acceptance Criteria:**
- [ ] `npm ci && npm run build` produces `web/dist/`.
- [ ] `npm run dev` serves on `:5173`.
- [ ] Eslint + TypeScript strict mode pass.

**Dependencies:** Task 55
**Effort:** 3-4 hours
**Refs:** IMPLEMENTATION.md §3.1

---

### Task 60: `build.rs` Frontend Integration + Embed

**`build.rs` runs the frontend build and `include_dir!` embeds the output.**

**Files to create:**
- `crates/desmos-webui/build.rs` — runs `npm ci && npm run build` with staleness check + feature-gate
- `crates/desmos-webui/src/embed.rs` — `include_dir!("web/dist")` + static-file route handler

**Acceptance Criteria:**
- [ ] `cargo build -p desmos-webui` invokes the Vite build once.
- [ ] Re-building with no frontend changes skips Node.
- [ ] `cargo build --no-default-features -p desmos-webui` skips Node (`embed` feature off).
- [ ] `GET /` serves `index.html` from the embedded bundle.
- [ ] `GET /static/*` serves embedded assets with correct `Content-Type`.

**Dependencies:** Task 59
**Effort:** 3 hours
**Refs:** IMPLEMENTATION.md §1.2

---

### Task 61: Dashboard Page + ThroughputChart

**Live dashboard with real-time throughput graph.**

**Files to create:**
- `crates/desmos-webui/web/src/pages/Dashboard.tsx`
- `crates/desmos-webui/web/src/components/ThroughputChart.tsx`
- `crates/desmos-webui/web/src/components/TunnelStatusBadge.tsx`

**Acceptance Criteria:**
- [ ] Throughput chart updates via `/api/v1/ws/stats`.
- [ ] Status badge reflects `up|connecting|degraded|down`.
- [ ] Dashboard loads < 200 ms on localhost.

**Dependencies:** Task 58, Task 60
**Effort:** 5 hours
**Refs:** SPECIFICATION.md §3.5.1

---

### Task 62: Interfaces + Bonding Pages

**Interface table and bonding controls.**

**Files to create:**
- `crates/desmos-webui/web/src/pages/Interfaces.tsx`
- `crates/desmos-webui/web/src/components/InterfaceTable.tsx`
- `crates/desmos-webui/web/src/pages/Bonding.tsx`
- `crates/desmos-webui/web/src/components/StrategyDropdown.tsx`
- `crates/desmos-webui/web/src/components/WeightSlider.tsx`

**Acceptance Criteria:**
- [ ] Interfaces table toggles links via `PUT /api/v1/interfaces/:name`.
- [ ] Bonding strategy dropdown hot-switches within 500 ms.
- [ ] Weight sliders apply and reflect in `GET /api/v1/bonding`.

**Dependencies:** Task 61
**Effort:** 5 hours
**Refs:** SPECIFICATION.md §3.5.2, §3.5.3

---

### Task 63: Connections + Logs + Settings Pages

**Remaining three screens.**

**Files to create:**
- `crates/desmos-webui/web/src/pages/Connections.tsx`
- `crates/desmos-webui/web/src/pages/Logs.tsx`
- `crates/desmos-webui/web/src/components/LogStream.tsx`
- `crates/desmos-webui/web/src/pages/Settings.tsx`
- `crates/desmos-webui/web/src/components/TomlEditor.tsx`

**Acceptance Criteria:**
- [ ] Connections lists server clients, kick works.
- [ ] Logs streams via `/api/v1/ws/logs` with level filter.
- [ ] Settings editor validates TOML before submitting.

**Dependencies:** Task 62
**Effort:** 6-8 hours
**Refs:** SPECIFICATION.md §3.5.4, §3.5.5, §3.5.6

---

### Task 64: DNS Leak Protection

**Route DNS through the tunnel when `dns_leak_protection = true`.**

**Files to create:**
- `crates/desmos-core/src/net/dns.rs` — minimal UDP DNS resolver
- `crates/desmos-core/src/net/resolver_hook.rs` — platform DNS override (`resolv.conf`, `scutil`, `netsh`)

**Acceptance Criteria:**
- [ ] With the option on, queries route through the tunnel.
- [ ] With the option off, behavior is unchanged.
- [ ] Teardown restores the original DNS configuration.

**Dependencies:** Task 45
**Effort:** 6 hours
**Refs:** PRD §12 Phase 7

---

## Release

> Documentation, benchmarks, packaging, v1.0 tag.

### Task 65: User-Facing Documentation

**Architecture, protocol, CLI, Web UI docs.**

**Files to create:**
- `docs/architecture.md`
- `docs/protocol.md` — DWP spec reference
- `docs/cli.md` — every subcommand with examples
- `docs/webui.md` — page-by-page reference

**Acceptance Criteria:**
- [ ] `cargo doc --workspace --no-deps` succeeds with zero broken intra-doc links.
- [ ] Every CLI subcommand has an example in `docs/cli.md`.
- [ ] DWP packet layout diagram matches IMPLEMENTATION.md §4.1.

**Dependencies:** Task 1-64
**Effort:** 6 hours
**Refs:** IMPLEMENTATION.md §12

---

### Task 66: ADRs + README Rewrite

**Architecture Decision Records + BRANDING-aligned README.**

**Files to create:**
- `docs/adr/0001-workspace-layout.md`
- `docs/adr/0002-hand-rolled-runtime.md`
- `docs/adr/0003-5-crate-budget.md`
- `docs/adr/0004-typestate-for-sessions.md`
- `README.md` — full rewrite following BRANDING.md voice and visual conventions

**Acceptance Criteria:**
- [ ] Each ADR uses the standard `Context / Decision / Consequences` format.
- [ ] README renders cleanly on GitHub and matches BRANDING.md.

**Dependencies:** Task 65, BRANDING.md
**Effort:** 4 hours
**Refs:** BRANDING.md

---

### Task 67: Benchmarks and Perf Validation

**`criterion` benches that gate release on perf targets.**

**Files to create:**
- `benches/crypto.rs`
- `benches/bonding.rs`
- `benches/reorder.rs`
- `benches/wire.rs`

**Acceptance Criteria:**
- [ ] AEAD throughput ≥ 2 Gbps / core on x86_64.
- [ ] Scheduler dispatch < 200 ns/packet.
- [ ] Reorder p99 added latency < 1 ms.
- [ ] CI publishes bench deltas on PRs.

**Dependencies:** Task 1-64
**Effort:** 5-6 hours
**Refs:** SPECIFICATION.md §10

---

### Task 68: Packaging Artifacts

**Debian, RPM, AppImage, Homebrew formula, winget, AUR.**

**Files to create:**
- `packaging/linux/debian/` — control, rules, postinst
- `packaging/linux/rpm/desmos.spec`
- `packaging/linux/appimage/AppImage.yml`
- `packaging/linux/systemd/desmos.service`
- `packaging/macos/homebrew/desmos.rb` (template)
- `packaging/macos/pkg/` — `.pkg` postinstall scripts
- `packaging/windows/winget/desmos.yaml` (template)
- `packaging/linux/aur/PKGBUILD` (template)

**Acceptance Criteria:**
- [ ] `dpkg-deb --build` produces a working `.deb` on Debian.
- [ ] `rpmbuild -bb` produces an installable `.rpm`.
- [ ] Homebrew formula installs and runs `desmos --version`.
- [ ] `desmos.service` systemd unit starts and stops the daemon.

**Dependencies:** Task 45, Task 46, Task 49
**Effort:** 8 hours
**Refs:** PRD §14

---

### Task 69: Release Workflow + v1.0.0 Tag + Smoke Test

**Automated tagged release producing all artifacts, plus a fresh-VM smoke test.**

**Files to create/modify:**
- `.github/workflows/release.yml` — on tag push: build all Tier 1 + Tier 2 targets, MSI, deb, rpm, pkg, ipk, AppImage; attach to GitHub Release with SHA-256 sums
- `CHANGELOG.md` — v1.0.0 entry
- `scripts/release.sh` — local pre-flight check (tag, changelog, version bump)
- `scripts/smoke-test.sh` — installs the Linux binary on a fresh VM and runs `desmos up`

**Acceptance Criteria:**
- [ ] Pushing `v1.0.0` triggers the full release build.
- [ ] GitHub Release has artifacts for every Tier 1 + Tier 2 target with SHA-256 sums.
- [ ] `scripts/smoke-test.sh` passes on a fresh Debian 12 VM.
- [ ] Version in `Cargo.toml` of every crate matches `1.0.0`.

**Dependencies:** Task 1-68
**Effort:** 6 hours
**Refs:** PRD §14

---

## Milestones

| Milestone         | After Task | What's Achieved                                               | Demo-able?                       |
|-------------------|------------|---------------------------------------------------------------|----------------------------------|
| Foundation        | 6          | Workspace compiles, CI green on Tier 1                        | `cargo build`                    |
| First Tunnel      | 14         | Plaintext Linux tunnel through TUN + UDP                      | `ping` through `desmos0`         |
| Encrypted Tunnel  | 19         | Noise IK + AEAD tunnel, single interface                      | `iperf3` with encryption         |
| Bonded Tunnel     | 24         | 2+ interfaces via Round-Robin, probing, reorder               | `iperf3` faster than one link    |
| Advanced Bonding  | 29         | 4 strategies, failover, PMTUD                                 | Kill an interface mid-transfer   |
| Server Mode MVP   | 36         | Multi-client Linux server with 4 auth methods                 | Two clients share one server     |
| P2P               | 39         | STUN + hole punch + relay                                     | Two NAT'd peers tunnel           |
| Cross-Platform    | 49         | All 6 platforms, priv drop, MSI, ipk, pkg                     | Run on macOS, Windows, OpenWrt   |
| Web UI Backend    | 58         | HTTP + REST + WS backend complete                             | `curl` every endpoint            |
| Web UI Frontend   | 63         | All 6 screens wired to backend                                | Live browser demo                |
| Polish & Perf     | 67         | Docs complete, benches meet targets                           | Grafana dashboard via Prometheus |
| v1.0 Release      | 69         | All artifacts published, smoke test green                     | Download + install               |

---

## Dependency Graph

```
Phase 0:
[T1 Scaffold] -> [T2 Log] -> [T3 TOML] -> [T4 Schema]
              -> [T5 CLI] -> [T6 CI]

Phase 1:
[T7 DWP] -> [T8 PktBuf] -> [T9 Ring] -> [T10 epoll] -> [T11 Timer]
                                           |
                                           v
                                      [T12 TUN] -> [T13 Socket]
                                                       |
                                                       v
                                                 [T14 Plaintext E2E]

Phase 2:
[T15 Crypto] -> [T16 Noise IK] -> [T17 Session] -> [T19 Encrypted Pipeline]
                                        |                  ^
                                 [T18 Anti-replay] ---------'
[T19] -> [T20 Iface] -> [T21 RR] -> [T22 Reorder] -> [T23 Probe] -> [T24 E2E]

Phase 3:
[T23] -> [T25 Weighted+LA] -> [T26 Redundant]
            |
       [T27 Link SM] -> [T28 PMTUD] -> [T29 Failover E2E]

Phase 4:
[T19,T17] -> [T30 Server] -> [T31 NAT]
                   |
             [T32 PSK+Pub] -> [T33 TOTP] -> [T34 mTLS]
                   |
             [T35 RateLimit] -> [T36 Server CLI]

Phase 5:
[T13] -> [T37 STUN] -> [T38 Holepunch] -> [T39 Relay]

Phase 6:
[T10,T9] -> [T40 kqueue] -> [T41 macOS TUN]
                         -> [T44 FreeBSD TUN]
[T10]    -> [T42 IOCP]   -> [T43 Wintun]
[T41,T43,T44] -> [T45 Priv Drop]
[T45] -> [T46 OpenWrt IPK] -> [T47 OpenWrt UCI/LuCI]
[T44] -> [T48 pfSense]
[T43] -> [T49 Win Service + MSI]

Phase 7:
[T10] -> [T50 HTTP Core] -> [T51 Router] -> [T52 JSON]
                                         -> [T53 WebSocket]
                                         -> [T54 Basic Auth]
[T51,T54] -> [T55 REST Read] -> [T56 REST Write]
[T55] -> [T57 Prometheus]
[T53,T55] -> [T58 WS Stats+Logs]
[T55] -> [T59 Vite Scaffold] -> [T60 build.rs Embed]
[T58,T60] -> [T61 Dashboard] -> [T62 Iface+Bond] -> [T63 Conn+Logs+Settings]
[T45] -> [T64 DNS Leak]

Release:
ALL -> [T65 Docs] -> [T66 ADRs+README]
ALL -> [T67 Benchmarks]
[T45,T46,T49] -> [T68 Packaging Artifacts]
[T66,T67,T68] -> [T69 Release v1.0.0]
```
