# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial Cargo workspace scaffolding (7 crates, pinned toolchain, lint configs, deny policy).
- `desmos-core` error taxonomy (`CoreError`, `ConfigError`, `IoError`) and `Result` alias.
- `desmos-core` structured logger: `log!` macro, `Level`, `Entry`, stderr sink, 500-entry bounded ring, secret-field redactor (`psk`, `password`, `private_key`).
- `desmos-core::config` hand-rolled TOML subset parser (lexer + recursive-descent parser), `Value` tree, `Path` / `ParseError` / `ParseErrorKind` with `path.to.field` Display, `to_toml` serializer, 29 unit tests plus a deterministic 1000-case round-trip fuzzer using a seeded xorshift64 RNG.
- `desmos-core::config::validate` strongly typed `Config` tree (`GeneralConfig`, `ServerConfig`, `ClientConfig`, `WebuiConfig`, `P2pConfig`, `AuthConfig`, `InterfaceConfig`) plus `Mode`, `LogLevel`, `AuthMethod`, `BondingStrategy` enums; `Config::from_value` with `missing_field` / `out_of_range` / `type_mismatch` / `unknown_section` error reporting; Argon2id PHC syntactic recognizer.
- `config/desmos.toml.example` fully commented reference configuration covering client, server, p2p, and Web UI sections.
- `desmos-cli` hand-rolled argument parser, subcommand dispatcher, coloured output layer, and stubs for every standard subcommand (`up`, `down`, `status`, `reload`, `config`, `interfaces`, `bonding`, `clients`, `logs`, `webui`, `version`). Supports global flags `-c/--config`, `-v/--verbose`, `-q/--quiet`, `--no-color`, `--json`, `-h/--help`, `-V/--version`, clustered short flags, inline `--flag=value`, `--` passthrough, and Levenshtein-based closest-match suggestions for typos (exit code 64 on unknown subcommand).
- `desmos` binary now wires `Dispatcher::with_standard_commands` as its entry point so `desmos --help`, `desmos status --json`, and all subcommand stubs work end-to-end.
- GitHub Actions CI bootstrap: `.github/workflows/ci.yml` (fmt, clippy, and the full 7-target Tier 1 build / test matrix across Ubuntu, macOS 14, and Windows, with cross-rs for aarch64-musl and FreeBSD), `.github/workflows/security.yml` (cargo-deny bans/licenses/sources + cargo-audit, weekly cron), and issue templates for bug reports and feature requests.
- `desmos-proto` DWP wire layer: `Header` struct with encode / decode producing the 16-byte big-endian frame from `IMPLEMENTATION.md §4.1`, `PacketType` enum (Data / Handshake / Keepalive / Probe / Control), newtype wrappers `SessionId`, `InterfaceId`, `Seq`, `TimestampUs`, hand-rolled `Flags` bitfield preserving unknown bits, and a `WireError` taxonomy rejecting `UnsupportedVersion`, `UnknownPacketType`, and short buffers. 16 unit tests plus a deterministic xorshift64 1000-case round-trip integration test.
- `desmos-proto::packet` owning `PacketBuf` (boxed slice, `mtu + PACKET_OVERHEAD=256` capacity, `set_len` publishes the filled region) and `PacketMeta` with inbound/outbound constructors.
- `desmos-rt::pool` thread-safe `PacketPool` with prefill, atomic counters (`acquires`, `hits`, `releases`, `allocations`), `PoolStats::hit_rate`, and a 10 000-iteration acceptance test hitting >99% pool reuse. `desmos-rt` now depends on `desmos-proto`.
- `desmos-rt::ring` lock-free SPSC ring buffer with cache-padded head/tail, power-of-two capacity, `Producer` / `Consumer` split handles, `try_push` / `try_pop`, and a 1 000 000-item two-thread stress test verifying FIFO order. First crate with `unsafe` — every block carries an audited SAFETY comment.
