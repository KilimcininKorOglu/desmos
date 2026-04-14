# ADR 0003: Five-Crate Dependency Budget

**Status:** Accepted
**Date:** 2026-04-10

## Context

Supply chain attacks on the Rust ecosystem (and npm, PyPI, etc.) are a
growing concern. Each external dependency is an attack surface: a
compromised crate update can inject malicious code into every downstream
binary. For a VPN — software that handles all network traffic — the
stakes are high.

At the same time, certain operations (authenticated encryption, hashing,
cross-platform socket options, Windows TUN) are impractical to implement
from scratch without introducing bugs worse than the supply chain risk.

## Decision

Allow exactly five external runtime crates:

| Crate     | Version   | Purpose                               |
|-----------|-----------|---------------------------------------|
| `ring`    | 0.17.x    | ChaCha20-Poly1305, PBKDF2, HKDF, X25519 helpers |
| `blake3`  | =1.5.4    | Session key derivation, integrity      |
| `socket2` | 0.5.x     | Cross-platform socket options          |
| `wintun`  | 0.7.x     | Windows TUN adapter (Windows-only)     |

(`argon2` was originally planned as the fifth but is blocked on MSRV
1.75 due to transitive edition 2024 dependencies. Replaced by
`ring::pbkdf2`.)

All other functionality is hand-rolled:

- TOML parser (700 lines)
- JSON codec (500 lines)
- HTTP/1.1 server (1,200 lines)
- WebSocket codec (400 lines)
- CLI parser (300 lines)
- DNS resolver (250 lines)
- Event loop per platform (~800 lines each)

Enforcement: `deny.toml` maintains an explicit allow-list. `cargo deny
check bans` runs in CI on every push.

## Consequences

- Attack surface is auditable: five crates, all widely reviewed
  (ring has undergone formal audit).
- `blake3` is pinned to `=1.5.4` because 1.8+ pulls `constant_time_eq`
  0.4.x which requires edition 2024 (incompatible with MSRV 1.75).
- Hand-rolled components require more code (~5,000 lines total) but are
  fully under project control.
- No `serde`, `clap`, `log`, `tracing`, `hyper`, `reqwest`, or any
  framework dependency.
- Adding a sixth crate requires an ADR amendment and `deny.toml` update.
- Binary size stays under 5 MB (Linux x86_64, stripped, musl).
