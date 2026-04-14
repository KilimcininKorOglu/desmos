# ADR 0002: Hand-Rolled Async Runtime

**Status:** Accepted
**Date:** 2026-04-10

## Context

Most Rust networking projects use `tokio` or `async-std` for their event
loop. These runtimes are mature and well-tested but bring significant
dependency trees (50+ transitive crates for tokio), increase binary size,
and make the build dependent on ecosystem churn.

Desmos has a strict five-crate dependency budget. Adding tokio alone would
exceed the budget by an order of magnitude. The project also targets
embedded-ish platforms (OpenWrt, pfSense) where a minimal binary matters.

The I/O model is straightforward: read from TUN, write to UDP sockets
(and vice versa), with timers for keepalive and rekey. There is no need
for a general-purpose task scheduler, async/await syntax, or HTTP client.

## Decision

Implement a hand-rolled, single-threaded event loop per platform:

| Platform        | Syscall   | Crate location       |
|-----------------|-----------|----------------------|
| Linux           | `epoll`   | `desmos-rt/epoll.rs` |
| macOS / FreeBSD | `kqueue`  | `desmos-rt/kqueue.rs`|
| Windows         | IOCP      | `desmos-rt/iocp.rs`  |

Each reactor implements a common trait surface: register fd/handle,
poll with timeout, dispatch ready events. The timer wheel (hashed,
64-slot) is shared across platforms.

No `async`/`await`. No `Future` trait. Callbacks are plain function
pointers or closures passed to the reactor.

## Consequences

- Zero external runtime dependencies. The reactor is ~800 lines per
  platform.
- Binary size reduction: ~1 MB saved vs. a tokio-based equivalent.
- `unsafe` is concentrated in one crate (`desmos-rt`), making security
  audits tractable.
- No ecosystem-provided TLS, HTTP client, or DNS resolver — all must
  be hand-rolled or avoided.
- Contributors must understand platform-specific I/O APIs rather than
  tokio abstractions.
- Testing requires platform-specific CI runners (Linux, macOS, Windows).
