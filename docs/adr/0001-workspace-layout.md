# ADR 0001: Seven-Crate Workspace Layout

**Status:** Accepted
**Date:** 2026-04-10

## Context

Desmos is a cross-platform VPN with protocol logic, platform I/O, domain
rules, HTTP serving, a Web UI, and a CLI. Packing all of this into a
single crate would produce a 30,000+ line monolith where a change to a
CLI help string recompiles the crypto stack.

We need a workspace layout that:

1. Enforces dependency direction (protocol code must not pull in OS I/O).
2. Enables parallel compilation across independent crates.
3. Keeps the `no_std`-capable protocol crate truly I/O-free.
4. Isolates `unsafe` syscall FFI to a single auditable crate.

## Decision

Split the project into seven crates forming a strict DAG:

```
desmos-proto   desmos-rt
     \            /
      desmos-core
           |
      desmos-http
       /       \
desmos-webui  desmos-cli
       \       /
        desmos    (binary)
```

- **desmos-proto**: Wire protocol, crypto primitives, handshake state
  machine. I/O-free, `no_std + alloc` compatible.
- **desmos-rt**: Hand-rolled async runtime with per-platform reactor,
  TUN, sockets, timer wheel. The only crate with `unsafe` FFI.
- **desmos-core**: Domain logic — bonding, sessions, config, auth,
  server, network interface discovery.
- **desmos-http**: HTTP/1.1 server, WebSocket, JSON codec, Basic Auth.
- **desmos-webui**: REST handlers, embedded React SPA.
- **desmos-cli**: CLI parser, subcommand dispatcher.
- **desmos**: Binary entry point, daemon runner.

Cargo enforces no cycles. A change in `desmos-cli` does not recompile
`desmos-proto`.

## Consequences

- Seven `Cargo.toml` files to maintain.
- Cross-crate type sharing requires careful `pub use` re-exports.
- Incremental builds are faster: a CLI-only change rebuilds ~2 crates
  instead of all 7.
- `desmos-proto` can be extracted as an independent library for third-party
  DWP implementations.
- `unsafe` audit scope is limited to `desmos-rt` (~3,000 lines).
