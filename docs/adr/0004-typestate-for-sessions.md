# ADR 0004: Typestate Pattern for Sessions

**Status:** Accepted
**Date:** 2026-04-10

## Context

A VPN session progresses through distinct phases: initiated, handshaking,
established, and torn down. Each phase has different valid operations:

- An **initiated** session can start a handshake but cannot send data.
- A **handshaking** session can process handshake messages but cannot
  encrypt tunnel traffic.
- An **established** session can encrypt/decrypt traffic and must handle
  rekey events.

Using a single `Session` struct with a `state: SessionState` enum field
allows calling `encrypt()` on a session that hasn't completed its
handshake. Runtime checks (panics or `Result` returns) catch this, but
they push correctness verification to runtime rather than compile time.

## Decision

Use Rust's typestate pattern to encode the session lifecycle in the type
system:

```rust
struct Session<S: SessionPhase> { /* ... */ }

// Phase markers (zero-sized types).
struct Initiator;
struct Handshaking;
struct Established;

impl Session<Initiator> {
    fn begin_handshake(self) -> Session<Handshaking> { /* ... */ }
}

impl Session<Handshaking> {
    fn complete(self) -> Session<Established> { /* ... */ }
}

impl Session<Established> {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> { /* ... */ }
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> { /* ... */ }
}
```

Each phase transition consumes `self` and returns the next phase. The
compiler prevents calling `encrypt()` on a `Session<Handshaking>` — it
is a type error, not a runtime error.

The session manager holds sessions in an enum wrapper for storage:

```rust
enum ManagedSession {
    Initiating(Session<Initiator>),
    Handshaking(Session<Handshaking>),
    Established(Session<Established>),
}
```

## Consequences

- Invalid state transitions are compile-time errors.
- Each phase's API surface is minimal and self-documenting.
- Phase transitions are explicit function calls that consume the old
  state — no "forgotten" transitions or stale state.
- The enum wrapper adds one `match` at the session manager boundary
  but keeps storage homogeneous.
- Generics propagate into functions that accept sessions, requiring
  either concrete phase parameters or trait bounds.
- The pattern is well-established in the Rust ecosystem (see `hyper`'s
  `Request<Body>` builder) and familiar to experienced Rust developers.
