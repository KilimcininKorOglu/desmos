//! `ClientRegistry`: the server-side orchestrator that turns raw
//! Noise IK message-1 bytes into fully-installed
//! `Session<Established>` entries in the shared `SessionTable`.
//!
//! Two concerns mix here:
//!
//! - **Handshake driver.** The responder half of every accepted
//!   connection runs inside `accept_client_msg1`. It allocates a
//!   fresh `SessionId`, constructs a `Session<Handshaking>` via
//!   `new_responder`, advances it through the single IK exchange,
//!   and parks the resulting `Session<Established>` in the table.
//! - **Admission control.** `max_clients` caps the active session
//!   count. A fresh msg1 beyond the cap is rejected with
//!   `ServerError::MaxClientsReached` before any crypto runs, so a
//!   handshake flood cannot exhaust the CPU.
//!
//! The registry is `Sync`: the underlying `SessionTable` already
//! uses an `RwLock<HashMap>` and the id allocator is an atomic.
//! Nothing here talks to a socket — the pipeline stage that will
//! eventually own the UDP listener in the daemon runner calls
//! `accept_client_msg1` with whatever bytes showed up and writes
//! the returned `msg2` back to the source addr.

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use desmos_proto::crypto::x25519::PublicKey;
use desmos_proto::crypto::x25519::X25519PrivateKey;
use desmos_proto::handshake::HandshakeError;
use desmos_proto::SessionId;

use crate::session::manager::Slot;
use crate::session::HandshakeOutcome;
use crate::session::Session;
use crate::session::SessionError;
use crate::session::SessionTable;

/// Errors the server-side handshake driver can emit.
#[derive(Debug)]
pub enum ServerError {
    /// The configured `max_clients` cap was reached and the new
    /// handshake was rejected before any crypto work happened.
    MaxClientsReached,
    /// The client msg1 failed the Noise IK checks (bad length,
    /// MAC failure, unknown initiator static).
    Handshake(HandshakeError),
    /// The handshake succeeded on the wire but downstream session
    /// construction tripped an internal error.
    Session(SessionError),
    /// Session id space exhausted — every 16-bit id already
    /// installed. Effectively unreachable under `max_clients`
    /// limits sane operators would ever set, but the path is
    /// handled rather than panicking.
    IdSpaceExhausted,
}

impl From<HandshakeError> for ServerError {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

impl From<SessionError> for ServerError {
    fn from(e: SessionError) -> Self {
        // Lift handshake failures out of the `SessionError`
        // wrapper so callers that only care about the
        // pattern-matching distinction "was this an IK check
        // failure or not" see a clean `ServerError::Handshake`
        // rather than `Session(Handshake(...))`.
        match e {
            SessionError::Handshake(h) => Self::Handshake(h),
            other => Self::Session(other),
        }
    }
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MaxClientsReached => f.write_str("server: max_clients cap reached"),
            Self::Handshake(e) => write!(f, "server: handshake: {e}"),
            Self::Session(e) => write!(f, "server: session: {e}"),
            Self::IdSpaceExhausted => f.write_str("server: session id space exhausted"),
        }
    }
}

impl std::error::Error for ServerError {}

/// Server-side client orchestrator.
pub struct ClientRegistry {
    static_key: X25519PrivateKey,
    known_clients: Vec<PublicKey>,
    prologue: Vec<u8>,
    max_clients: u32,
    next_id: AtomicU16,
    table: SessionTable,
}

impl ClientRegistry {
    /// Construct a fresh registry.
    ///
    /// `static_key` is the server's long-lived X25519 key (read
    /// from `/etc/desmos/server.key` in the daemon). `known_clients`
    /// is the initiator-static whitelist passed to every
    /// `Responder`; an empty vec means "accept any client that
    /// completes the handshake", which is the right default for
    /// the common PSK / web-UI-auth server modes. `prologue` is
    /// the Noise prologue string — callers must match what their
    /// initiator sends.
    pub fn new(
        static_key: X25519PrivateKey,
        known_clients: Vec<PublicKey>,
        prologue: Vec<u8>,
        max_clients: u32,
    ) -> Self {
        Self {
            static_key,
            known_clients,
            prologue,
            max_clients,
            // Start ids at 1; `SessionId(0)` is reserved for
            // "no session" in metrics and log entries.
            next_id: AtomicU16::new(1),
            table: SessionTable::new(),
        }
    }

    /// Configured client cap.
    pub fn max_clients(&self) -> u32 {
        self.max_clients
    }

    /// Number of active session slots in the table.
    pub fn active_clients(&self) -> u32 {
        self.table.len() as u32
    }

    /// Share the underlying `SessionTable` with callers that need
    /// raw lookup access (pipeline stage, `desmos clients` CLI).
    pub fn table(&self) -> &SessionTable {
        &self.table
    }

    /// Drive the Noise IK responder for a freshly arrived msg1.
    /// Returns the allocated `SessionId` and the msg2 bytes the
    /// caller should send back to the source address.
    ///
    /// Admission control happens first: if the table is already at
    /// `max_clients`, `ServerError::MaxClientsReached` is returned
    /// and no handshake work runs. This is the cheap path that a
    /// DoS flood hits — we want it to cost nothing beyond a read
    /// lock on the table.
    pub fn accept_client_msg1(
        &self,
        msg1: &[u8],
        now_ms: u64,
    ) -> Result<(SessionId, Vec<u8>), ServerError> {
        if self.active_clients() >= self.max_clients {
            return Err(ServerError::MaxClientsReached);
        }

        let id = self.allocate_id()?;
        let handshaking = Session::<crate::session::Handshaking>::new_responder(
            id,
            self.static_key.clone(),
            self.known_clients.clone(),
            &self.prologue,
        );

        match handshaking.advance(Some(msg1), now_ms)? {
            HandshakeOutcome::Established { outbound: Some(msg2), session } => {
                self.table.insert(session);
                Ok((id, msg2))
            }
            HandshakeOutcome::Established { outbound: None, .. } => {
                // Responder path always emits msg2; this branch
                // would indicate a Session layer bug.
                Err(ServerError::Session(SessionError::WrongStep))
            }
            HandshakeOutcome::NeedsMore { .. } => {
                // Responder completes in one step for IK. Another
                // Session layer bug path.
                Err(ServerError::Session(SessionError::WrongStep))
            }
        }
    }

    /// Remove a client session from the table. Called by the
    /// keepalive / idle sweeper (Phase 4+) and by explicit
    /// `desmos down` requests.
    pub fn remove_client(&self, id: SessionId) -> Option<Slot> {
        self.table.remove(id)
    }

    /// Shutdown: remove every client session from the table. The
    /// drained slots are returned so callers that need to emit a
    /// "goodbye" control packet per session have the opportunity.
    pub fn shutdown(&self) -> Vec<Slot> {
        let ids: Vec<SessionId> = self.table.ids();
        ids.into_iter().filter_map(|id| self.table.remove(id)).collect()
    }

    /// Atomically allocate a new `SessionId` that is not currently
    /// in the table. Walks the 16-bit space from the current
    /// cursor once; if every id is taken the function returns
    /// `IdSpaceExhausted`.
    fn allocate_id(&self) -> Result<SessionId, ServerError> {
        // 16-bit id space = 65 536 slots. `max_clients` is a u32
        // but the check above rejects anything above
        // `u16::MAX as u32` implicitly by the table becoming full
        // well before the allocator wraps.
        for _ in 0..u16::MAX as u32 + 1 {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed);
            let sid = SessionId(candidate);
            if candidate == 0 {
                // Skip the reserved id.
                continue;
            }
            if !self.table.contains(sid) {
                return Ok(sid);
            }
        }
        Err(ServerError::IdSpaceExhausted)
    }
}

impl core::fmt::Debug for ClientRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientRegistry")
            .field("max_clients", &self.max_clients)
            .field("active_clients", &self.active_clients())
            .field("known_clients", &self.known_clients.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::AnySession;
    use desmos_proto::handshake::HandshakeError;
    use desmos_proto::handshake::Initiator;

    fn server_static() -> X25519PrivateKey {
        X25519PrivateKey::from_bytes([0x22; 32])
    }

    fn client_static(seed: u8) -> X25519PrivateKey {
        X25519PrivateKey::from_bytes([seed; 32])
    }

    fn prologue() -> Vec<u8> {
        b"desmos-server-test".to_vec()
    }

    /// Helper: run the initiator half in-memory and produce the
    /// msg1 bytes that a client would put on the wire.
    fn client_msg1(client_key: &X25519PrivateKey, server_pub: PublicKey) -> Vec<u8> {
        let mut ini = Initiator::new(client_key.clone(), server_pub, &prologue());
        ini.write_message_1().unwrap()
    }

    #[test]
    fn new_registry_is_empty() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        assert_eq!(reg.active_clients(), 0);
        assert_eq!(reg.max_clients(), 10);
    }

    #[test]
    fn accept_installs_session_and_returns_msg2() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();
        let msg1 = client_msg1(&client_static(0x11), server_pub);

        let (sid, msg2) = reg.accept_client_msg1(&msg1, 0).unwrap();
        // msg2 is the Noise IK response packet, fixed layout.
        assert_eq!(msg2.len(), desmos_proto::handshake::noise::MSG_2_LEN);
        assert_eq!(reg.active_clients(), 1);

        // The session landed in the table as Established.
        let slot = reg.table().get(sid).expect("session should be installed");
        let guard = slot.lock().unwrap();
        match &*guard {
            AnySession::Established(s) => assert_eq!(s.id(), sid),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    #[test]
    fn two_clients_get_distinct_session_ids() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();

        let (sid_a, _) =
            reg.accept_client_msg1(&client_msg1(&client_static(0x11), server_pub), 0).unwrap();
        let (sid_b, _) =
            reg.accept_client_msg1(&client_msg1(&client_static(0x33), server_pub), 0).unwrap();

        assert_ne!(sid_a, sid_b);
        assert_eq!(reg.active_clients(), 2);
    }

    #[test]
    fn max_clients_cap_is_enforced_before_crypto() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 2);
        let server_pub = server_static().public_key();

        reg.accept_client_msg1(&client_msg1(&client_static(0x11), server_pub), 0).unwrap();
        reg.accept_client_msg1(&client_msg1(&client_static(0x33), server_pub), 0).unwrap();
        assert_eq!(reg.active_clients(), 2);

        let err =
            reg.accept_client_msg1(&client_msg1(&client_static(0x44), server_pub), 0).unwrap_err();
        assert!(matches!(err, ServerError::MaxClientsReached), "got {err:?}");
        // Still 2 clients — the rejected msg1 never touched the table.
        assert_eq!(reg.active_clients(), 2);
    }

    #[test]
    fn unknown_client_static_is_rejected_when_whitelist_is_set() {
        let allowed = client_static(0x11).public_key();
        let reg = ClientRegistry::new(server_static(), vec![allowed], prologue(), 10);
        let server_pub = server_static().public_key();

        // Client that is NOT on the whitelist.
        let msg1 = client_msg1(&client_static(0x77), server_pub);
        let err = reg.accept_client_msg1(&msg1, 0).unwrap_err();
        match err {
            ServerError::Handshake(HandshakeError::UnknownStatic) => {}
            other => panic!("expected UnknownStatic, got {other:?}"),
        }
        assert_eq!(reg.active_clients(), 0);
    }

    #[test]
    fn malformed_msg1_returns_handshake_error() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let err = reg.accept_client_msg1(&[0u8; 10], 0).unwrap_err();
        match err {
            ServerError::Handshake(HandshakeError::BadMessage) => {}
            other => panic!("expected BadMessage, got {other:?}"),
        }
    }

    #[test]
    fn remove_client_drops_session_from_table() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();
        let (sid, _) =
            reg.accept_client_msg1(&client_msg1(&client_static(0x11), server_pub), 0).unwrap();
        assert_eq!(reg.active_clients(), 1);
        let removed = reg.remove_client(sid);
        assert!(removed.is_some());
        assert_eq!(reg.active_clients(), 0);
        assert!(reg.remove_client(sid).is_none());
    }

    #[test]
    fn shutdown_drains_every_session() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();
        for seed in [0x11u8, 0x22, 0x33, 0x44] {
            reg.accept_client_msg1(&client_msg1(&client_static(seed), server_pub), 0).unwrap();
        }
        assert_eq!(reg.active_clients(), 4);
        let drained = reg.shutdown();
        assert_eq!(drained.len(), 4);
        assert_eq!(reg.active_clients(), 0);
        // Second shutdown is a no-op.
        assert!(reg.shutdown().is_empty());
    }

    #[test]
    fn session_ids_allocate_from_one_and_skip_reserved_zero() {
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();
        let (first, _) =
            reg.accept_client_msg1(&client_msg1(&client_static(0x11), server_pub), 0).unwrap();
        // First allocated id must not be SessionId(0).
        assert_ne!(first.0, 0);
    }

    #[test]
    fn accepting_after_shutdown_still_works() {
        // Regression: the id cursor should keep advancing after
        // shutdown so replacement sessions never collide with
        // newly-removed ids still held by callers.
        let reg = ClientRegistry::new(server_static(), Vec::new(), prologue(), 10);
        let server_pub = server_static().public_key();
        reg.accept_client_msg1(&client_msg1(&client_static(0x11), server_pub), 0).unwrap();
        reg.shutdown();
        let (sid_after, _) =
            reg.accept_client_msg1(&client_msg1(&client_static(0x33), server_pub), 0).unwrap();
        assert_ne!(sid_after.0, 0);
    }
}
