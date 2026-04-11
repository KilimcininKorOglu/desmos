//! Session typestate.
//!
//! A `Session<S>` moves through four compile-time states:
//!
//! ```text
//! Session<Handshaking>  ───advance──▶  Session<Established>
//!                                             │
//!                                        begin_rekey
//!                                             ▼
//!                                      Session<Rekeying>  ───advance_rekey──▶  Session<Established>
//!                                             │
//!                                           close
//!                                             ▼
//!                                        Session<Closed>
//! ```
//!
//! The whole point is that `encrypt_data` and `decrypt_data` only exist
//! on `Session<Established>` (and, for decryption of in-flight traffic,
//! on `Session<Rekeying>`). Calling them on a fresh `Session<Handshaking>`
//! is a compile error, not a runtime panic.
//!
//! # Compile-time safety
//!
//! ```compile_fail
//! # use desmos_core::session::{new_initiator_for_doctest, Session, Handshaking};
//! let s: Session<Handshaking> = new_initiator_for_doctest();
//! // `encrypt_data` is not in scope on `Session<Handshaking>`.
//! let _ = s.encrypt_data(b"secret");
//! ```

pub mod keepalive;
pub mod manager;
pub mod rekey;

pub use manager::AnySession;
pub use manager::SessionTable;
pub use rekey::REKEY_INTERVAL_MS;

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use desmos_proto::antireplay::AntiReplayWindow;
use desmos_proto::antireplay::ReplayError;
use desmos_proto::crypto::aead::AeadKey;
use desmos_proto::crypto::aead::NONCE_LEN;
use desmos_proto::crypto::x25519::PublicKey;
use desmos_proto::crypto::x25519::X25519PrivateKey;
use desmos_proto::crypto::CryptoError;
use desmos_proto::handshake::HandshakeError;
use desmos_proto::handshake::Initiator;
use desmos_proto::handshake::Responder;
use desmos_proto::handshake::TransportKeys;
use desmos_proto::SessionId;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SessionError {
    Handshake(HandshakeError),
    Crypto(CryptoError),
    /// Anti-replay window rejected the packet (duplicate or out-of-window).
    Replay(ReplayError),
    /// `encrypt_data` or `decrypt_data` called with a sequence number
    /// that would overflow the 64-bit counter (2^64 packets — will not
    /// happen in practice but we refuse rather than wrap).
    CounterOverflow,
    /// `advance` called with the wrong kind of message for the current
    /// role (e.g. responder with `None`, initiator past the second
    /// exchange).
    WrongStep,
}

impl From<HandshakeError> for SessionError {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

impl From<ReplayError> for SessionError {
    fn from(e: ReplayError) -> Self {
        Self::Replay(e)
    }
}

impl From<CryptoError> for SessionError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handshake(e) => write!(f, "session: handshake: {e}"),
            Self::Crypto(e) => write!(f, "session: crypto: {e}"),
            Self::Replay(e) => write!(f, "session: {e}"),
            Self::CounterOverflow => f.write_str("session: send counter overflow"),
            Self::WrongStep => f.write_str("session: advance called in wrong step"),
        }
    }
}

impl std::error::Error for SessionError {}

// ---------------------------------------------------------------------------
// State markers
// ---------------------------------------------------------------------------

/// State marker: the handshake is in flight. No data-plane crypto
/// methods are reachable from this state.
pub struct Handshaking {
    inner: HandshakeInner,
}

enum HandshakeInner {
    Initiator(Initiator),
    Responder(Responder),
}

impl core::fmt::Debug for Handshaking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.inner {
            HandshakeInner::Initiator(_) => f.write_str("Handshaking(Initiator)"),
            HandshakeInner::Responder(_) => f.write_str("Handshaking(Responder)"),
        }
    }
}

/// State marker: handshake completed, transport keys derived, data-plane
/// encryption enabled. `encrypt_data`, `decrypt_data`, `needs_rekey`, and
/// `begin_rekey` live on this state.
pub struct Established {
    send_key: AeadKey,
    recv_key: AeadKey,
    send_counter: AtomicU64,
    /// Per-session anti-replay window guarding `decrypt_data`. Wrapped
    /// in a `Mutex` because `decrypt_data` takes `&self` (so the
    /// session is `Sync` for `SessionTable` storage) but the window is
    /// mutable state.
    recv_window: Mutex<AntiReplayWindow>,
    established_at_ms: u64,
    handshake_hash: [u8; 32],
}

impl core::fmt::Debug for Established {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Established")
            .field("established_at_ms", &self.established_at_ms)
            .field("send_counter", &self.send_counter.load(Ordering::SeqCst))
            .finish()
    }
}

/// State marker: a rekey is in progress. Inbound decryption still uses
/// the old keys until the new handshake finalises so in-flight packets
/// are not lost. Outbound encryption is refused on this state — the
/// pipeline must wait for the new `Established`.
pub struct Rekeying {
    old: Established,
    new: Box<Session<Handshaking>>,
}

impl core::fmt::Debug for Rekeying {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rekeying").field("old", &self.old).finish()
    }
}

/// State marker: terminal state. Nothing can happen on a closed session.
#[derive(Debug, Default)]
pub struct Closed;

// ---------------------------------------------------------------------------
// Session<S>
// ---------------------------------------------------------------------------

/// Generic session wrapper. The state parameter `S` is one of
/// [`Handshaking`], [`Established`], [`Rekeying`], or [`Closed`].
#[derive(Debug)]
pub struct Session<S> {
    id: SessionId,
    state: S,
}

impl<S> Session<S> {
    pub fn id(&self) -> SessionId {
        self.id
    }
}

// ---------------------------------------------------------------------------
// Session<Handshaking>
// ---------------------------------------------------------------------------

/// Return value of `Session<Handshaking>::advance`.
///
/// `Session<Established>` holds two 32-byte ChaCha20-Poly1305 keys
/// (each ~600 bytes inside `ring::aead::LessSafeKey`) so the enum ends
/// up around 1.2 KB. The value is pattern-matched and consumed in the
/// same statement, so the size does not hurt anything.
#[allow(clippy::large_enum_variant)]
pub enum HandshakeOutcome {
    /// The handshake continues. Send `outbound` to the peer and call
    /// `advance` again when the peer replies.
    NeedsMore { outbound: Vec<u8>, next: Session<Handshaking> },
    /// The handshake is complete. If `outbound` is `Some`, send that
    /// final message to the peer. `session` is ready for data traffic.
    Established { outbound: Option<Vec<u8>>, session: Session<Established> },
}

impl Session<Handshaking> {
    /// Open a client-side session: we are the initiator and already know
    /// the server's static public key.
    pub fn new_initiator(
        id: SessionId,
        static_key: X25519PrivateKey,
        responder_static: PublicKey,
        prologue: &[u8],
    ) -> Self {
        Self {
            id,
            state: Handshaking {
                inner: HandshakeInner::Initiator(Initiator::new(
                    static_key,
                    responder_static,
                    prologue,
                )),
            },
        }
    }

    /// Open a server-side session: we are the responder and optionally
    /// pin a whitelist of initiator static keys.
    pub fn new_responder(
        id: SessionId,
        static_key: X25519PrivateKey,
        known_initiators: Vec<PublicKey>,
        prologue: &[u8],
    ) -> Self {
        Self {
            id,
            state: Handshaking {
                inner: HandshakeInner::Responder(Responder::new(
                    static_key,
                    known_initiators,
                    prologue,
                )),
            },
        }
    }

    /// Drive the handshake forward. Consumes `self` and returns either a
    /// new `Session<Handshaking>` (when the handshake still has more
    /// messages) or a `Session<Established>` (when it is done).
    ///
    /// `peer_msg` is the message received from the peer; pass `None` on
    /// the very first call for an initiator (no peer message yet) and
    /// `Some(msg1)` on the first call for a responder.
    pub fn advance(
        self,
        peer_msg: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<HandshakeOutcome, SessionError> {
        let id = self.id;
        match self.state.inner {
            HandshakeInner::Initiator(mut ini) => match peer_msg {
                None => {
                    let msg1 = ini.write_message_1()?;
                    Ok(HandshakeOutcome::NeedsMore {
                        outbound: msg1,
                        next: Session {
                            id,
                            state: Handshaking { inner: HandshakeInner::Initiator(ini) },
                        },
                    })
                }
                Some(msg2) => {
                    let keys = ini.read_message_2(msg2)?;
                    let session = established_from_keys(id, keys, now_ms)?;
                    Ok(HandshakeOutcome::Established { outbound: None, session })
                }
            },
            HandshakeInner::Responder(mut res) => {
                let msg1 = peer_msg.ok_or(SessionError::WrongStep)?;
                res.read_message_1(msg1)?;
                let (msg2, keys) = res.write_message_2()?;
                let session = established_from_keys(id, keys, now_ms)?;
                Ok(HandshakeOutcome::Established { outbound: Some(msg2), session })
            }
        }
    }
}

fn established_from_keys(
    id: SessionId,
    keys: TransportKeys,
    now_ms: u64,
) -> Result<Session<Established>, SessionError> {
    let send_key = AeadKey::new(&keys.send)?;
    let recv_key = AeadKey::new(&keys.recv)?;
    Ok(Session {
        id,
        state: Established {
            send_key,
            recv_key,
            send_counter: AtomicU64::new(0),
            recv_window: Mutex::new(AntiReplayWindow::new()),
            established_at_ms: now_ms,
            handshake_hash: keys.handshake_hash,
        },
    })
}

// ---------------------------------------------------------------------------
// Session<Established>
// ---------------------------------------------------------------------------

impl Session<Established> {
    /// Seal `plaintext` with the session's send key and return the
    /// sequence number that was used together with the ciphertext.
    /// The pipeline stage stamps `seq` into the DWP header before
    /// putting the packet on the wire.
    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), SessionError> {
        let seq = self.state.send_counter.fetch_add(1, Ordering::SeqCst);
        if seq == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }
        let nonce = build_nonce(seq);
        let aad = build_aad(self.id, seq);
        let mut buf = plaintext.to_vec();
        self.state.send_key.seal_in_place(&nonce, &aad, &mut buf)?;
        Ok((seq, buf))
    }

    /// Convenience wrapper over [`encrypt_packet`](Self::encrypt_packet)
    /// for call sites that do not need the sequence number back.
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.encrypt_packet(plaintext).map(|(_, ct)| ct)
    }

    /// Open a received packet.
    ///
    /// Anti-replay is enforced first: duplicates and out-of-window
    /// sequences return `SessionError::Replay` without touching the
    /// AEAD. Successful opens update the window. `ciphertext` is
    /// opened in place; the returned `Vec` is a copy of the plaintext
    /// region.
    pub fn decrypt_data(&self, seq: u64, ciphertext: &mut [u8]) -> Result<Vec<u8>, SessionError> {
        {
            let mut window = self.state.recv_window.lock().unwrap();
            window.check_and_update(seq)?;
        }
        let nonce = build_nonce(seq);
        let aad = build_aad(self.id, seq);
        let pt = self.state.recv_key.open_in_place(&nonce, &aad, ciphertext)?;
        Ok(pt.to_vec())
    }

    /// `true` if the session is at or past the 120-second rekey window.
    pub fn needs_rekey(&self, now_ms: u64) -> bool {
        rekey::is_due(self.state.established_at_ms, now_ms)
    }

    /// Read-only access to the final Noise transcript hash — used as a
    /// channel binding for upper-layer authentication.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.state.handshake_hash
    }

    /// Current send counter. Useful for metrics / tests.
    pub fn send_counter(&self) -> u64 {
        self.state.send_counter.load(Ordering::SeqCst)
    }

    /// Begin a rekey by attaching a fresh initiator-side handshake. The
    /// old keys stay available for inbound decryption until
    /// `Session<Rekeying>::advance_rekey` finalises.
    pub fn begin_rekey(
        self,
        static_key: X25519PrivateKey,
        responder_static: PublicKey,
        prologue: &[u8],
    ) -> Session<Rekeying> {
        let new =
            Session::<Handshaking>::new_initiator(self.id, static_key, responder_static, prologue);
        Session { id: self.id, state: Rekeying { old: self.state, new: Box::new(new) } }
    }

    /// Close the session. Consumes self; the only reachable state
    /// afterwards is `Session<Closed>`.
    pub fn close(self) -> Session<Closed> {
        Session { id: self.id, state: Closed }
    }
}

// ---------------------------------------------------------------------------
// Session<Rekeying>
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
pub enum RekeyOutcome {
    NeedsMore { outbound: Vec<u8>, next: Session<Rekeying> },
    Finished(Session<Established>),
}

impl Session<Rekeying> {
    /// Decrypt an in-flight packet with the *old* keys. The new
    /// handshake has not finalised yet, so freshly-sent packets may
    /// still arrive under the previous epoch. The old session's
    /// anti-replay window is still enforced.
    pub fn decrypt_with_old(
        &self,
        seq: u64,
        ciphertext: &mut [u8],
    ) -> Result<Vec<u8>, SessionError> {
        {
            let mut window = self.state.old.recv_window.lock().unwrap();
            window.check_and_update(seq)?;
        }
        let nonce = build_nonce(seq);
        let aad = build_aad(self.id, seq);
        let pt = self.state.old.recv_key.open_in_place(&nonce, &aad, ciphertext)?;
        Ok(pt.to_vec())
    }

    /// Drive the embedded handshake. Matches the shape of
    /// `Session<Handshaking>::advance` but returns `RekeyOutcome` so the
    /// caller can distinguish "still rekeying" from "new epoch ready".
    pub fn advance_rekey(
        self,
        peer_msg: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<RekeyOutcome, SessionError> {
        let Session { id, state: Rekeying { old, new } } = self;
        match (*new).advance(peer_msg, now_ms)? {
            HandshakeOutcome::NeedsMore { outbound, next } => Ok(RekeyOutcome::NeedsMore {
                outbound,
                next: Session { id, state: Rekeying { old, new: Box::new(next) } },
            }),
            HandshakeOutcome::Established { session, .. } => {
                // The new epoch takes over. `old` falls out of scope
                // here, dropping the previous transport keys.
                let _ = old;
                Ok(RekeyOutcome::Finished(session))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Nonce + AAD helpers
// ---------------------------------------------------------------------------

/// Build a DWP-compatible ChaCha20-Poly1305 nonce: 4 zero bytes followed
/// by the 64-bit sequence counter in big-endian. Matches the Noise wire
/// layout from `handshake::SymmetricState` for consistency.
fn build_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Associated data that binds the packet to its session and its
/// position in the stream. A packet encrypted with `(sid, seq)` cannot
/// be replayed into a different session or a different sequence slot
/// without the tag failing to verify.
fn build_aad(id: SessionId, seq: u64) -> [u8; 10] {
    let mut aad = [0u8; 10];
    aad[..2].copy_from_slice(&id.0.to_be_bytes());
    aad[2..].copy_from_slice(&seq.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Doctest helper — only visible when running the crate tests.
// ---------------------------------------------------------------------------

/// Not public API. Used by the module-level `compile_fail` doctest to
/// construct a dummy `Session<Handshaking>` without forcing the doctest
/// to generate a real keypair. Hidden from the rustdoc output.
#[doc(hidden)]
pub fn new_initiator_for_doctest() -> Session<Handshaking> {
    let sk = X25519PrivateKey::from_bytes([0x11; 32]);
    let peer = X25519PrivateKey::from_bytes([0x22; 32]).public_key();
    Session::<Handshaking>::new_initiator(SessionId(1), sk, peer, b"doctest")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ini_static() -> X25519PrivateKey {
        X25519PrivateKey::from_bytes([0x11; 32])
    }

    fn res_static() -> X25519PrivateKey {
        X25519PrivateKey::from_bytes([0x22; 32])
    }

    fn full_handshake() -> (Session<Established>, Session<Established>) {
        let ini = Session::<Handshaking>::new_initiator(
            SessionId(7),
            ini_static(),
            res_static().public_key(),
            b"test",
        );
        let res =
            Session::<Handshaking>::new_responder(SessionId(7), res_static(), Vec::new(), b"test");

        let (msg1, ini) = match ini.advance(None, 0).unwrap() {
            HandshakeOutcome::NeedsMore { outbound, next } => (outbound, next),
            _ => panic!("initiator should need more after first advance"),
        };
        let (msg2, res_established) = match res.advance(Some(&msg1), 0).unwrap() {
            HandshakeOutcome::Established { outbound, session } => {
                (outbound.expect("responder emits msg2"), session)
            }
            _ => panic!("responder should be established after msg1"),
        };
        let ini_established = match ini.advance(Some(&msg2), 0).unwrap() {
            HandshakeOutcome::Established { outbound, session } => {
                assert!(outbound.is_none());
                session
            }
            _ => panic!("initiator should be established after msg2"),
        };
        (ini_established, res_established)
    }

    #[test]
    fn handshaking_advances_to_established() {
        let (ini, res) = full_handshake();
        assert_eq!(ini.id(), SessionId(7));
        assert_eq!(res.id(), SessionId(7));
        assert_eq!(ini.handshake_hash(), res.handshake_hash());
        assert_eq!(ini.send_counter(), 0);
        assert_eq!(res.send_counter(), 0);
    }

    #[test]
    fn encrypt_on_ini_decrypts_on_res() {
        let (ini, res) = full_handshake();
        let ct = ini.encrypt_data(b"hello world").unwrap();
        let mut buf = ct.clone();
        let pt = res.decrypt_data(0, &mut buf).unwrap();
        assert_eq!(pt, b"hello world");
        assert_eq!(ini.send_counter(), 1);
    }

    #[test]
    fn encrypt_on_res_decrypts_on_ini() {
        let (ini, res) = full_handshake();
        let ct = res.encrypt_data(b"response").unwrap();
        let mut buf = ct.clone();
        let pt = ini.decrypt_data(0, &mut buf).unwrap();
        assert_eq!(pt, b"response");
    }

    #[test]
    fn counter_increments_across_calls() {
        let (ini, _res) = full_handshake();
        let _ = ini.encrypt_data(b"a").unwrap();
        let _ = ini.encrypt_data(b"b").unwrap();
        let _ = ini.encrypt_data(b"c").unwrap();
        assert_eq!(ini.send_counter(), 3);
    }

    #[test]
    fn decrypt_with_wrong_session_id_fails() {
        let (ini, _res) = full_handshake();
        let ct = ini.encrypt_data(b"secret").unwrap();
        // Build a phony Established for a different session id by
        // running another full handshake with the same static keys but
        // a different SessionId.
        let (_other_ini, other_res) = {
            let ini = Session::<Handshaking>::new_initiator(
                SessionId(42),
                ini_static(),
                res_static().public_key(),
                b"test",
            );
            let res = Session::<Handshaking>::new_responder(
                SessionId(42),
                res_static(),
                Vec::new(),
                b"test",
            );
            let (m1, ini) = match ini.advance(None, 0).unwrap() {
                HandshakeOutcome::NeedsMore { outbound, next } => (outbound, next),
                _ => unreachable!(),
            };
            let (m2, other_res) = match res.advance(Some(&m1), 0).unwrap() {
                HandshakeOutcome::Established { outbound, session } => (outbound.unwrap(), session),
                _ => unreachable!(),
            };
            let other_ini = match ini.advance(Some(&m2), 0).unwrap() {
                HandshakeOutcome::Established { session, .. } => session,
                _ => unreachable!(),
            };
            (other_ini, other_res)
        };

        let mut buf = ct.clone();
        let err = other_res.decrypt_data(0, &mut buf).unwrap_err();
        assert!(matches!(err, SessionError::Crypto(_)));
    }

    #[test]
    fn needs_rekey_triggers_at_120_seconds() {
        let (ini, _res) = full_handshake();
        assert!(!ini.needs_rekey(0));
        assert!(!ini.needs_rekey(119_999));
        assert!(ini.needs_rekey(120_000));
        assert!(ini.needs_rekey(999_999));
    }

    #[test]
    fn begin_rekey_moves_to_rekeying_state() {
        let (ini, _res) = full_handshake();
        let rekeying = ini.begin_rekey(ini_static(), res_static().public_key(), b"rekey");
        assert_eq!(rekeying.id(), SessionId(7));
    }

    #[test]
    fn rekeying_can_still_decrypt_old_inflight_traffic() {
        let (ini, res) = full_handshake();
        // Send one packet before the rekey starts.
        let ct = res.encrypt_data(b"in-flight").unwrap();
        let rekeying = ini.begin_rekey(ini_static(), res_static().public_key(), b"rekey");
        let mut buf = ct.clone();
        let pt = rekeying.decrypt_with_old(0, &mut buf).unwrap();
        assert_eq!(pt, b"in-flight");
    }

    #[test]
    fn close_moves_to_closed_state() {
        let (ini, _res) = full_handshake();
        let closed = ini.close();
        assert_eq!(closed.id(), SessionId(7));
    }

    #[test]
    fn aad_binds_session_id_and_seq() {
        let a = build_aad(SessionId(1), 0);
        let b = build_aad(SessionId(1), 1);
        let c = build_aad(SessionId(2), 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn nonce_layout_is_four_zero_then_big_endian_counter() {
        let n = build_nonce(0x0102_0304_0506_0708);
        assert_eq!(n, [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn encrypt_packet_returns_the_seq_that_was_used() {
        let (ini, _res) = full_handshake();
        let (seq0, _) = ini.encrypt_packet(b"first").unwrap();
        let (seq1, _) = ini.encrypt_packet(b"second").unwrap();
        let (seq2, _) = ini.encrypt_packet(b"third").unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(ini.send_counter(), 3);
    }

    #[test]
    fn decrypt_rejects_replay_of_the_same_packet() {
        let (ini, res) = full_handshake();
        let (seq, ct) = ini.encrypt_packet(b"once").unwrap();
        let mut first = ct.clone();
        let mut second = ct;
        res.decrypt_data(seq, &mut first).unwrap();
        let err = res.decrypt_data(seq, &mut second).unwrap_err();
        assert!(matches!(err, SessionError::Replay(_)), "got {err:?}");
    }

    #[test]
    fn decrypt_rejects_out_of_window_sequence() {
        let (ini, res) = full_handshake();
        // Advance the initiator counter past the 128-wide window.
        for _ in 0..200u64 {
            let _ = ini.encrypt_data(b"skip").unwrap();
        }
        // Now send a real packet; the receiver sees it and slides past.
        let (seq_high, ct_high) = ini.encrypt_packet(b"fresh").unwrap();
        let mut buf = ct_high.clone();
        res.decrypt_data(seq_high, &mut buf).unwrap();

        // Synthesise an ancient sequence that is well below the window tail.
        // We cannot actually encrypt at that seq without rewinding the
        // counter, so test that the window alone rejects the call before
        // AEAD runs by passing any nonsense ciphertext — the replay check
        // fires first.
        let mut bogus = vec![0u8; 32];
        let err = res.decrypt_data(0, &mut bogus).unwrap_err();
        assert!(matches!(err, SessionError::Replay(_)), "got {err:?}");
    }
}
