//! Noise IK state machine. The "I" stands for immediate initiator
//! authentication (initiator's static key is sent in message 1) and the
//! "K" stands for known responder static (the initiator pre-knows it).
//!
//! For Desmos the IK pattern is the right fit: the client already has
//! the server's static public key pinned in its config file, and the
//! server learns the client's identity during the first round trip.
//! Two messages, one round trip, mutual authentication.

use crate::crypto::aead::TAG_LEN;
use crate::crypto::x25519::PublicKey;
use crate::crypto::x25519::X25519PrivateKey;
use crate::crypto::x25519::PUBLIC_KEY_LEN;
use crate::crypto::CryptoError;

use super::SymmetricState;
use super::HASH_LEN;

/// Noise protocol name. Its length (31 bytes) is ≤ `HASH_LEN = 32`, so it
/// is zero-padded directly into the initial transcript hash rather than
/// pre-hashed. Matching this exact byte string is required for interop.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";

/// Wire length of the initiator's message 1. `re (32) || enc_s (32+TAG) ||
/// enc_payload (TAG)`.
pub const MSG_1_LEN: usize = PUBLIC_KEY_LEN + (PUBLIC_KEY_LEN + TAG_LEN) + TAG_LEN;

/// Wire length of the responder's message 2. `re (32) || enc_payload (TAG)`.
pub const MSG_2_LEN: usize = PUBLIC_KEY_LEN + TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    Crypto(CryptoError),
    /// Responder received a message 1 whose decoded static key is not on
    /// the initiator whitelist. Matches IMPL §2.3 "pinned peer keys".
    UnknownStatic,
    /// Wire length, internal framing, or DH output was malformed.
    BadMessage,
    /// A state-transition method was called in the wrong phase.
    WrongState,
}

impl From<CryptoError> for HandshakeError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "handshake: {e}"),
            Self::UnknownStatic => f.write_str("handshake: unknown initiator static key"),
            Self::BadMessage => f.write_str("handshake: malformed message"),
            Self::WrongState => f.write_str("handshake: wrong state"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// The output of a completed handshake.
///
/// `send` is the key this side uses to seal outbound data-plane packets;
/// `recv` is the key used to open inbound packets. The split is oriented
/// so both sides see their own outbound key in `send` and the peer's
/// outbound key in `recv`.
#[derive(Clone)]
pub struct TransportKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    /// Final Noise transcript hash, suitable as a channel-binding token.
    pub handshake_hash: [u8; HASH_LEN],
}

impl core::fmt::Debug for TransportKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TransportKeys(<redacted>, h={:02x}{:02x}..{:02x}{:02x})",
            self.handshake_hash[0],
            self.handshake_hash[1],
            self.handshake_hash[HASH_LEN - 2],
            self.handshake_hash[HASH_LEN - 1],
        )
    }
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// Initiator side of Noise IK.
pub struct Initiator {
    symm: SymmetricState,
    s: X25519PrivateKey,
    e: Option<X25519PrivateKey>,
    rs: PublicKey,
}

impl Initiator {
    /// Start a fresh handshake. The initiator must already know the
    /// responder's static public key (otherwise use XX).
    pub fn new(static_key: X25519PrivateKey, responder_static: PublicKey, prologue: &[u8]) -> Self {
        let mut symm = SymmetricState::new(PROTOCOL_NAME);
        symm.mix_hash(prologue);
        // Pre-message token `<- s`: both sides mix in the responder static.
        symm.mix_hash(&responder_static.0);
        Self { symm, s: static_key, e: None, rs: responder_static }
    }

    /// Emit message 1: `e, es, s, ss` followed by an empty encrypted payload.
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.e.is_some() {
            return Err(HandshakeError::WrongState);
        }
        // Token `e`: generate the ephemeral and mix its public half.
        let e = X25519PrivateKey::generate()?;
        let e_pub = e.public_key();
        self.symm.mix_hash(&e_pub.0);
        // Token `es`: DH(e_i, s_r).
        let dh_es = e.diffie_hellman(&self.rs);
        self.symm.mix_key(&dh_es)?;
        // Token `s`: send the initiator static under the current key.
        let s_pub = self.s.public_key();
        let enc_s = self.symm.encrypt_and_hash(&s_pub.0)?;
        // Token `ss`: DH(s_i, s_r).
        let dh_ss = self.s.diffie_hellman(&self.rs);
        self.symm.mix_key(&dh_ss)?;
        // Empty payload, still authenticated.
        let enc_payload = self.symm.encrypt_and_hash(&[])?;

        self.e = Some(e);

        let mut out = Vec::with_capacity(MSG_1_LEN);
        out.extend_from_slice(&e_pub.0);
        out.extend_from_slice(&enc_s);
        out.extend_from_slice(&enc_payload);
        debug_assert_eq!(out.len(), MSG_1_LEN);
        Ok(out)
    }

    /// Consume the responder's message 2 and return the transport keys.
    pub fn read_message_2(mut self, msg: &[u8]) -> Result<TransportKeys, HandshakeError> {
        if msg.len() != MSG_2_LEN {
            return Err(HandshakeError::BadMessage);
        }
        let e = self.e.take().ok_or(HandshakeError::WrongState)?;
        let re = PublicKey({
            let mut a = [0u8; PUBLIC_KEY_LEN];
            a.copy_from_slice(&msg[..PUBLIC_KEY_LEN]);
            a
        });
        let enc_payload = &msg[PUBLIC_KEY_LEN..];
        // Token `e` (responder's ephemeral).
        self.symm.mix_hash(&re.0);
        // Token `ee`: DH(e_i, e_r).
        let dh_ee = e.diffie_hellman(&re);
        self.symm.mix_key(&dh_ee)?;
        // Token `se`: DH(s_i, e_r).
        let dh_se = self.s.diffie_hellman(&re);
        self.symm.mix_key(&dh_se)?;
        // Verify empty payload MAC.
        let pt = self.symm.decrypt_and_hash(enc_payload)?;
        if !pt.is_empty() {
            return Err(HandshakeError::BadMessage);
        }
        // Split. Initiator's send key is the first half, recv is second.
        let (k_i2r, k_r2i) = self.symm.split()?;
        Ok(TransportKeys { send: k_i2r, recv: k_r2i, handshake_hash: self.symm.handshake_hash() })
    }
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initiator")
            .field("rs", &self.rs)
            .field("has_ephemeral", &self.e.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Responder side of Noise IK.
pub struct Responder {
    symm: SymmetricState,
    s: X25519PrivateKey,
    /// Learned during `read_message_1`.
    re: Option<PublicKey>,
    /// Learned during `read_message_1`.
    rs: Option<PublicKey>,
    /// Initiator static whitelist. Empty = accept any initiator that
    /// completes the handshake (still mutually authenticated by DH).
    known_initiators: Vec<PublicKey>,
}

impl Responder {
    pub fn new(
        static_key: X25519PrivateKey,
        known_initiators: Vec<PublicKey>,
        prologue: &[u8],
    ) -> Self {
        let mut symm = SymmetricState::new(PROTOCOL_NAME);
        symm.mix_hash(prologue);
        let s_pub = static_key.public_key();
        symm.mix_hash(&s_pub.0);
        Self { symm, s: static_key, re: None, rs: None, known_initiators }
    }

    /// Decode the initiator's message 1.
    ///
    /// Populates `re` and `rs` so `write_message_2` can finish the
    /// handshake. Rejects the message if the decoded initiator static key
    /// is not on the whitelist (when the whitelist is non-empty).
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if msg.len() != MSG_1_LEN {
            return Err(HandshakeError::BadMessage);
        }
        if self.re.is_some() {
            return Err(HandshakeError::WrongState);
        }

        let re_bytes = &msg[..PUBLIC_KEY_LEN];
        let enc_s = &msg[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + TAG_LEN];
        let enc_payload = &msg[PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + TAG_LEN..];

        let re = PublicKey({
            let mut a = [0u8; PUBLIC_KEY_LEN];
            a.copy_from_slice(re_bytes);
            a
        });
        // Token `e`.
        self.symm.mix_hash(&re.0);
        // Token `es`: DH(s_r, e_i) on the responder side.
        let dh_es = self.s.diffie_hellman(&re);
        self.symm.mix_key(&dh_es)?;
        // Token `s`: decrypt the initiator static.
        let s_bytes = self.symm.decrypt_and_hash(enc_s)?;
        if s_bytes.len() != PUBLIC_KEY_LEN {
            return Err(HandshakeError::BadMessage);
        }
        let rs = PublicKey({
            let mut a = [0u8; PUBLIC_KEY_LEN];
            a.copy_from_slice(&s_bytes);
            a
        });
        if !self.known_initiators.is_empty() && !self.known_initiators.iter().any(|k| k.0 == rs.0) {
            return Err(HandshakeError::UnknownStatic);
        }
        // Token `ss`: DH(s_r, s_i).
        let dh_ss = self.s.diffie_hellman(&rs);
        self.symm.mix_key(&dh_ss)?;
        // Verify empty payload MAC.
        let pt = self.symm.decrypt_and_hash(enc_payload)?;
        if !pt.is_empty() {
            return Err(HandshakeError::BadMessage);
        }

        self.re = Some(re);
        self.rs = Some(rs);
        Ok(())
    }

    /// Emit message 2 and finalise the handshake. Consumes `self`.
    pub fn write_message_2(mut self) -> Result<(Vec<u8>, TransportKeys), HandshakeError> {
        let re = self.re.take().ok_or(HandshakeError::WrongState)?;
        let rs = self.rs.take().ok_or(HandshakeError::WrongState)?;

        // Token `e`: responder generates an ephemeral.
        let e = X25519PrivateKey::generate()?;
        let e_pub = e.public_key();
        self.symm.mix_hash(&e_pub.0);
        // Token `ee`: DH(e_r, e_i).
        let dh_ee = e.diffie_hellman(&re);
        self.symm.mix_key(&dh_ee)?;
        // Token `se`: Noise §7 defines it as DH(s_initiator, e_responder);
        // on the responder side that is DH(local_ephemeral, remote_static).
        let dh_se = e.diffie_hellman(&rs);
        self.symm.mix_key(&dh_se)?;
        // Empty payload MAC.
        let enc_payload = self.symm.encrypt_and_hash(&[])?;

        let mut out = Vec::with_capacity(MSG_2_LEN);
        out.extend_from_slice(&e_pub.0);
        out.extend_from_slice(&enc_payload);
        debug_assert_eq!(out.len(), MSG_2_LEN);

        // Split: responder-to-initiator is `recv` for the responder.
        let (k_i2r, k_r2i) = self.symm.split()?;
        let keys =
            TransportKeys { send: k_r2i, recv: k_i2r, handshake_hash: self.symm.handshake_hash() };
        Ok((out, keys))
    }

    /// Expose the initiator static key that was learned from message 1,
    /// once `read_message_1` has succeeded. Returns `None` before then.
    pub fn initiator_static(&self) -> Option<&PublicKey> {
        self.rs.as_ref()
    }
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("has_initiator_ephemeral", &self.re.is_some())
            .field("has_initiator_static", &self.rs.is_some())
            .field("whitelist_len", &self.known_initiators.len())
            .finish()
    }
}
