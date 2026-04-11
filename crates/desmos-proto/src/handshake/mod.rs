//! Noise IK handshake for Desmos.
//!
//! Variant: `Noise_IK_25519_ChaChaPoly_SHA256`.
//!
//! ```text
//! <- s                 (pre-message; initiator knows responder static)
//! -> e, es, s, ss      (message 1: initiator -> responder)
//! <- e, ee, se         (message 2: responder -> initiator)
//! ```
//!
//! After message 2 both sides `Split()` the chaining key into two transport
//! keys: the initiator-to-responder key and the responder-to-initiator key.
//! Those are what `Session<Established>` uses to seal and open data-plane
//! packets in Task 17.
//!
//! The hash function is SHA-256, not BLAKE3, because a standard Noise variant
//! needs MixHash and HKDF to share a hash family and our `hkdf` module is
//! HMAC-SHA256. The rest of the crate continues to use BLAKE3 elsewhere.

pub mod cookie;
pub mod noise;

pub use cookie::compute_cookie;
pub use cookie::verify_cookie;
pub use cookie::CookieError;
pub use cookie::CookieKey;
pub use cookie::COOKIE_KEY_LEN;
pub use cookie::COOKIE_LEN;
pub use noise::HandshakeError;
pub use noise::Initiator;
pub use noise::Responder;
pub use noise::TransportKeys;
pub use noise::PROTOCOL_NAME;

use ring::digest;

use crate::crypto::aead::AeadKey;
use crate::crypto::aead::KEY_LEN as AEAD_KEY_LEN;
use crate::crypto::aead::NONCE_LEN as AEAD_NONCE_LEN;
use crate::crypto::hkdf;
use crate::crypto::CryptoError;

pub(crate) const HASH_LEN: usize = 32;

/// One-shot SHA-256 that returns a 32-byte array instead of ring's `Digest`.
fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// Noise `SymmetricState` — the chaining key, transcript hash, and current
/// AEAD key + per-key nonce counter. Every MixKey call resets the counter.
pub(crate) struct SymmetricState {
    ck: [u8; HASH_LEN],
    h: [u8; HASH_LEN],
    k: Option<AeadKey>,
    n: u64,
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)` from the Noise spec §5.2.
    pub(crate) fn new(protocol_name: &[u8]) -> Self {
        // If `len(protocol_name) <= HASHLEN` it is zero-padded into `h`,
        // otherwise `h = HASH(protocol_name)`.
        let h = if protocol_name.len() <= HASH_LEN {
            let mut h = [0u8; HASH_LEN];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            sha256(protocol_name)
        };
        Self { ck: h, h, k: None, n: 0 }
    }

    /// `MixKey(input_key_material)` — updates `ck` and resets the cipher.
    pub(crate) fn mix_key(&mut self, ikm: &[u8]) -> Result<(), CryptoError> {
        // HKDF with `salt = ck`, `ikm = input`, no info; take 64 bytes and
        // split into (new_ck, temp_k).
        let mut out = [0u8; HASH_LEN + AEAD_KEY_LEN];
        hkdf::derive(&self.ck, ikm, &[], &mut out)?;
        self.ck.copy_from_slice(&out[..HASH_LEN]);
        self.k = Some(AeadKey::new(&out[HASH_LEN..])?);
        self.n = 0;
        Ok(())
    }

    /// `MixHash(data)` — `h = HASH(h || data)`.
    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(HASH_LEN + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = sha256(&buf);
    }

    /// `EncryptAndHash(plaintext)`. If no key is set yet, the plaintext is
    /// returned as-is and still mixed into the transcript. Otherwise it is
    /// ChaCha20-Poly1305 sealed with `h` as associated data, so any transcript
    /// divergence flips the tag.
    pub(crate) fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = plaintext.to_vec();
        if let Some(k) = self.k.as_ref() {
            let nonce = nonce_bytes(self.n);
            k.seal_in_place(&nonce, &self.h, &mut out)?;
            self.n = self.n.checked_add(1).ok_or(CryptoError::AeadFailed)?;
        }
        self.mix_hash(&out);
        Ok(out)
    }

    /// `DecryptAndHash(ciphertext)`. Mirror of `encrypt_and_hash`. The
    /// ciphertext is always the thing mixed into the transcript, not the
    /// plaintext — otherwise a tag forgery would desync the transcripts.
    pub(crate) fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pt = if let Some(k) = self.k.as_ref() {
            let nonce = nonce_bytes(self.n);
            let mut buf = ciphertext.to_vec();
            let pt_len = {
                let pt = k.open_in_place(&nonce, &self.h, &mut buf)?;
                pt.len()
            };
            self.n = self.n.checked_add(1).ok_or(CryptoError::AeadFailed)?;
            buf.truncate(pt_len);
            buf
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// `Split()` — derive the two transport keys from the final `ck`.
    pub(crate) fn split(&self) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_KEY_LEN]), CryptoError> {
        let mut out = [0u8; AEAD_KEY_LEN * 2];
        hkdf::derive(&self.ck, &[], &[], &mut out)?;
        let mut k1 = [0u8; AEAD_KEY_LEN];
        let mut k2 = [0u8; AEAD_KEY_LEN];
        k1.copy_from_slice(&out[..AEAD_KEY_LEN]);
        k2.copy_from_slice(&out[AEAD_KEY_LEN..]);
        Ok((k1, k2))
    }

    /// Read-only access to the transcript hash for callers that want to
    /// stash it as a channel binding.
    pub(crate) fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.h
    }
}

/// Noise nonce layout (§5.1): 4 zero bytes followed by the 64-bit counter
/// encoded in big-endian, totalling the 96 bits ChaCha20-Poly1305 expects.
fn nonce_bytes(counter: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_matches_noise_spec() {
        let n = nonce_bytes(0x0102_0304_0506_0708);
        assert_eq!(n, [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn symmetric_state_initial_hash_is_padded_protocol_name() {
        let name = b"short_name";
        let s = SymmetricState::new(name);
        let mut expected = [0u8; HASH_LEN];
        expected[..name.len()].copy_from_slice(name);
        assert_eq!(s.h, expected);
        assert_eq!(s.ck, expected);
        assert!(s.k.is_none());
    }

    #[test]
    fn symmetric_state_long_protocol_name_is_hashed() {
        let name = vec![b'x'; HASH_LEN + 1];
        let s = SymmetricState::new(&name);
        assert_eq!(s.h, sha256(&name));
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips_with_matching_states() {
        let mut a = SymmetricState::new(b"test");
        let mut b = SymmetricState::new(b"test");
        a.mix_key(&[0xAAu8; 32]).unwrap();
        b.mix_key(&[0xAAu8; 32]).unwrap();

        let ct = a.encrypt_and_hash(b"hello").unwrap();
        let pt = b.decrypt_and_hash(&ct).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(a.handshake_hash(), b.handshake_hash());
    }

    #[test]
    fn mix_key_resets_nonce_counter() {
        let mut s = SymmetricState::new(b"test");
        s.mix_key(&[1u8; 32]).unwrap();
        let _ = s.encrypt_and_hash(b"one").unwrap();
        assert_eq!(s.n, 1);
        s.mix_key(&[2u8; 32]).unwrap();
        assert_eq!(s.n, 0);
    }

    #[test]
    fn split_is_deterministic_and_two_distinct_keys() {
        let mut s = SymmetricState::new(b"test");
        s.mix_key(&[7u8; 32]).unwrap();
        let (k1, k2) = s.split().unwrap();
        let (k1_again, k2_again) = s.split().unwrap();
        assert_eq!(k1, k1_again);
        assert_eq!(k2, k2_again);
        assert_ne!(k1, k2);
    }

    #[test]
    fn decrypt_with_diverged_transcript_fails() {
        let mut a = SymmetricState::new(b"test");
        let mut b = SymmetricState::new(b"test");
        a.mix_key(&[0xAAu8; 32]).unwrap();
        b.mix_key(&[0xAAu8; 32]).unwrap();
        a.mix_hash(b"alice-only");
        let ct = a.encrypt_and_hash(b"payload").unwrap();
        let err = b.decrypt_and_hash(&ct).unwrap_err();
        assert_eq!(err, CryptoError::AeadFailed);
    }
}
