//! X25519 public API built on the hand-rolled scalar multiplier in
//! [`super::x25519_field`]. `ring::agreement` cannot serve Noise IK
//! because `EphemeralPrivateKey::diffie_hellman` consumes `self` and
//! `SecureRandom` is a sealed trait, so we cannot construct a reusable
//! private key from seed bytes. The Noise IK pattern needs the initiator's
//! ephemeral and static keys reused twice each (`es` + `ee`, `ss` + `se`),
//! so we ship our own X25519 instead.
//!
//! Key generation draws entropy from `ring::rand::SystemRandom`; all the
//! actual scalar math lives in `x25519_field.rs`.

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

use super::x25519_field::scalarmult;
use super::x25519_field::scalarmult_base;
use super::CryptoError;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SHARED_SECRET_LEN: usize = 32;
pub const PRIVATE_KEY_LEN: usize = 32;

/// Persistent X25519 private key. Unlike `ring::agreement::EphemeralPrivateKey`
/// this can run `diffie_hellman` any number of times against any peer,
/// which is what Noise IK requires.
#[derive(Clone)]
pub struct X25519PrivateKey {
    seed: [u8; PRIVATE_KEY_LEN],
}

impl X25519PrivateKey {
    /// Draw 32 fresh bytes of entropy and wrap them. The actual
    /// RFC 7748 clamping happens inside `scalarmult`, so the stored
    /// seed is the raw value the RNG produced.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let mut seed = [0u8; PRIVATE_KEY_LEN];
        rng.fill(&mut seed).map_err(|_| CryptoError::X25519Failed)?;
        Ok(Self { seed })
    }

    /// Wrap an existing 32-byte seed. Useful for deterministic test
    /// vectors and for on-disk static keys.
    pub fn from_bytes(seed: [u8; PRIVATE_KEY_LEN]) -> Self {
        Self { seed }
    }

    /// Derive the corresponding public key via `scalarmult(seed, basepoint)`.
    pub fn public_key(&self) -> PublicKey {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        scalarmult_base(&mut out, &self.seed);
        PublicKey(out)
    }

    /// Perform X25519 Diffie-Hellman against `peer`. Non-consuming by
    /// design — Noise IK calls this twice on each side of the handshake.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; SHARED_SECRET_LEN] {
        let mut shared = [0u8; SHARED_SECRET_LEN];
        scalarmult(&mut shared, &self.seed, &peer.0);
        shared
    }

    /// Expose the raw seed for callers that need to serialise the key.
    /// This is secret material; callers must zero the returned bytes
    /// after use.
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_LEN] {
        self.seed
    }
}

impl core::fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519PrivateKey(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Short fingerprint so logs never leak an entire key.
        write!(
            f,
            "PublicKey(x25519:{:02x}{:02x}..{:02x}{:02x})",
            self.0[0], self.0[1], self.0[30], self.0[31]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_public_key_matches_scalarmult_base() {
        let priv_key = X25519PrivateKey::generate().unwrap();
        let via_api = priv_key.public_key();
        let mut direct = [0u8; PUBLIC_KEY_LEN];
        scalarmult_base(&mut direct, &priv_key.seed);
        assert_eq!(via_api.0, direct);
    }

    #[test]
    fn symmetric_dh_yields_same_secret() {
        let alice = X25519PrivateKey::generate().unwrap();
        let alice_pub = alice.public_key();
        let bob = X25519PrivateKey::generate().unwrap();
        let bob_pub = bob.public_key();

        let s1 = alice.diffie_hellman(&bob_pub);
        let s2 = bob.diffie_hellman(&alice_pub);
        assert_eq!(s1, s2, "Alice and Bob must derive the same shared secret");
    }

    #[test]
    fn different_pairs_yield_different_secrets() {
        let a = X25519PrivateKey::generate().unwrap();
        let b = X25519PrivateKey::generate().unwrap();
        let b_pub = b.public_key();
        let c = X25519PrivateKey::generate().unwrap();
        let c_pub = c.public_key();
        assert_ne!(a.diffie_hellman(&b_pub), b.diffie_hellman(&c_pub));
    }

    #[test]
    fn key_is_reusable_across_multiple_dh_ops() {
        // This is the whole reason we hand-rolled X25519: ring's
        // EphemeralPrivateKey is move-consumed on DH so the same private
        // key cannot run two DH ops. Ours can.
        let key = X25519PrivateKey::generate().unwrap();
        let peer_a = X25519PrivateKey::generate().unwrap().public_key();
        let peer_b = X25519PrivateKey::generate().unwrap().public_key();

        let s1 = key.diffie_hellman(&peer_a);
        let s2 = key.diffie_hellman(&peer_b);
        let s1_again = key.diffie_hellman(&peer_a);
        assert_ne!(s1, s2);
        assert_eq!(s1, s1_again, "DH must be deterministic for the same (priv, pub)");
    }

    #[test]
    fn from_bytes_preserves_seed() {
        let seed = [7u8; PRIVATE_KEY_LEN];
        let key = X25519PrivateKey::from_bytes(seed);
        assert_eq!(key.to_bytes(), seed);
    }

    #[test]
    fn debug_format_redacts_private_key() {
        let key = X25519PrivateKey::from_bytes([0xAA; PRIVATE_KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("aa"));
    }

    #[test]
    fn debug_format_redacts_public_key_middle_bytes() {
        let pk = PublicKey([0xAA; PUBLIC_KEY_LEN]);
        let rendered = format!("{pk:?}");
        assert!(rendered.contains("aaaa..aaaa"));
    }
}
