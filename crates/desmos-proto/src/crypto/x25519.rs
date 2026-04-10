//! X25519 ephemeral Diffie-Hellman via `ring::agreement`.
//!
//! The Noise IK handshake consumes each ephemeral private key after one
//! DH operation, so the API is deliberately move-consuming: calling
//! `diffie_hellman(self, ...)` drops the private scalar.

use ring::agreement::agree_ephemeral;
use ring::agreement::EphemeralPrivateKey as RingPriv;
use ring::agreement::UnparsedPublicKey;
use ring::agreement::X25519;
use ring::rand::SystemRandom;

use super::CryptoError;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SHARED_SECRET_LEN: usize = 32;

pub struct EphemeralPrivateKey {
    inner: RingPriv,
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

impl EphemeralPrivateKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let inner = RingPriv::generate(&X25519, &rng).map_err(|_| CryptoError::X25519Failed)?;
        Ok(Self { inner })
    }

    pub fn public_key(&self) -> Result<PublicKey, CryptoError> {
        let bytes = self.inner.compute_public_key().map_err(|_| CryptoError::X25519Failed)?;
        let slice = bytes.as_ref();
        if slice.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::X25519Failed);
        }
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(slice);
        Ok(PublicKey(out))
    }

    /// Consume the private key and perform `DH(self, peer)`, returning
    /// the 32-byte shared secret.
    pub fn diffie_hellman(self, peer: &PublicKey) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
        let peer_raw = peer.0;
        let peer_key = UnparsedPublicKey::new(&X25519, peer_raw);
        agree_ephemeral(self.inner, &peer_key, |secret| {
            let mut out = [0u8; SHARED_SECRET_LEN];
            out.copy_from_slice(secret);
            out
        })
        .map_err(|_| CryptoError::X25519Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_public_key_is_thirty_two_bytes() {
        let priv_key = EphemeralPrivateKey::generate().unwrap();
        let pk = priv_key.public_key().unwrap();
        assert_eq!(pk.0.len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn symmetric_dh_yields_same_secret() {
        let alice = EphemeralPrivateKey::generate().unwrap();
        let alice_pub = alice.public_key().unwrap();
        let bob = EphemeralPrivateKey::generate().unwrap();
        let bob_pub = bob.public_key().unwrap();

        let s1 = alice.diffie_hellman(&bob_pub).unwrap();
        let s2 = bob.diffie_hellman(&alice_pub).unwrap();
        assert_eq!(s1, s2, "Alice and Bob must derive the same shared secret");
    }

    #[test]
    fn different_pairs_yield_different_secrets() {
        let a = EphemeralPrivateKey::generate().unwrap();
        let b = EphemeralPrivateKey::generate().unwrap();
        let b_pub = b.public_key().unwrap();
        let c = EphemeralPrivateKey::generate().unwrap();
        let c_pub = c.public_key().unwrap();

        let s_ab = a.diffie_hellman(&b_pub).unwrap();
        let s_bc = b.diffie_hellman(&c_pub).unwrap();
        assert_ne!(s_ab, s_bc);
    }

    #[test]
    fn debug_format_redacts_middle_bytes() {
        let pk = PublicKey([0xAA; 32]);
        let rendered = format!("{pk:?}");
        assert!(rendered.contains("aaaa..aaaa"));
    }
}
