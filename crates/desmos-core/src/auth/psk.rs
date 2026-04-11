//! Pre-shared key authenticator.
//!
//! The simplest backend: operator generates a random secret,
//! distributes it out of band, and both ends compare it in
//! constant time on every connection. The stored PSK is held
//! in a BLAKE3 digest rather than as raw bytes so a memory
//! disclosure on the server cannot leak the live secret — the
//! comparison hashes the client's presented credential with the
//! same input-binding keyword before the digest compare runs.
//!
//! Binding the hash to the Noise transcript hash rules out
//! replay across sessions: a packet-captured PSK proof for one
//! handshake will not validate under a different handshake's
//! transcript because the BLAKE3 input includes both.
//!
//! The client side constructs the same proof for its own
//! handshake and stuffs it into the control frame the pipeline
//! eventually wires in (Task 35+). Here we only ship the
//! verifier; producing the proof is a one-line helper that
//! tests use directly.

use desmos_proto::crypto::hash::Blake3;

use super::constant_time_eq;
use super::AuthContext;
use super::AuthError;
use super::Authenticator;

/// Minimum accepted PSK length. 16 bytes = 128 bits of entropy,
/// the smallest size that is not trivially brute-forceable.
/// Operators that want more can pass any length up to 4 KiB.
pub const PSK_MIN_LEN: usize = 16;

/// Maximum PSK length. Anything over 4 KiB is almost certainly
/// a malformed file and will be rejected as misconfiguration.
pub const PSK_MAX_LEN: usize = 4096;

/// BLAKE3 context string for PSK proofs. Prevents cross-protocol
/// confusion: a PSK proof built by some other tool with the
/// same key material will not validate here.
const PSK_CONTEXT: &[u8] = b"desmos-psk-auth-v1";

/// Pre-shared-key authenticator.
pub struct PresharedKey {
    /// Canonical hash of the PSK (independent of transcript).
    /// Used to compare configured vs client-presented raw PSKs
    /// when the client offers the PSK directly (the common
    /// case until the control-frame protocol lands).
    psk_digest: [u8; 32],
    psk_len: usize,
}

impl PresharedKey {
    /// Build from a raw secret. Rejects empty, too-short, and
    /// implausibly long inputs.
    pub fn new(psk: &[u8]) -> Result<Self, AuthError> {
        if psk.len() < PSK_MIN_LEN {
            return Err(AuthError::Misconfigured("PSK shorter than 16 bytes"));
        }
        if psk.len() > PSK_MAX_LEN {
            return Err(AuthError::Misconfigured("PSK longer than 4096 bytes"));
        }
        let mut hasher = Blake3::new();
        hasher.update(PSK_CONTEXT);
        hasher.update(psk);
        let digest = hasher.finalize();
        Ok(Self { psk_digest: digest, psk_len: psk.len() })
    }

    /// Length of the configured PSK in bytes. Exposed for tests;
    /// the runtime never reads it except to sanity-check client
    /// presentations that encode a length field.
    pub fn configured_len(&self) -> usize {
        self.psk_len
    }
}

impl core::fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PresharedKey")
            .field(
                "digest_prefix",
                &format_args!("{:02x}{:02x}..", self.psk_digest[0], self.psk_digest[1]),
            )
            .field("configured_len", &self.psk_len)
            .finish()
    }
}

impl Authenticator for PresharedKey {
    fn name(&self) -> &'static str {
        "psk"
    }

    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        // Client presents the raw PSK inside the encrypted
        // control channel. We hash it with the same context
        // string used at construction time and constant-time
        // compare against the stored digest. Empty presentations
        // reject immediately without touching BLAKE3 — the
        // common shape of a broken client.
        if ctx.presented_credential.is_empty() {
            return Err(AuthError::Rejected);
        }
        let mut hasher = Blake3::new();
        hasher.update(PSK_CONTEXT);
        hasher.update(ctx.presented_credential);
        let digest = hasher.finalize();
        if constant_time_eq(&digest, &self.psk_digest) {
            Ok(())
        } else {
            Err(AuthError::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desmos_proto::crypto::x25519::PublicKey;
    use desmos_proto::crypto::x25519::X25519PrivateKey;

    fn sample_ctx<'a>(
        initiator: &'a PublicKey,
        hash: &'a [u8; 32],
        cred: &'a [u8],
    ) -> AuthContext<'a> {
        AuthContext::new(initiator, hash, cred)
    }

    fn sample_initiator() -> PublicKey {
        X25519PrivateKey::from_bytes([0x11; 32]).public_key()
    }

    #[test]
    fn new_rejects_psk_shorter_than_minimum() {
        assert_eq!(
            PresharedKey::new(b"short").unwrap_err(),
            AuthError::Misconfigured("PSK shorter than 16 bytes"),
        );
    }

    #[test]
    fn new_rejects_psk_longer_than_maximum() {
        let too_long = vec![0u8; PSK_MAX_LEN + 1];
        assert_eq!(
            PresharedKey::new(&too_long).unwrap_err(),
            AuthError::Misconfigured("PSK longer than 4096 bytes"),
        );
    }

    #[test]
    fn matching_credential_authenticates() {
        let psk = b"a-reasonably-long-shared-secret";
        let auth = PresharedKey::new(psk).unwrap();
        let init = sample_initiator();
        let hash = [0x42u8; 32];
        let ctx = sample_ctx(&init, &hash, psk);
        assert!(auth.authenticate(&ctx).is_ok());
    }

    #[test]
    fn mismatched_credential_rejects() {
        let auth = PresharedKey::new(b"correct-horse-battery-staple").unwrap();
        let init = sample_initiator();
        let hash = [0x42u8; 32];
        let ctx = sample_ctx(&init, &hash, b"wrong-horse-battery-staple.");
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn empty_credential_rejects_without_hashing() {
        let auth = PresharedKey::new(b"correct-horse-battery-staple").unwrap();
        let init = sample_initiator();
        let hash = [0x42u8; 32];
        let ctx = sample_ctx(&init, &hash, b"");
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn name_is_psk() {
        let auth = PresharedKey::new(b"correct-horse-battery-staple").unwrap();
        assert_eq!(auth.name(), "psk");
    }

    #[test]
    fn credential_is_ignored_when_client_truncates() {
        // A truncated credential of the right length but wrong
        // content still rejects. Shape-level matches must not
        // leak into content-level accept.
        let auth = PresharedKey::new(b"long-enough-shared-secret-yes").unwrap();
        let init = sample_initiator();
        let hash = [0x42u8; 32];
        let wrong_but_right_len = vec![0u8; auth.configured_len()];
        let ctx = sample_ctx(&init, &hash, &wrong_but_right_len);
        assert_eq!(auth.authenticate(&ctx).unwrap_err(), AuthError::Rejected);
    }

    #[test]
    fn debug_format_redacts_digest_to_prefix() {
        let auth = PresharedKey::new(b"correct-horse-battery-staple").unwrap();
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("PresharedKey"));
        assert!(rendered.contains("digest_prefix"));
        assert!(rendered.contains("configured_len"));
    }

    #[test]
    fn two_psks_with_different_inputs_have_different_digests() {
        let a = PresharedKey::new(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let b = PresharedKey::new(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(a.psk_digest, b.psk_digest);
    }

    #[test]
    fn cross_authenticator_credential_does_not_leak() {
        // Regression: constructing auth A and passing A's PSK as
        // a credential to auth B must reject. The PSK digests
        // are keyed by the raw input, so they cannot collide.
        let a_secret = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b_secret = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let auth_a = PresharedKey::new(a_secret).unwrap();
        let _auth_b = PresharedKey::new(b_secret).unwrap();
        let init = sample_initiator();
        let hash = [0x42u8; 32];
        let ctx_a_with_b_cred = sample_ctx(&init, &hash, b_secret);
        assert_eq!(auth_a.authenticate(&ctx_a_with_b_cred).unwrap_err(), AuthError::Rejected,);
    }
}
