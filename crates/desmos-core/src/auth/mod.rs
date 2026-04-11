//! Pluggable client authentication backends.
//!
//! Every auth backend implements the [`Authenticator`] trait:
//! `name()` for metrics / logging, `authenticate(&ctx)` for the
//! actual decision. The Phase 4 server daemon picks a backend at
//! config load time (from the `[server.auth]` section) and wraps
//! it in a `Box<dyn Authenticator>`; the handshake accept path
//! then calls `authenticate` once per client before installing
//! the session in the `SessionTable`.
//!
//! The trait is deliberately narrow. Noise IK already verifies
//! the initiator's static public key belongs to whoever sent
//! msg1 (the AEAD tag on `enc_s` fails otherwise), so every
//! backend can trust the `initiator_static` field in
//! [`AuthContext`] as long as the Noise handshake completed.
//! The transcript hash is provided so backends that need a
//! server-side HMAC over session-binding material (PSK, mTLS)
//! can compute it without re-running the handshake.
//!
//! Task 32 ships two backends: [`psk::PresharedKey`] and
//! [`pubkey::PublicKeyList`]. Task 33 adds TOTP. Task 34 adds
//! mTLS. Task 35+ wires a configurable dispatcher so
//! `[server.auth] method = "psk" | "pubkey" | "totp" | "mtls"`
//! picks between them.

pub mod asn1;
pub mod psk;
pub mod pubkey;
pub mod totp;
pub mod x509;

pub use psk::PresharedKey;
pub use psk::PSK_MIN_LEN;
pub use pubkey::PublicKeyList;
pub use totp::TotpAuthenticator;
pub use totp::TotpConfig;

use core::fmt;

use desmos_proto::crypto::x25519::PublicKey;

/// Per-client authentication decision context.
///
/// The Phase 4 server handshake accept path builds this for every
/// client that completes msg1 and hands it to the configured
/// [`Authenticator`] before installing the session in the table.
pub struct AuthContext<'a> {
    /// Initiator's long-lived X25519 static public key, already
    /// verified by the Noise IK `enc_s` tag check.
    pub initiator_static: &'a PublicKey,
    /// Final Noise transcript hash. Backends that bind their
    /// credential material to the session transcript should feed
    /// this into whatever MAC they use.
    pub handshake_hash: &'a [u8; 32],
    /// Opaque credential bytes the client presented alongside the
    /// handshake — e.g. the PSK itself, a TOTP code, or a
    /// challenge response. May be empty for backends that only
    /// need the static public key.
    pub presented_credential: &'a [u8],
}

impl<'a> AuthContext<'a> {
    pub fn new(
        initiator_static: &'a PublicKey,
        handshake_hash: &'a [u8; 32],
        presented_credential: &'a [u8],
    ) -> Self {
        Self { initiator_static, handshake_hash, presented_credential }
    }
}

/// Backend-neutral authentication failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The backend rejected the presented credential. Matches the
    /// generic "bad auth" response every method reports on the
    /// wire — the backend-specific distinction (wrong PSK vs
    /// unknown pubkey) stays internal to avoid leaking which
    /// class of mistake the client made.
    Rejected,
    /// The backend could not make a decision because its own
    /// config is malformed (e.g. empty PSK file, invalid
    /// base64). Distinct from `Rejected` so operators can spot
    /// config problems in the logs.
    Misconfigured(&'static str),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("auth: rejected"),
            Self::Misconfigured(reason) => write!(f, "auth: misconfigured: {reason}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Common interface every auth backend implements.
pub trait Authenticator: Send + Sync {
    /// Short identifier used by metrics and `desmos status`.
    fn name(&self) -> &'static str;

    /// Return `Ok(())` when the client should be allowed in,
    /// `Err(AuthError)` otherwise.
    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError>;
}

/// Constant-time byte-slice equality. Used by every backend that
/// compares secrets against user input. Panics if `a` and `b`
/// have different lengths — callers must establish shape first.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_agrees_with_normal_eq() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn auth_error_displays_cleanly() {
        assert_eq!(AuthError::Rejected.to_string(), "auth: rejected");
        assert_eq!(
            AuthError::Misconfigured("empty PSK").to_string(),
            "auth: misconfigured: empty PSK",
        );
    }

    /// Trait-object safety smoke test.
    #[test]
    fn authenticator_is_object_safe() {
        let _: Box<dyn Authenticator> =
            Box::new(PresharedKey::new(b"long-enough-key-for-test").unwrap());
    }
}
