//! Thin wrappers over the two runtime crypto crates (`ring` and `blake3`).
//!
//! Every primitive surfaces a single `Result<_, CryptoError>` so upper
//! layers never have to touch the third-party error types directly, and so
//! a future swap of implementations does not ripple through the codebase.

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod verify;
pub mod x25519;
pub mod x25519_field;

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidCiphertextLength,
    /// AEAD open failed: tag mismatch, wrong key, or tampered ciphertext.
    AeadFailed,
    /// X25519 keygen or agreement failed.
    X25519Failed,
    /// HKDF expand failed (almost always: requested output too long).
    HkdfFailed,
    /// Output buffer was too small for the requested operation.
    ShortOutput,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidKeyLength => "crypto: invalid key length",
            Self::InvalidNonceLength => "crypto: invalid nonce length",
            Self::InvalidCiphertextLength => "crypto: invalid ciphertext length",
            Self::AeadFailed => "crypto: AEAD open failed (bad key, tag mismatch, or tamper)",
            Self::X25519Failed => "crypto: X25519 operation failed",
            Self::HkdfFailed => "crypto: HKDF expand failed",
            Self::ShortOutput => "crypto: output buffer too small",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CryptoError {}
