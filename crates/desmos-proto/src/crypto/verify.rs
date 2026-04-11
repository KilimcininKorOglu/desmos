//! Digital signature verification wrappers over `ring::signature`.
//!
//! Used by the Task 34 X.509 chain verifier in `desmos-core::auth`.
//! Exposes a narrow public surface covering exactly the signature
//! algorithms the mTLS authenticator has to accept on RFC 5280
//! compliant certificate chains:
//!
//! - ECDSA P-256 + SHA-256 (OID 1.2.840.10045.4.3.2)
//! - ECDSA P-384 + SHA-384 (OID 1.2.840.10045.4.3.3)
//! - RSA PKCS#1 v1.5 + SHA-256 (OID 1.2.840.113549.1.1.11)
//! - Ed25519 (OID 1.3.101.112)
//!
//! Every other OID is rejected as [`VerifyError::UnsupportedAlgorithm`].
//! That keeps the attack surface tight and ensures future
//! algorithm additions go through a review step rather than
//! appearing by default because ring added support.

use core::fmt;

use ring::signature;

/// Supported signature algorithm on a verify call. Picked by the
/// X.509 parser from the signatureAlgorithm OID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    RsaPkcs1Sha256,
    Ed25519,
}

impl SignatureAlgorithm {
    fn ring_alg(self) -> &'static dyn signature::VerificationAlgorithm {
        match self {
            Self::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
            Self::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
            Self::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Self::Ed25519 => &signature::ED25519,
        }
    }
}

/// Errors the verifier can surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Caller passed an algorithm we deliberately do not
    /// support (legacy SHA-1, MD5, etc.).
    UnsupportedAlgorithm,
    /// The signature did not verify: wrong key, wrong
    /// signature, or tampered message. ring folds every
    /// negative result into a single opaque error and we do
    /// the same to avoid leaking anything useful to an
    /// attacker.
    Invalid,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm => f.write_str("verify: unsupported signature algorithm"),
            Self::Invalid => f.write_str("verify: signature did not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify `signature` against `message` using `public_key`.
///
/// `public_key` is the raw encoded public key as pulled from
/// an X.509 `SubjectPublicKeyInfo.subjectPublicKey` BIT STRING:
///
/// - For **ECDSA P-256 / P-384**, the raw uncompressed SEC1
///   encoding (`0x04 || X || Y`), which is what ring's
///   `UnparsedPublicKey::verify` expects for the
///   `ECDSA_P*_SHA*_ASN1` family.
/// - For **RSA PKCS#1**, the DER-encoded `RSAPublicKey`
///   (`SEQUENCE { modulus INTEGER, publicExponent INTEGER }`).
///   X.509 wraps this in a BIT STRING whose content bytes are
///   exactly that DER, so the caller can pass the stripped
///   BIT STRING body directly.
/// - For **Ed25519**, the raw 32-byte public key.
///
/// `signature` is the raw signature bytes as they appear in the
/// certificate's `signatureValue` BIT STRING.
pub fn verify(
    alg: SignatureAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), VerifyError> {
    let ring_alg = alg.ring_alg();
    let key = signature::UnparsedPublicKey::new(ring_alg, public_key);
    key.verify(message, signature_bytes).map_err(|_| VerifyError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    #[test]
    fn ed25519_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let msg = b"hello desmos";
        let sig = kp.sign(msg);
        let pub_bytes = kp.public_key().as_ref();
        verify(SignatureAlgorithm::Ed25519, pub_bytes, msg, sig.as_ref()).unwrap();
    }

    #[test]
    fn ed25519_rejects_tampered_message() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let sig = kp.sign(b"original");
        let pub_bytes = kp.public_key().as_ref();
        let err =
            verify(SignatureAlgorithm::Ed25519, pub_bytes, b"tampered", sig.as_ref()).unwrap_err();
        assert_eq!(err, VerifyError::Invalid);
    }

    #[test]
    fn ed25519_rejects_wrong_public_key() {
        let rng = SystemRandom::new();
        let pkcs8_a = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pkcs8_b = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp_a = signature::Ed25519KeyPair::from_pkcs8(pkcs8_a.as_ref()).unwrap();
        let kp_b = signature::Ed25519KeyPair::from_pkcs8(pkcs8_b.as_ref()).unwrap();
        let sig = kp_a.sign(b"msg");
        let wrong_pub = kp_b.public_key().as_ref();
        let err = verify(SignatureAlgorithm::Ed25519, wrong_pub, b"msg", sig.as_ref()).unwrap_err();
        assert_eq!(err, VerifyError::Invalid);
    }

    #[test]
    fn ecdsa_p256_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let msg = b"hello desmos";
        let sig = kp.sign(&rng, msg).unwrap();
        verify(SignatureAlgorithm::EcdsaP256Sha256, kp.public_key().as_ref(), msg, sig.as_ref())
            .unwrap();
    }

    #[test]
    fn ecdsa_p256_rejects_tampered_message() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let sig = kp.sign(&rng, b"original").unwrap();
        let err = verify(
            SignatureAlgorithm::EcdsaP256Sha256,
            kp.public_key().as_ref(),
            b"tampered",
            sig.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Invalid);
    }

    #[test]
    fn ecdsa_p384_round_trip() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            &rng,
        )
        .unwrap();
        let kp = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let msg = b"hello desmos";
        let sig = kp.sign(&rng, msg).unwrap();
        verify(SignatureAlgorithm::EcdsaP384Sha384, kp.public_key().as_ref(), msg, sig.as_ref())
            .unwrap();
    }

    #[test]
    fn display_covers_both_variants() {
        assert_eq!(
            VerifyError::UnsupportedAlgorithm.to_string(),
            "verify: unsupported signature algorithm",
        );
        assert_eq!(VerifyError::Invalid.to_string(), "verify: signature did not verify",);
    }
}
