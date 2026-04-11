//! mTLS-style client authenticator.
//!
//! A client presents:
//!
//! 1. its DER-encoded leaf certificate, issued by a CA the
//!    server trusts, and
//! 2. an Ed25519 signature over the Noise handshake transcript
//!    hash, produced with the leaf certificate's private key.
//!
//! The authenticator:
//!
//! - parses the leaf cert,
//! - verifies the leaf's signature chain up to the configured
//!   CA,
//! - checks the leaf's validity window against an injected
//!   clock,
//! - optionally checks a CRL (signed by the same CA),
//! - verifies the transcript signature with the leaf's SPKI
//!   public key,
//!
//! and on success reports [`Authenticator::name`] = `"mtls"`.
//!
//! The transcript-signature step is what gives this
//! authenticator real mTLS semantics — without it, a stolen
//! cert would act as a bearer token. Because Noise IK already
//! binds the client's X25519 static public key to the session,
//! the Ed25519 signature on the same transcript proves the
//! client also holds the cert's private key at session time.
//!
//! # Credential wire format
//!
//! The `presented_credential` bytes in the [`AuthContext`] must
//! be laid out as:
//!
//! ```text
//! [u16 BE leaf_der_len][leaf_der][64-byte Ed25519 sig]
//! ```
//!
//! Only Ed25519 leaf SPKIs are accepted — the transcript
//! signature check always uses
//! [`SignatureAlgorithm::Ed25519`]. The CA cert itself may be
//! signed with any algorithm the verify module supports.
//!
//! # Scope boundary
//!
//! Chain walking is single-step (leaf → CA). Intermediate CAs
//! are not supported. This matches the `[server.auth]
//! method = "mtls"` config in the MVP (`ca_cert` is a single
//! DER path, no bundle).

use core::fmt;

use desmos_proto::crypto::verify as sig_verify;
use desmos_proto::crypto::verify::SignatureAlgorithm;

use super::crl::{CertificateList, CrlError};
use super::x509::{Certificate, X509Error, OID_ED25519};
use super::{AuthContext, AuthError, Authenticator};

const ED25519_SIG_LEN: usize = 64;

/// Config handed to [`MtlsAuthenticator::new`].
pub struct MtlsConfig {
    /// DER bytes of the trusted CA certificate.
    pub ca_der: Vec<u8>,
    /// Optional DER bytes of a current CRL signed by the CA.
    /// If `None`, no revocation check is performed.
    pub crl_der: Option<Vec<u8>>,
}

/// Errors that can fire while *building* an
/// [`MtlsAuthenticator`]. Runtime auth failures go through
/// [`AuthError`] instead so the wire response does not leak
/// which branch tripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsInitError {
    /// The CA certificate did not parse.
    Ca(X509Error),
    /// The supplied CRL did not parse or its signature did not
    /// verify against the CA.
    Crl(CrlError),
    /// The CA cert uses an SPKI algorithm the verify module
    /// does not support (so no leaf signed by it could ever be
    /// checked).
    UnsupportedCa,
}

impl fmt::Display for MtlsInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ca(e) => write!(f, "mtls: ca cert: {e}"),
            Self::Crl(e) => write!(f, "mtls: crl: {e}"),
            Self::UnsupportedCa => f.write_str("mtls: ca cert uses unsupported algorithm"),
        }
    }
}

impl std::error::Error for MtlsInitError {}

/// mTLS client authenticator.
pub struct MtlsAuthenticator {
    ca_der: Vec<u8>,
    crl_der: Option<Vec<u8>>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl fmt::Debug for MtlsAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtlsAuthenticator")
            .field("ca_der_len", &self.ca_der.len())
            .field("has_crl", &self.crl_der.is_some())
            .finish()
    }
}

impl MtlsAuthenticator {
    /// Build a new authenticator. Validates the CA cert and
    /// (if supplied) the CRL once up front so the daemon sees
    /// config errors at load time rather than per-client.
    pub fn new(cfg: MtlsConfig) -> Result<Self, MtlsInitError> {
        {
            let ca = Certificate::parse(&cfg.ca_der).map_err(MtlsInitError::Ca)?;
            if let Some(crl) = cfg.crl_der.as_deref() {
                let list = CertificateList::parse(crl).map_err(MtlsInitError::Crl)?;
                list.verify_signed_by(&ca).map_err(MtlsInitError::Crl)?;
            }
        }
        Ok(Self { ca_der: cfg.ca_der, crl_der: cfg.crl_der, clock: Box::new(default_clock) })
    }

    /// Swap out the wall-clock source. Tests use this to drive
    /// deterministic validity-window and CRL-freshness checks.
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Extract the subject CN from a credential payload, for
    /// logging / session-identity mapping. Does not verify the
    /// chain — callers must run [`Self::authenticate`] first.
    pub fn peek_subject_cn<'a>(&self, credential: &'a [u8]) -> Option<&'a str> {
        let (leaf_der, _sig) = split_credential(credential)?;
        let cert = Certificate::parse(leaf_der).ok()?;
        cert.subject_cn()
    }
}

impl Authenticator for MtlsAuthenticator {
    fn name(&self) -> &'static str {
        "mtls"
    }

    fn authenticate(&self, ctx: &AuthContext<'_>) -> Result<(), AuthError> {
        let (leaf_der, transcript_sig) =
            split_credential(ctx.presented_credential).ok_or(AuthError::Rejected)?;

        let leaf = Certificate::parse(leaf_der).map_err(|_| AuthError::Rejected)?;
        let ca = Certificate::parse(&self.ca_der)
            .map_err(|_| AuthError::Misconfigured("mtls: ca cert reparse failed"))?;

        // Chain check: CA must have signed the leaf.
        leaf.verify_signed_by(&ca).map_err(|_| AuthError::Rejected)?;

        // Leaf must carry an Ed25519 SPKI so we can verify the
        // transcript signature with it.
        if leaf.spki_algorithm_oid != OID_ED25519 {
            return Err(AuthError::Rejected);
        }
        if leaf.spki_key_bytes.len() != 32 {
            return Err(AuthError::Rejected);
        }

        // Transcript-signature proof of possession.
        sig_verify::verify(
            SignatureAlgorithm::Ed25519,
            leaf.spki_key_bytes,
            &ctx.handshake_hash[..],
            transcript_sig,
        )
        .map_err(|_| AuthError::Rejected)?;

        // Validity windows.
        let now = (self.clock)();
        if !leaf.is_valid_at(now) {
            return Err(AuthError::Rejected);
        }
        if !ca.is_valid_at(now) {
            return Err(AuthError::Misconfigured("mtls: ca cert expired"));
        }

        // Revocation check.
        if let Some(crl_der) = self.crl_der.as_deref() {
            let crl = CertificateList::parse(crl_der)
                .map_err(|_| AuthError::Misconfigured("mtls: crl reparse failed"))?;
            crl.verify_signed_by(&ca)
                .map_err(|_| AuthError::Misconfigured("mtls: crl signature"))?;
            if crl.is_revoked(leaf.serial) {
                return Err(AuthError::Rejected);
            }
        }

        Ok(())
    }
}

/// Split a credential blob into `(leaf_der, transcript_sig)`.
/// Returns `None` if the length prefix is truncated, the cert
/// body is truncated, or the signature body is not the expected
/// Ed25519 length.
fn split_credential(cred: &[u8]) -> Option<(&[u8], &[u8])> {
    if cred.len() < 2 {
        return None;
    }
    let leaf_len = u16::from_be_bytes([cred[0], cred[1]]) as usize;
    let total_min = 2 + leaf_len + ED25519_SIG_LEN;
    if cred.len() < total_min {
        return None;
    }
    let leaf_der = &cred[2..2 + leaf_len];
    let sig = &cred[2 + leaf_len..2 + leaf_len + ED25519_SIG_LEN];
    Some((leaf_der, sig))
}

/// Default wall-clock used when the caller does not override
/// via [`MtlsAuthenticator::with_clock`]. Returns seconds since
/// the Unix epoch; panics if the system clock is before 1970,
/// which matches how every other authenticator treats a broken
/// clock.
fn default_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("mtls: system clock is before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_credential_rejects_short_prefix() {
        assert!(split_credential(&[]).is_none());
        assert!(split_credential(&[0x00]).is_none());
    }

    #[test]
    fn split_credential_rejects_truncated_cert_body() {
        // Claims 100-byte cert but we only supply 10.
        let mut blob = vec![0x00, 0x64]; // u16 BE 100
        blob.extend_from_slice(&[0u8; 10]);
        blob.extend_from_slice(&[0u8; ED25519_SIG_LEN]);
        assert!(split_credential(&blob).is_none());
    }

    #[test]
    fn split_credential_rejects_truncated_signature() {
        let mut blob = vec![0x00, 0x05]; // u16 BE 5
        blob.extend_from_slice(&[0u8; 5]);
        blob.extend_from_slice(&[0u8; ED25519_SIG_LEN - 1]); // one byte short
        assert!(split_credential(&blob).is_none());
    }

    #[test]
    fn split_credential_happy_path() {
        let mut blob = vec![0x00, 0x05];
        blob.extend_from_slice(&[1u8, 2, 3, 4, 5]);
        blob.extend_from_slice(&[9u8; ED25519_SIG_LEN]);
        let (leaf, sig) = split_credential(&blob).unwrap();
        assert_eq!(leaf, &[1u8, 2, 3, 4, 5]);
        assert_eq!(sig.len(), ED25519_SIG_LEN);
        assert_eq!(sig[0], 9);
    }

    #[test]
    fn display_covers_init_error_variants() {
        assert_eq!(
            MtlsInitError::UnsupportedCa.to_string(),
            "mtls: ca cert uses unsupported algorithm"
        );
    }
}
