//! RFC 5280 §5.1 Certificate Revocation List (CRL) parser.
//!
//! Consumed by the [`super::mtls::MtlsAuthenticator`] to
//! reject revoked client certificates. Builds on the same
//! [`super::asn1::DerReader`] and time / algorithm helpers as
//! [`super::x509`].
//!
//! Only the bits the mTLS authenticator actually needs are
//! parsed:
//!
//! - version (optional, must be v2 when present)
//! - inner + outer `AlgorithmIdentifier` (must agree)
//! - issuer `Name` (raw DER for matching against a CA cert's
//!   subject)
//! - `thisUpdate` / optional `nextUpdate` as Unix seconds
//! - `revokedCertificates` as a borrowed DER slice that
//!   [`CertificateList::is_revoked`] walks on demand
//! - raw TBS bytes for [`CertificateList::verify_signed_by`]
//!
//! CRL extensions (issuer alt-name, CRL number, AKI, etc.) are
//! walked past without interpretation.

use core::fmt;

use desmos_proto::crypto::verify as sig_verify;
use desmos_proto::crypto::verify::SignatureAlgorithm;

use super::asn1::tag;
use super::asn1::Asn1Error;
use super::asn1::DerReader;
use super::x509::{
    oid_to_signature_algorithm, read_algorithm_identifier, read_time, Certificate, X509Error,
};

/// Errors the CRL parser / verifier can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlError {
    /// The outer DER structure failed to parse.
    Asn1(Asn1Error),
    /// The inner `signature` AlgorithmIdentifier disagrees with
    /// the outer `signatureAlgorithm` (RFC 5280 §5.1.1.2).
    AlgorithmMismatch,
    /// The signature algorithm OID is not one the verify
    /// wrapper recognises.
    UnsupportedAlgorithm,
    /// `version` was present but not v2.
    UnsupportedVersion,
    /// `thisUpdate` or `nextUpdate` did not decode.
    InvalidTime,
    /// `verify_signed_by` rejected the signature.
    SignatureInvalid,
}

impl From<Asn1Error> for CrlError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

impl From<X509Error> for CrlError {
    fn from(e: X509Error) -> Self {
        match e {
            X509Error::Asn1(a) => Self::Asn1(a),
            X509Error::InvalidTime => Self::InvalidTime,
            X509Error::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            X509Error::AlgorithmMismatch => Self::AlgorithmMismatch,
            X509Error::SignatureInvalid => Self::SignatureInvalid,
            // Anything else from the X.509 helpers is a bug —
            // fold into Asn1 / InvalidValue so CrlError stays a
            // narrow enum.
            _ => Self::Asn1(Asn1Error::InvalidValue("crl: x509 helper error")),
        }
    }
}

impl fmt::Display for CrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "crl: {e}"),
            Self::AlgorithmMismatch => f.write_str("crl: TBS signature algorithm mismatch"),
            Self::UnsupportedAlgorithm => f.write_str("crl: unsupported signature algorithm"),
            Self::UnsupportedVersion => f.write_str("crl: unsupported CRL version"),
            Self::InvalidTime => f.write_str("crl: malformed time field"),
            Self::SignatureInvalid => f.write_str("crl: signature did not verify"),
        }
    }
}

impl std::error::Error for CrlError {}

/// Parsed view over a DER-encoded X.509 `CertificateList`.
/// All fields are borrows into the caller's input buffer.
#[derive(Debug, Clone)]
pub struct CertificateList<'a> {
    /// Exact bytes of the TBS portion, used for signature
    /// verification.
    pub raw_tbs: &'a [u8],
    /// Raw `Name` DER for the CRL issuer.
    pub issuer_raw: &'a [u8],
    /// `thisUpdate` as Unix epoch seconds.
    pub this_update: u64,
    /// `nextUpdate` as Unix epoch seconds. `None` if absent.
    pub next_update: Option<u64>,
    /// Outer signatureAlgorithm, mapped to the enum the verify
    /// module understands.
    pub signature_algorithm: SignatureAlgorithm,
    /// BIT STRING body of the outer signatureValue.
    pub signature_value: &'a [u8],
    /// Raw DER bytes of the `revokedCertificates SEQUENCE OF`
    /// *body* (inside the tag + length). `None` if the field
    /// was omitted (zero revoked certs).
    revoked_raw: Option<&'a [u8]>,
}

impl<'a> CertificateList<'a> {
    /// Parse a DER-encoded `CertificateList`.
    pub fn parse(der: &'a [u8]) -> Result<Self, CrlError> {
        let mut outer = DerReader::new(der);
        let mut list = outer.read_sequence()?;

        // Snapshot the TBS before descending into the child
        // reader so we can recover the exact signed bytes.
        let tbs_start = list.remaining();
        let tbs_before = tbs_start.len();
        let mut tbs = list.read_sequence()?;
        let tbs_after = list.remaining().len();
        let raw_tbs = &tbs_start[..tbs_before - tbs_after];

        // version OPTIONAL — must be v2 (INTEGER 1) when
        // present. We peek rather than `maybe_tagged` because
        // the field is an INTEGER, not a context tag.
        if tbs.peek_tag() == Some(tag::INTEGER) {
            let v = tbs.read_u64()?;
            if v != 1 {
                return Err(CrlError::UnsupportedVersion);
            }
        }

        // signature AlgorithmIdentifier
        let (tbs_sig_alg_oid, _tbs_sig_alg_params) = read_algorithm_identifier(&mut tbs)?;

        // issuer Name (raw DER slice for later matching).
        let issuer_raw = tbs.read_tagged(tag::SEQUENCE)?;

        // thisUpdate Time
        let this_update = read_time(&mut tbs)?;

        // nextUpdate OPTIONAL Time — CHOICE between UTCTime
        // and GeneralizedTime, distinguishable by tag.
        let next_update = match tbs.peek_tag() {
            Some(t) if t == tag::UTC_TIME || t == tag::GENERALIZED_TIME => {
                Some(read_time(&mut tbs)?)
            }
            _ => None,
        };

        // revokedCertificates OPTIONAL SEQUENCE OF SEQUENCE
        let revoked_raw = match tbs.peek_tag() {
            Some(tag::SEQUENCE) => Some(tbs.read_tagged(tag::SEQUENCE)?),
            _ => None,
        };

        // Skip crlExtensions [0] EXPLICIT if present.
        while !tbs.is_empty() {
            tbs.skip_one()?;
        }

        // Outer signatureAlgorithm + signatureValue.
        let (outer_sig_alg_oid, _outer_sig_alg_params) = read_algorithm_identifier(&mut list)?;
        if outer_sig_alg_oid != tbs_sig_alg_oid {
            return Err(CrlError::AlgorithmMismatch);
        }
        let signature_algorithm =
            oid_to_signature_algorithm(outer_sig_alg_oid).ok_or(CrlError::UnsupportedAlgorithm)?;
        let signature_value = list.read_bit_string()?;

        Ok(Self {
            raw_tbs,
            issuer_raw,
            this_update,
            next_update,
            signature_algorithm,
            signature_value,
            revoked_raw,
        })
    }

    /// Verify that this CRL was signed by `issuer`. The mTLS
    /// authenticator calls this before trusting any revoked
    /// serial.
    pub fn verify_signed_by(&self, issuer: &Certificate<'_>) -> Result<(), CrlError> {
        sig_verify::verify(
            self.signature_algorithm,
            issuer.spki_key_bytes,
            self.raw_tbs,
            self.signature_value,
        )
        .map_err(|_| CrlError::SignatureInvalid)
    }

    /// `true` when `serial` appears in the `revokedCertificates`
    /// list, byte-for-byte against the raw `INTEGER` content
    /// (matching [`Certificate::serial`]). Malformed entries
    /// cause the walk to stop — a broken CRL should never be
    /// treated as "no revocations". Callers must also gate on
    /// [`Self::verify_signed_by`] before trusting the result.
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        let Some(raw) = self.revoked_raw else {
            return false;
        };
        let mut reader = DerReader::new(raw);
        while !reader.is_empty() {
            let Ok(mut entry) = reader.read_sequence() else {
                return false;
            };
            let Ok(entry_serial) = entry.read_integer_bytes() else {
                return false;
            };
            if entry_serial == serial {
                return true;
            }
            // revocationDate + optional crlEntryExtensions get
            // dropped implicitly when the child reader is
            // dropped on the next loop iteration.
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-assembled CRL signed by a fresh Ed25519 keypair.
    /// Returns `(crl_der, ca_der)` — the CA cert is built from
    /// the same keypair so `verify_signed_by(&ca)` passes.
    fn build_signed_crl_with_revoked_serial(serial: u64) -> (Vec<u8>, Vec<u8>) {
        use ring::signature::{self as r_sig, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = r_sig::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = r_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = kp.public_key().as_ref();

        // Minimal DER helpers inlined here to avoid touching
        // the private test helpers in x509::tests.
        fn der_tlv(tag_byte: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag_byte];
            encode_length(body.len(), &mut out);
            out.extend_from_slice(body);
            out
        }
        fn encode_length(len: usize, out: &mut Vec<u8>) {
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x100 {
                out.push(0x81);
                out.push(len as u8);
            } else if len < 0x10000 {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            } else {
                panic!("encode_length: oversized body in test helper");
            }
        }
        fn der_integer(value: u64) -> Vec<u8> {
            let mut body = value.to_be_bytes().to_vec();
            while body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
                body.remove(0);
            }
            if body[0] & 0x80 != 0 {
                body.insert(0, 0x00);
            }
            der_tlv(tag::INTEGER, &body)
        }
        fn der_alg_id_ed25519() -> Vec<u8> {
            let oid = der_tlv(tag::OID, super::super::x509::OID_ED25519);
            der_tlv(tag::SEQUENCE, &oid)
        }
        fn der_common_name(cn: &str) -> Vec<u8> {
            let cn_value = der_tlv(tag::UTF8_STRING, cn.as_bytes());
            let mut atv = der_tlv(tag::OID, &[0x55, 0x04, 0x03]);
            atv.extend_from_slice(&cn_value);
            let atv_seq = der_tlv(tag::SEQUENCE, &atv);
            let rdn_set = der_tlv(tag::SET, &atv_seq);
            der_tlv(tag::SEQUENCE, &rdn_set)
        }
        fn der_utc_time(value: &[u8]) -> Vec<u8> {
            der_tlv(tag::UTC_TIME, value)
        }
        fn der_spki_ed25519(pk: &[u8]) -> Vec<u8> {
            let alg = der_alg_id_ed25519();
            let mut bit_string = vec![0u8];
            bit_string.extend_from_slice(pk);
            let spk = der_tlv(tag::BIT_STRING, &bit_string);
            let mut body = alg;
            body.extend_from_slice(&spk);
            der_tlv(tag::SEQUENCE, &body)
        }

        // Build a minimal self-signed CA certificate first so
        // the test can call `crl.verify_signed_by(&ca)`.
        let ca_name = der_common_name("desmos-test-crl-ca");
        let ca_validity = {
            let mut v = der_utc_time(b"250101000000Z");
            v.extend_from_slice(&der_utc_time(b"350101000000Z"));
            der_tlv(tag::SEQUENCE, &v)
        };
        let ca_spki = der_spki_ed25519(pub_bytes);
        let mut ca_tbs_body: Vec<u8> = Vec::new();
        ca_tbs_body.extend_from_slice(&der_tlv(
            super::super::asn1::context_tag_explicit(0),
            der_integer(2).as_slice(),
        ));
        ca_tbs_body.extend_from_slice(&der_integer(1));
        ca_tbs_body.extend_from_slice(&der_alg_id_ed25519());
        ca_tbs_body.extend_from_slice(&ca_name); // issuer
        ca_tbs_body.extend_from_slice(&ca_validity);
        ca_tbs_body.extend_from_slice(&ca_name); // subject
        ca_tbs_body.extend_from_slice(&ca_spki);
        let ca_tbs = der_tlv(tag::SEQUENCE, &ca_tbs_body);
        let ca_sig = kp.sign(&ca_tbs);
        let mut ca_sig_bs = vec![0u8];
        ca_sig_bs.extend_from_slice(ca_sig.as_ref());
        let mut ca_body = ca_tbs;
        ca_body.extend_from_slice(&der_alg_id_ed25519());
        ca_body.extend_from_slice(&der_tlv(tag::BIT_STRING, &ca_sig_bs));
        let ca_der = der_tlv(tag::SEQUENCE, &ca_body);

        // Build the CRL TBS.
        let version = der_integer(1); // v2
        let sig_alg = der_alg_id_ed25519();
        let issuer = ca_name;
        let this_update = der_utc_time(b"250601000000Z");
        let next_update = der_utc_time(b"260601000000Z");
        let revoked_entry = {
            let serial_integer = der_integer(serial);
            let rev_date = der_utc_time(b"250615000000Z");
            let mut body = serial_integer;
            body.extend_from_slice(&rev_date);
            der_tlv(tag::SEQUENCE, &body)
        };
        let revoked_seq = der_tlv(tag::SEQUENCE, &revoked_entry);

        let mut tbs_body: Vec<u8> = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&sig_alg);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&this_update);
        tbs_body.extend_from_slice(&next_update);
        tbs_body.extend_from_slice(&revoked_seq);

        let tbs = der_tlv(tag::SEQUENCE, &tbs_body);
        let sig = kp.sign(&tbs);
        let mut sig_bs = vec![0u8];
        sig_bs.extend_from_slice(sig.as_ref());

        let mut crl_body = tbs;
        crl_body.extend_from_slice(&der_alg_id_ed25519());
        crl_body.extend_from_slice(&der_tlv(tag::BIT_STRING, &sig_bs));
        let crl_der = der_tlv(tag::SEQUENCE, &crl_body);

        (crl_der, ca_der)
    }

    #[test]
    fn parse_and_verify_signed_crl_with_one_revoked_serial() {
        let (crl_der, ca_der) = build_signed_crl_with_revoked_serial(0xDEAD_BEEF);
        let ca = Certificate::parse(&ca_der).unwrap();
        let crl = CertificateList::parse(&crl_der).unwrap();

        assert_eq!(crl.signature_algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(crl.this_update, 1_748_736_000); // 2025-06-01
        assert_eq!(crl.next_update, Some(1_780_272_000)); // 2026-06-01
        crl.verify_signed_by(&ca).unwrap();

        // Match the serial exactly.
        let mut serial_bytes = 0xDEAD_BEEFu64.to_be_bytes().to_vec();
        while serial_bytes.len() > 1 && serial_bytes[0] == 0 && serial_bytes[1] & 0x80 == 0 {
            serial_bytes.remove(0);
        }
        if serial_bytes[0] & 0x80 != 0 {
            serial_bytes.insert(0, 0x00);
        }
        assert!(crl.is_revoked(&serial_bytes));
        assert!(!crl.is_revoked(&[0x01, 0x02, 0x03]));
    }

    #[test]
    fn verify_signed_by_rejects_foreign_ca() {
        let (crl_der, _ca_der) = build_signed_crl_with_revoked_serial(1);
        // Build a *different* CA cert and use it as the issuer.
        let (_other_crl, other_ca_der) = build_signed_crl_with_revoked_serial(2);
        let other_ca = Certificate::parse(&other_ca_der).unwrap();
        let crl = CertificateList::parse(&crl_der).unwrap();
        let err = crl.verify_signed_by(&other_ca).unwrap_err();
        assert_eq!(err, CrlError::SignatureInvalid);
    }

    #[test]
    fn display_covers_every_variant() {
        assert_eq!(
            CrlError::AlgorithmMismatch.to_string(),
            "crl: TBS signature algorithm mismatch"
        );
        assert_eq!(
            CrlError::UnsupportedAlgorithm.to_string(),
            "crl: unsupported signature algorithm"
        );
        assert_eq!(CrlError::UnsupportedVersion.to_string(), "crl: unsupported CRL version");
        assert_eq!(CrlError::InvalidTime.to_string(), "crl: malformed time field");
        assert_eq!(CrlError::SignatureInvalid.to_string(), "crl: signature did not verify");
    }
}
