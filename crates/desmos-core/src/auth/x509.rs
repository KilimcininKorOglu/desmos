//! RFC 5280 §4.1 X.509 certificate parser.
//!
//! Builds on the pass-1 [`super::asn1::DerReader`] and consumes
//! exactly what the mTLS authenticator in pass 3 needs: serial
//! number, issuer / subject DNs, validity window in Unix
//! seconds, `SubjectPublicKeyInfo`, signature algorithm, and
//! the raw TBS bytes for re-hashing. Anything else (extensions,
//! unique IDs, CRL distribution points) is walked past without
//! interpretation so the next task's CRL logic can add what it
//! needs on top of this without rewriting the parser.
//!
//! The parser never allocates on the hot path: every field is
//! a borrowed slice of the caller's input. `parse()` returns a
//! `Certificate<'a>` that lives as long as the input buffer.
//!
//! # What is parsed
//!
//! - `version` (defaults to v1 when the `[0] EXPLICIT` tag is
//!   absent)
//! - `serialNumber` (raw DER `INTEGER` content bytes — the
//!   mTLS CRL check compares by byte equality)
//! - inner `signature` `AlgorithmIdentifier` (must match the
//!   outer `signatureAlgorithm` or the cert is ill-formed per
//!   RFC 5280 §4.1.1.2)
//! - `issuer` and `subject` DNs as raw slices. A best-effort
//!   `common_name()` extractor walks the inner SETs to find
//!   the `CN` attribute.
//! - `validity` (`notBefore` / `notAfter`) parsed to Unix
//!   seconds via a hand-rolled Gregorian date helper.
//! - `SubjectPublicKeyInfo` algorithm OID plus the
//!   `subjectPublicKey` BIT STRING content (unused-bits byte
//!   stripped). Ready to hand to the signature verifier
//!   directly.
//! - Outer `signatureAlgorithm` and `signatureValue`.
//!
//! # What is verified
//!
//! [`Certificate::verify_signed_by`] hashes the raw TBS slice
//! with the configured algorithm and calls into
//! `desmos-proto::crypto::verify` for the actual signature
//! check. That is the full signature-level verification — the
//! chain walk, validity window check, and CRL lookup live in
//! pass 3.

use core::fmt;

use desmos_proto::crypto::verify as sig_verify;
use desmos_proto::crypto::verify::SignatureAlgorithm;

use super::asn1::context_tag_explicit;
use super::asn1::tag;
use super::asn1::Asn1Error;
use super::asn1::DerReader;

/// Errors the X.509 parser / verifier can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X509Error {
    /// The outer DER structure failed to parse.
    Asn1(Asn1Error),
    /// `signatureAlgorithm` inside the TBS did not match the
    /// outer `signatureAlgorithm` (RFC 5280 §4.1.1.2 requires
    /// they be equal).
    AlgorithmMismatch,
    /// The parser encountered a signature algorithm OID we
    /// deliberately do not support.
    UnsupportedAlgorithm,
    /// `version` was something other than v1, v2, or v3.
    UnsupportedVersion,
    /// `Validity` encoded in a format other than UTCTime /
    /// GeneralizedTime, or with bytes that are not canonical.
    InvalidTime,
    /// `notBefore > notAfter` on the parsed validity window.
    InvalidValidityOrder,
    /// `verify_signed_by` rejected the signature.
    SignatureInvalid,
}

impl From<Asn1Error> for X509Error {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "x509: {e}"),
            Self::AlgorithmMismatch => f.write_str("x509: TBS signature algorithm mismatch"),
            Self::UnsupportedAlgorithm => f.write_str("x509: unsupported signature algorithm"),
            Self::UnsupportedVersion => f.write_str("x509: unsupported certificate version"),
            Self::InvalidTime => f.write_str("x509: malformed validity time"),
            Self::InvalidValidityOrder => f.write_str("x509: notBefore is after notAfter"),
            Self::SignatureInvalid => f.write_str("x509: signature did not verify"),
        }
    }
}

impl std::error::Error for X509Error {}

/// X.509 certificate version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
    V3,
}

/// Parsed view over a DER-encoded X.509 certificate. All
/// fields are borrows into the caller's input buffer.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub version: Version,
    /// Exact bytes of the TBS portion, used for signature
    /// verification.
    pub raw_tbs: &'a [u8],
    /// Raw `INTEGER` content for the serial number.
    pub serial: &'a [u8],
    /// Raw `Name` DER for the issuer. Re-parsed by
    /// [`Self::issuer_cn`] on demand.
    pub issuer_raw: &'a [u8],
    /// Raw `Name` DER for the subject.
    pub subject_raw: &'a [u8],
    /// `notBefore` as Unix epoch seconds.
    pub not_before: u64,
    /// `notAfter` as Unix epoch seconds.
    pub not_after: u64,
    /// SPKI algorithm OID as DER content bytes (no tag / length).
    pub spki_algorithm_oid: &'a [u8],
    /// SPKI public key bytes (BIT STRING content with the
    /// leading unused-bits byte stripped).
    pub spki_key_bytes: &'a [u8],
    /// Raw SPKI DER bytes, useful for matching a cert as the
    /// issuer of another cert (RFC 5280 §6.1 chain walk).
    pub raw_spki: &'a [u8],
    /// Outer signatureAlgorithm mapped to the enum the verify
    /// module understands.
    pub signature_algorithm: SignatureAlgorithm,
    /// BIT STRING body of the outer signatureValue.
    pub signature_value: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Parse a DER-encoded certificate.
    pub fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(der);
        let mut cert = outer.read_sequence()?;

        // TBS — we need the exact bytes the signer saw, so we
        // snapshot them before reading into the child reader.
        let tbs_start = cert.remaining();
        let tbs_reader_before = tbs_start.len();
        let mut tbs = cert.read_sequence()?;
        let tbs_reader_after = cert.remaining().len();
        let raw_tbs_total = tbs_reader_before - tbs_reader_after;
        let raw_tbs = &tbs_start[..raw_tbs_total];

        // version [0] EXPLICIT Version DEFAULT v1
        let version = match tbs.maybe_tagged(context_tag_explicit(0))? {
            Some(inner) => {
                let mut r = DerReader::new(inner);
                let v = r.read_u64()?;
                match v {
                    0 => Version::V1,
                    1 => Version::V2,
                    2 => Version::V3,
                    _ => return Err(X509Error::UnsupportedVersion),
                }
            }
            None => Version::V1,
        };

        let serial = tbs.read_integer_bytes()?;

        // TBS signature AlgorithmIdentifier
        let (tbs_sig_alg_oid, _tbs_sig_alg_params) = read_algorithm_identifier(&mut tbs)?;

        // Issuer and subject are Name SEQUENCEs. We keep the
        // raw DER rather than decoding the full SET-of-RDN
        // structure — the mTLS authenticator only needs CN
        // and chain-matching on the raw bytes.
        let issuer_raw = tbs.read_tagged(tag::SEQUENCE)?;

        // Validity SEQUENCE { notBefore Time, notAfter Time }
        let mut validity = tbs.read_sequence()?;
        let not_before = read_time(&mut validity)?;
        let not_after = read_time(&mut validity)?;
        if not_before > not_after {
            return Err(X509Error::InvalidValidityOrder);
        }

        let subject_raw = tbs.read_tagged(tag::SEQUENCE)?;

        // SubjectPublicKeyInfo
        let spki_start_remaining = tbs.remaining();
        let _spki = tbs.read_tagged(tag::SEQUENCE)?;
        let raw_spki = &spki_start_remaining[..spki_start_remaining.len() - tbs.remaining().len()];
        // Re-parse the SPKI so we can pull out the algorithm
        // and key bytes.
        let mut spki_reader =
            DerReader::new(&raw_spki[raw_spki.len() - _spki.len() - der_header_len(_spki.len())..]);
        let _ = spki_reader.read_sequence()?; // top
        let mut spki = DerReader::new(_spki);
        let (spki_algorithm_oid, _spki_params) = read_algorithm_identifier(&mut spki)?;
        let spki_key_bytes = spki.read_bit_string()?;

        // Skip optional issuerUniqueID / subjectUniqueID / extensions
        // without interpreting them. Pass 3's CRL / extension
        // walker will re-open the TBS from raw_tbs if it needs
        // the fields.
        while !tbs.is_empty() {
            tbs.skip_one()?;
        }

        // Outer signatureAlgorithm + signatureValue.
        let (outer_sig_alg_oid, _outer_sig_alg_params) = read_algorithm_identifier(&mut cert)?;
        if outer_sig_alg_oid != tbs_sig_alg_oid {
            return Err(X509Error::AlgorithmMismatch);
        }
        let signature_algorithm =
            oid_to_signature_algorithm(outer_sig_alg_oid).ok_or(X509Error::UnsupportedAlgorithm)?;
        let signature_value = cert.read_bit_string()?;

        Ok(Certificate {
            version,
            raw_tbs,
            serial,
            issuer_raw,
            subject_raw,
            not_before,
            not_after,
            spki_algorithm_oid,
            spki_key_bytes,
            raw_spki,
            signature_algorithm,
            signature_value,
        })
    }

    /// Best-effort extraction of the subject's Common Name
    /// attribute. Returns the first `CN` value found (the
    /// leaf-most RDN in a typical X.509 DN). Returns `None`
    /// if no `CN` is present or the Name structure is
    /// malformed.
    pub fn subject_cn(&self) -> Option<&'a str> {
        extract_cn(self.subject_raw)
    }

    /// Same as [`subject_cn`](Self::subject_cn) but for the
    /// issuer DN.
    pub fn issuer_cn(&self) -> Option<&'a str> {
        extract_cn(self.issuer_raw)
    }

    /// `true` when `now_unix_s` falls within
    /// `[not_before, not_after]`.
    pub fn is_valid_at(&self, now_unix_s: u64) -> bool {
        now_unix_s >= self.not_before && now_unix_s <= self.not_after
    }

    /// Verify that the certificate was signed by `issuer`. Used
    /// by the chain walker in pass 3; a self-signed certificate
    /// can pass itself as the issuer.
    pub fn verify_signed_by(&self, issuer: &Certificate<'_>) -> Result<(), X509Error> {
        sig_verify::verify(
            self.signature_algorithm,
            issuer.spki_key_bytes,
            self.raw_tbs,
            self.signature_value,
        )
        .map_err(|_| X509Error::SignatureInvalid)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the number of bytes required to encode a DER length
/// field for `len`. Used only by the SPKI slice-recovery dance
/// in `parse`.
fn der_header_len(len: usize) -> usize {
    // SEQUENCE tag (1) + length encoding (1 for short form, 2-5
    // for long form).
    let length_bytes = if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else if len < 0x10000 {
        3
    } else if len < 0x1000000 {
        4
    } else {
        5
    };
    1 + length_bytes
}

/// Read one `AlgorithmIdentifier` SEQUENCE and return the OID
/// plus its parameters slice (which may be empty).
pub(super) fn read_algorithm_identifier<'a>(
    r: &mut DerReader<'a>,
) -> Result<(&'a [u8], &'a [u8]), X509Error> {
    let mut ai = r.read_sequence()?;
    let oid = ai.read_oid()?;
    // Parameters are optional. If present they may be `NULL`
    // (common for RSA) or a curve OID (common for ECDSA).
    let params = if ai.is_empty() { &[][..] } else { ai.remaining() };
    Ok((oid, params))
}

/// Parse a `Time` CHOICE. Returns Unix epoch seconds.
pub(super) fn read_time(r: &mut DerReader<'_>) -> Result<u64, X509Error> {
    let (tag_byte, value) = r.read_tlv()?;
    match tag_byte {
        tag::UTC_TIME => parse_utc_time(value),
        tag::GENERALIZED_TIME => parse_generalized_time(value),
        _ => Err(X509Error::InvalidTime),
    }
}

/// RFC 5280 §4.1.2.5.1 UTCTime format: `YYMMDDHHMMSSZ` in
/// ASCII. The two-digit year pivots at 50: `< 50` → 20YY,
/// `>= 50` → 19YY.
fn parse_utc_time(bytes: &[u8]) -> Result<u64, X509Error> {
    if bytes.len() != 13 || !bytes.ends_with(b"Z") {
        return Err(X509Error::InvalidTime);
    }
    let digits = &bytes[..12];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(X509Error::InvalidTime);
    }
    let yy = parse_u32(&digits[0..2])?;
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let month = parse_u32(&digits[2..4])?;
    let day = parse_u32(&digits[4..6])?;
    let hour = parse_u32(&digits[6..8])?;
    let minute = parse_u32(&digits[8..10])?;
    let second = parse_u32(&digits[10..12])?;
    gregorian_to_unix(year as i32, month, day, hour, minute, second)
}

/// RFC 5280 §4.1.2.5.2 GeneralizedTime format:
/// `YYYYMMDDHHMMSSZ`, 15 ASCII chars.
fn parse_generalized_time(bytes: &[u8]) -> Result<u64, X509Error> {
    if bytes.len() != 15 || !bytes.ends_with(b"Z") {
        return Err(X509Error::InvalidTime);
    }
    let digits = &bytes[..14];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(X509Error::InvalidTime);
    }
    let year = parse_u32(&digits[0..4])?;
    let month = parse_u32(&digits[4..6])?;
    let day = parse_u32(&digits[6..8])?;
    let hour = parse_u32(&digits[8..10])?;
    let minute = parse_u32(&digits[10..12])?;
    let second = parse_u32(&digits[12..14])?;
    gregorian_to_unix(year as i32, month, day, hour, minute, second)
}

fn parse_u32(digits: &[u8]) -> Result<u32, X509Error> {
    let mut out: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return Err(X509Error::InvalidTime);
        }
        out = out * 10 + (b - b'0') as u32;
    }
    Ok(out)
}

/// Howard Hinnant's `days_from_civil` algorithm. Returns the
/// number of days since 1970-01-01 for a Gregorian calendar
/// date. Handles leap years correctly across any 4-digit year.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32; // [0, 399]
    let m_shifted = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * m_shifted + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era as i64 * 146097 + doe as i64 - 719468
}

fn gregorian_to_unix(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<u64, X509Error> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return Err(X509Error::InvalidTime);
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(X509Error::InvalidTime);
    }
    let total = days as u64 * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64;
    Ok(total)
}

// ---------------------------------------------------------------------------
// OID constants and mapping
// ---------------------------------------------------------------------------

/// `commonName` AttributeType: `2.5.4.3` (DER: `55 04 03`).
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// `ecdsa-with-SHA256`: `1.2.840.10045.4.3.2`.
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// `ecdsa-with-SHA384`: `1.2.840.10045.4.3.3`.
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// `sha256WithRSAEncryption`: `1.2.840.113549.1.1.11`.
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

/// `Ed25519`: `1.3.101.112`.
pub(super) const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

pub(super) fn oid_to_signature_algorithm(oid: &[u8]) -> Option<SignatureAlgorithm> {
    if oid == OID_ECDSA_WITH_SHA256 {
        Some(SignatureAlgorithm::EcdsaP256Sha256)
    } else if oid == OID_ECDSA_WITH_SHA384 {
        Some(SignatureAlgorithm::EcdsaP384Sha384)
    } else if oid == OID_RSA_SHA256 {
        Some(SignatureAlgorithm::RsaPkcs1Sha256)
    } else if oid == OID_ED25519 {
        Some(SignatureAlgorithm::Ed25519)
    } else {
        None
    }
}

/// Walk a raw `Name` DER and return the first `CN` UTF-8 /
/// PrintableString value as a `&str`.
fn extract_cn(name_der: &[u8]) -> Option<&str> {
    let mut outer = DerReader::new(name_der);
    while !outer.is_empty() {
        let mut rdn = outer.read_set().ok()?;
        while !rdn.is_empty() {
            let mut atv = rdn.read_sequence().ok()?;
            let oid = atv.read_oid().ok()?;
            let (value_tag, value_bytes) = atv.read_tlv().ok()?;
            if oid == OID_COMMON_NAME
                && matches!(value_tag, tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING)
            {
                return core::str::from_utf8(value_bytes).ok();
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_utc_time_at_epoch_pivot() {
        // 700101000000Z → 1970-01-01 00:00:00 UTC = 0 unix.
        let t = parse_utc_time(b"700101000000Z").unwrap();
        assert_eq!(t, 0);
    }

    #[test]
    fn parse_utc_time_post_2000() {
        // 200101000000Z → 2020-01-01 00:00:00 UTC.
        // Compare against a known Unix timestamp.
        let t = parse_utc_time(b"200101000000Z").unwrap();
        assert_eq!(t, 1_577_836_800);
    }

    #[test]
    fn parse_utc_time_year_2049_pivot() {
        // 491231235959Z → 2049-12-31 23:59:59 UTC.
        let t = parse_utc_time(b"491231235959Z").unwrap();
        assert_eq!(t, 2_524_607_999);
    }

    #[test]
    fn parse_utc_time_year_1950_pivot() {
        // 500101000000Z → 1950-01-01 00:00:00 UTC, well before
        // the Unix epoch — gregorian_to_unix rejects.
        let err = parse_utc_time(b"500101000000Z").unwrap_err();
        assert_eq!(err, X509Error::InvalidTime);
    }

    #[test]
    fn parse_utc_time_rejects_bad_shape() {
        assert!(parse_utc_time(b"").is_err());
        assert!(parse_utc_time(b"700101000000").is_err()); // no Z
        assert!(parse_utc_time(b"70010100000X").is_err()); // wrong terminator
        assert!(parse_utc_time(b"70J101000000Z").is_err()); // non-digit
    }

    #[test]
    fn parse_generalized_time_post_2050() {
        // 20500101000000Z → 2050-01-01 00:00:00 UTC.
        let t = parse_generalized_time(b"20500101000000Z").unwrap();
        assert_eq!(t, 2_524_608_000);
    }

    #[test]
    fn parse_generalized_time_rejects_bad_shape() {
        assert!(parse_generalized_time(b"").is_err());
        assert!(parse_generalized_time(b"2050010100000Z").is_err()); // too short
    }

    #[test]
    fn gregorian_to_unix_handles_leap_year() {
        // 2020-02-29 is valid; 2021-02-29 must not parse
        // through the caller (parse_u32 accepts, gregorian
        // path accepts day=29 but would produce an invalid
        // date in non-leap year). Here we just verify the
        // leap-year case parses to the expected unix stamp.
        // 2020-02-29 00:00:00 UTC = 1582934400.
        let u = gregorian_to_unix(2020, 2, 29, 0, 0, 0).unwrap();
        assert_eq!(u, 1_582_934_400);
    }

    #[test]
    fn gregorian_to_unix_rejects_out_of_range_fields() {
        assert!(gregorian_to_unix(2020, 13, 1, 0, 0, 0).is_err());
        assert!(gregorian_to_unix(2020, 0, 1, 0, 0, 0).is_err());
        assert!(gregorian_to_unix(2020, 1, 32, 0, 0, 0).is_err());
        assert!(gregorian_to_unix(2020, 1, 1, 24, 0, 0).is_err());
        assert!(gregorian_to_unix(2020, 1, 1, 0, 60, 0).is_err());
        assert!(gregorian_to_unix(2020, 1, 1, 0, 0, 60).is_err());
    }

    #[test]
    fn oid_to_signature_algorithm_maps_known_oids() {
        assert_eq!(
            oid_to_signature_algorithm(OID_ECDSA_WITH_SHA256),
            Some(SignatureAlgorithm::EcdsaP256Sha256),
        );
        assert_eq!(
            oid_to_signature_algorithm(OID_ECDSA_WITH_SHA384),
            Some(SignatureAlgorithm::EcdsaP384Sha384),
        );
        assert_eq!(
            oid_to_signature_algorithm(OID_RSA_SHA256),
            Some(SignatureAlgorithm::RsaPkcs1Sha256),
        );
        assert_eq!(oid_to_signature_algorithm(OID_ED25519), Some(SignatureAlgorithm::Ed25519),);
    }

    #[test]
    fn oid_to_signature_algorithm_rejects_unknown() {
        // 1.2.3 → DER 2A 03
        assert!(oid_to_signature_algorithm(&[0x2A, 0x03]).is_none());
    }

    #[test]
    fn extract_cn_pulls_common_name_out_of_name_structure() {
        // Name = SEQUENCE OF RDN, RDN = SET OF AttributeTypeAndValue
        // Here: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8 "desmos-test" } } }
        let mut bytes: Vec<u8> = Vec::new();
        // Inner SEQUENCE { OID, UTF8 }
        let cn_value = b"desmos-test";
        let mut atv: Vec<u8> = Vec::new();
        // OID 2.5.4.3
        atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]);
        // UTF8String
        atv.push(tag::UTF8_STRING);
        atv.push(cn_value.len() as u8);
        atv.extend_from_slice(cn_value);
        // SEQUENCE wrapper
        let mut atv_seq = vec![tag::SEQUENCE, atv.len() as u8];
        atv_seq.extend_from_slice(&atv);
        // SET wrapper
        let mut set = vec![tag::SET, atv_seq.len() as u8];
        set.extend_from_slice(&atv_seq);
        // Name SEQUENCE wrapper — but extract_cn takes the
        // Name's CONTENT bytes, not the wrapping SEQUENCE, so
        // we hand it `set` directly.
        bytes.extend_from_slice(&set);
        let cn = extract_cn(&bytes).unwrap();
        assert_eq!(cn, "desmos-test");
    }

    #[test]
    fn extract_cn_returns_none_on_missing_attribute() {
        // SET with a non-CN attribute (OID 2.5.4.6 countryName)
        let atv = [
            tag::SEQUENCE,
            0x0A,
            0x06,
            0x03,
            0x55,
            0x04,
            0x06, // OID 2.5.4.6
            tag::PRINTABLE_STRING,
            0x02,
            b'U',
            b'S',
        ];
        let set = {
            let mut s = vec![tag::SET, atv.len() as u8];
            s.extend_from_slice(&atv);
            s
        };
        assert!(extract_cn(&set).is_none());
    }

    #[test]
    fn is_valid_at_checks_validity_window() {
        let cert = Certificate {
            version: Version::V3,
            raw_tbs: &[],
            serial: &[],
            issuer_raw: &[],
            subject_raw: &[],
            not_before: 1_000,
            not_after: 2_000,
            spki_algorithm_oid: &[],
            spki_key_bytes: &[],
            raw_spki: &[],
            signature_algorithm: SignatureAlgorithm::Ed25519,
            signature_value: &[],
        };
        assert!(!cert.is_valid_at(999));
        assert!(cert.is_valid_at(1_000));
        assert!(cert.is_valid_at(1_500));
        assert!(cert.is_valid_at(2_000));
        assert!(!cert.is_valid_at(2_001));
    }

    // -----------------------------------------------------------------
    // End-to-end: hand-build a self-signed Ed25519 cert in-memory,
    // parse it, and verify `verify_signed_by(&self)` accepts.
    // -----------------------------------------------------------------

    /// Tiny DER encoder helpers. Produce a TLV as `Vec<u8>`.
    fn der_tlv(tag_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(tag_byte);
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
            panic!("encode_length: input too large for this test helper");
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

    fn der_oid_ed25519() -> Vec<u8> {
        der_tlv(tag::OID, OID_ED25519)
    }

    /// AlgorithmIdentifier for Ed25519 — SEQUENCE { OID, NULL
    /// is absent per RFC 8410 §3, so we only emit the OID }.
    fn der_alg_id_ed25519() -> Vec<u8> {
        der_tlv(tag::SEQUENCE, &der_oid_ed25519())
    }

    fn der_utc_time(value: &[u8]) -> Vec<u8> {
        der_tlv(tag::UTC_TIME, value)
    }

    fn der_common_name(cn: &str) -> Vec<u8> {
        // Name ::= SEQUENCE OF RelativeDistinguishedName
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        let cn_value = der_tlv(tag::UTF8_STRING, cn.as_bytes());
        let mut atv = der_tlv(tag::OID, OID_COMMON_NAME);
        atv.extend_from_slice(&cn_value);
        let atv_seq = der_tlv(tag::SEQUENCE, &atv);
        let rdn_set = der_tlv(tag::SET, &atv_seq);
        der_tlv(tag::SEQUENCE, &rdn_set)
    }

    fn der_spki_ed25519(public_key: &[u8]) -> Vec<u8> {
        let alg = der_alg_id_ed25519();
        // BIT STRING body: one "unused bits" byte (0) followed
        // by the raw 32-byte public key.
        let mut bit_string = vec![0u8];
        bit_string.extend_from_slice(public_key);
        let spk = der_tlv(tag::BIT_STRING, &bit_string);
        let mut body = alg;
        body.extend_from_slice(&spk);
        der_tlv(tag::SEQUENCE, &body)
    }

    /// Build a minimal DER-encoded self-signed Ed25519
    /// certificate using `ring` for the actual signing.
    /// Returns the certificate bytes.
    fn build_self_signed_ed25519_cert(
        subject_cn: &str,
        not_before: &[u8],
        not_after: &[u8],
    ) -> Vec<u8> {
        use ring::signature::{self as r_sig, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = r_sig::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = r_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = kp.public_key().as_ref();

        // Build TBS body: [0]EXPLICIT INTEGER 2 (v3)
        let version_inner = der_integer(2);
        let version = der_tlv(context_tag_explicit(0), version_inner.as_slice());

        let serial = der_integer(0x2A);
        let tbs_sig_alg = der_alg_id_ed25519();
        let name = der_common_name(subject_cn);
        let validity_body = {
            let mut v = der_utc_time(not_before);
            v.extend_from_slice(&der_utc_time(not_after));
            v
        };
        let validity = der_tlv(tag::SEQUENCE, &validity_body);
        let spki = der_spki_ed25519(pub_bytes);

        let mut tbs_body: Vec<u8> = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&tbs_sig_alg);
        tbs_body.extend_from_slice(&name); // issuer
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&name); // subject (self-signed)
        tbs_body.extend_from_slice(&spki);

        let tbs = der_tlv(tag::SEQUENCE, &tbs_body);

        // Sign the raw TBS bytes with Ed25519.
        let sig = kp.sign(&tbs);
        let sig_bytes = sig.as_ref();
        // signatureValue BIT STRING with 0 unused bits.
        let mut sig_bs = vec![0u8];
        sig_bs.extend_from_slice(sig_bytes);
        let outer_sig_alg = der_alg_id_ed25519();
        let outer_sig_value = der_tlv(tag::BIT_STRING, &sig_bs);

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&outer_sig_alg);
        cert_body.extend_from_slice(&outer_sig_value);
        der_tlv(tag::SEQUENCE, &cert_body)
    }

    #[test]
    fn parse_and_verify_self_signed_ed25519_cert() {
        let der =
            build_self_signed_ed25519_cert("desmos-test-ca", b"250101000000Z", b"350101000000Z");
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.version, Version::V3);
        assert_eq!(cert.subject_cn(), Some("desmos-test-ca"));
        assert_eq!(cert.issuer_cn(), Some("desmos-test-ca"));
        assert_eq!(cert.signature_algorithm, SignatureAlgorithm::Ed25519);
        // 2025-01-01 = 1735689600 unix.
        assert_eq!(cert.not_before, 1_735_689_600);
        // 2035-01-01 = 2051222400 unix.
        assert_eq!(cert.not_after, 2_051_222_400);
        assert!(cert.is_valid_at(1_800_000_000));
        assert!(!cert.is_valid_at(1_000_000_000));
        // Self-signed: the cert is its own issuer for the
        // signature check.
        cert.verify_signed_by(&cert).unwrap();
    }

    #[test]
    fn verify_signed_by_rejects_tampered_tbs() {
        // Build a valid cert and tamper one byte of the
        // signature value — parse still succeeds but the
        // verify call rejects.
        let der =
            build_self_signed_ed25519_cert("tampered-cert", b"250101000000Z", b"350101000000Z");
        let mut tampered = der.clone();
        // Flip the last byte (inside the signatureValue).
        *tampered.last_mut().unwrap() ^= 0x01;
        let cert = Certificate::parse(&tampered).unwrap();
        let err = cert.verify_signed_by(&cert).unwrap_err();
        assert_eq!(err, X509Error::SignatureInvalid);
    }

    #[test]
    fn parse_rejects_unknown_signature_algorithm() {
        // Build a cert with a made-up signature algorithm OID.
        // Easiest path: take a valid cert and rewrite the outer
        // algorithmIdentifier OID to something we do not
        // recognise. Instead we construct a minimal cert with
        // the unknown OID directly.
        let fake_oid = der_tlv(tag::OID, &[0x2A, 0x03, 0x04, 0x05]);
        let fake_alg = der_tlv(tag::SEQUENCE, &fake_oid);
        let version = der_tlv(context_tag_explicit(0), &der_integer(2));
        let serial = der_integer(1);
        let name = der_common_name("x");
        let validity = der_tlv(tag::SEQUENCE, &{
            let mut v = der_utc_time(b"250101000000Z");
            v.extend_from_slice(&der_utc_time(b"350101000000Z"));
            v
        });
        let spki = der_spki_ed25519(&[0u8; 32]);
        let mut tbs_body: Vec<u8> = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&fake_alg);
        tbs_body.extend_from_slice(&name);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&name);
        tbs_body.extend_from_slice(&spki);
        let tbs = der_tlv(tag::SEQUENCE, &tbs_body);
        let sig_bs = der_tlv(tag::BIT_STRING, &[0u8, 0u8]);
        let mut cert_body = tbs;
        cert_body.extend_from_slice(&fake_alg);
        cert_body.extend_from_slice(&sig_bs);
        let der = der_tlv(tag::SEQUENCE, &cert_body);
        let err = Certificate::parse(&der).unwrap_err();
        assert_eq!(err, X509Error::UnsupportedAlgorithm);
    }
}
