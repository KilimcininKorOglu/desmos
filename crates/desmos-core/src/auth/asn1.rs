//! Minimal ASN.1 DER reader for X.509 certificate parsing.
//!
//! The mTLS authenticator has to walk a `Certificate` and a
//! `TBSCertificate` structure as defined in RFC 5280 §4.1, plus a
//! `TBSCertList` for CRL checking (§5.1). Every field we care
//! about uses a handful of universal ASN.1 tags: `SEQUENCE`,
//! `SET`, `INTEGER`, `OID`, `UTF8String`, `PrintableString`,
//! `UTCTime`, `GeneralizedTime`, `BIT STRING`, `OCTET STRING`,
//! plus context-specific `[N] EXPLICIT` tags for optional fields
//! (version number, extensions).
//!
//! Pulling in a general-purpose ASN.1 crate would break the
//! 5-runtime-crate rule, so we hand-roll a small reader that
//! covers exactly what the parser needs and nothing else. The
//! reader is bounds-checked at every step — a malformed
//! certificate cannot induce an out-of-range slice.
//!
//! # What this reader does NOT do
//!
//! - **BER indefinite length** (§8.1.3.6): DER always uses
//!   definite length, so every valid certificate skips this.
//! - **BIT STRING with non-zero unused bits**: X.509 signature
//!   and SPKI fields always pad to whole bytes, so the first
//!   byte of the content is always zero.
//! - **Long-form tag numbers (> 30)**: the tags we care about
//!   all fit in the short form.
//!
//! Any input that needs those features is rejected as
//! [`Asn1Error::Unsupported`].

use core::fmt;

/// Universal tag numbers we care about.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30; // SEQUENCE | constructed bit
    pub const SET: u8 = 0x31; // SET | constructed bit
}

/// Construct a context-specific tag. `[N] EXPLICIT` fields use
/// the constructed form (`0xA0 | n`) when they wrap another TLV.
pub const fn context_tag_explicit(n: u8) -> u8 {
    0xA0 | n
}

/// Errors the reader produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Error {
    /// Fewer bytes remain than the parser expected.
    Truncated,
    /// Length encoding is malformed: too many length bytes,
    /// reserved 0x80 indefinite form, or length exceeds the
    /// buffer.
    BadLength,
    /// Tag did not match the expected universal / context-
    /// specific value.
    UnexpectedTag { expected: u8, got: u8 },
    /// BIT STRING header declares non-zero unused bits, which
    /// the parser does not need to handle and refuses.
    UnsupportedBitString,
    /// The value bytes failed a content-level check (for
    /// example, a BOOLEAN with a byte other than 0x00 / 0xFF).
    InvalidValue(&'static str),
    /// Explicit "we do not support this" for any higher-layer
    /// quirk the mTLS path runs into.
    Unsupported(&'static str),
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("asn1: truncated TLV"),
            Self::BadLength => f.write_str("asn1: malformed length"),
            Self::UnexpectedTag { expected, got } => {
                write!(f, "asn1: unexpected tag {got:#04x}, expected {expected:#04x}")
            }
            Self::UnsupportedBitString => f.write_str("asn1: BIT STRING with non-zero unused bits"),
            Self::InvalidValue(reason) => write!(f, "asn1: invalid value: {reason}"),
            Self::Unsupported(reason) => write!(f, "asn1: unsupported: {reason}"),
        }
    }
}

impl std::error::Error for Asn1Error {}

/// Stateful byte reader over a DER blob.
///
/// `DerReader` is explicitly not `Copy` — callers pass it by
/// value to helpers that need to consume it, or by `&mut` to
/// helpers that advance the same cursor.
#[derive(Debug, Clone)]
pub struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// Wrap a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// `true` when no bytes remain.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Bytes still to read.
    pub fn remaining_len(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Slice of every byte already read. Useful for recomputing
    /// a hash over the TBS portion of a certificate.
    pub fn consumed(&self) -> &'a [u8] {
        &self.buf[..self.pos]
    }

    /// Slice of every byte not yet read.
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn read_byte(&mut self) -> Result<u8, Asn1Error> {
        let b = *self.buf.get(self.pos).ok_or(Asn1Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read one DER TLV (tag + length + value bytes) and return
    /// the tag plus a slice of the value. The cursor advances
    /// past the value.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), Asn1Error> {
        let start = self.pos;
        let tag = self.read_byte()?;
        // Long-form tags (tag number >= 31) encode the low 5
        // bits as 0x1F and then a multi-byte number. None of the
        // tags in X.509 need this, so we reject it explicitly.
        if tag & 0x1F == 0x1F {
            return Err(Asn1Error::Unsupported("long-form tag"));
        }
        let len = self.read_length()?;
        if self.pos + len > self.buf.len() {
            // Rewind on failure so the caller sees a clean
            // "truncated" at the original position.
            self.pos = start;
            return Err(Asn1Error::Truncated);
        }
        let value = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, value))
    }

    fn read_length(&mut self) -> Result<usize, Asn1Error> {
        let first = self.read_byte()?;
        if first < 0x80 {
            return Ok(first as usize);
        }
        if first == 0x80 {
            // Indefinite length: BER-only, invalid in DER.
            return Err(Asn1Error::BadLength);
        }
        let n = (first & 0x7F) as usize;
        // A length field over 4 bytes would imply a value larger
        // than any realistic certificate; cap at 4.
        if n == 0 || n > 4 {
            return Err(Asn1Error::BadLength);
        }
        let mut len = 0usize;
        for _ in 0..n {
            let b = self.read_byte()?;
            len = (len << 8) | (b as usize);
        }
        Ok(len)
    }

    /// Read a TLV whose tag must equal `expected`. Returns the
    /// value slice on success; returns [`Asn1Error::UnexpectedTag`]
    /// and rewinds the cursor on mismatch.
    pub fn read_tagged(&mut self, expected: u8) -> Result<&'a [u8], Asn1Error> {
        let start = self.pos;
        let (tag, value) = self.read_tlv()?;
        if tag != expected {
            self.pos = start;
            return Err(Asn1Error::UnexpectedTag { expected, got: tag });
        }
        Ok(value)
    }

    /// Peek at the next tag without advancing. Returns `None` if
    /// the reader is empty.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Read a SEQUENCE and return a child reader over its
    /// contents.
    pub fn read_sequence(&mut self) -> Result<DerReader<'a>, Asn1Error> {
        let value = self.read_tagged(tag::SEQUENCE)?;
        Ok(DerReader::new(value))
    }

    /// Read a SET and return a child reader over its contents.
    pub fn read_set(&mut self) -> Result<DerReader<'a>, Asn1Error> {
        let value = self.read_tagged(tag::SET)?;
        Ok(DerReader::new(value))
    }

    /// Read an INTEGER and return its raw content bytes (the
    /// DER integer representation, big-endian, possibly with a
    /// leading zero pad to keep the sign positive).
    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], Asn1Error> {
        self.read_tagged(tag::INTEGER)
    }

    /// Read an INTEGER that fits in a `u64`. Used for parsing
    /// the certificate version number and similar small values.
    /// Rejects negative integers and values > u64::MAX.
    pub fn read_u64(&mut self) -> Result<u64, Asn1Error> {
        let bytes = self.read_integer_bytes()?;
        if bytes.is_empty() {
            return Err(Asn1Error::InvalidValue("empty INTEGER"));
        }
        if bytes[0] & 0x80 != 0 {
            return Err(Asn1Error::InvalidValue("negative INTEGER"));
        }
        // A leading zero is allowed (and required) when the
        // high bit of the first significant byte is set.
        let significant = if bytes.len() > 1 && bytes[0] == 0 { &bytes[1..] } else { bytes };
        if significant.len() > 8 {
            return Err(Asn1Error::InvalidValue("INTEGER > u64"));
        }
        let mut out = 0u64;
        for &b in significant {
            out = (out << 8) | (b as u64);
        }
        Ok(out)
    }

    /// Read an OBJECT IDENTIFIER and return its DER-encoded
    /// bytes (the content of the TLV, without the tag / length
    /// prefix). The parser compares OIDs by byte equality, so
    /// we never need to decode the arc representation.
    pub fn read_oid(&mut self) -> Result<&'a [u8], Asn1Error> {
        self.read_tagged(tag::OID)
    }

    /// Read a BIT STRING and return its content bytes. DER
    /// BIT STRING values start with a single "unused bits" byte
    /// followed by the actual data. We only accept `unused = 0`
    /// because every signature and public key in X.509 pads to
    /// whole bytes.
    pub fn read_bit_string(&mut self) -> Result<&'a [u8], Asn1Error> {
        let body = self.read_tagged(tag::BIT_STRING)?;
        if body.is_empty() {
            return Err(Asn1Error::InvalidValue("empty BIT STRING"));
        }
        if body[0] != 0 {
            return Err(Asn1Error::UnsupportedBitString);
        }
        Ok(&body[1..])
    }

    /// Read an OCTET STRING and return its content bytes.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], Asn1Error> {
        self.read_tagged(tag::OCTET_STRING)
    }

    /// Read a NULL TLV. The value must be empty.
    pub fn read_null(&mut self) -> Result<(), Asn1Error> {
        let value = self.read_tagged(tag::NULL)?;
        if !value.is_empty() {
            return Err(Asn1Error::InvalidValue("NULL with non-empty value"));
        }
        Ok(())
    }

    /// Read a BOOLEAN. DER encodes TRUE as `0xFF`; any non-
    /// zero value is technically BER-TRUE but strict DER
    /// requires `0xFF`, so we enforce it.
    pub fn read_bool(&mut self) -> Result<bool, Asn1Error> {
        let body = self.read_tagged(tag::BOOLEAN)?;
        if body.len() != 1 {
            return Err(Asn1Error::InvalidValue("BOOLEAN length != 1"));
        }
        match body[0] {
            0x00 => Ok(false),
            0xFF => Ok(true),
            _ => Err(Asn1Error::InvalidValue("BOOLEAN non-DER value")),
        }
    }

    /// Skip the next TLV, whatever it is. Useful for walking
    /// past optional fields the parser does not care about.
    pub fn skip_one(&mut self) -> Result<(), Asn1Error> {
        let _ = self.read_tlv()?;
        Ok(())
    }

    /// Try to read a TLV only if the next tag matches `expected`.
    /// Returns `Ok(Some(value))` on match, `Ok(None)` if the
    /// reader is empty or the next tag is different, and
    /// `Err` if the match succeeds but the TLV is malformed.
    pub fn maybe_tagged(&mut self, expected: u8) -> Result<Option<&'a [u8]>, Asn1Error> {
        match self.peek_tag() {
            Some(t) if t == expected => self.read_tagged(expected).map(Some),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(bytes: &[u8]) -> DerReader<'_> {
        DerReader::new(bytes)
    }

    #[test]
    fn short_form_length_is_a_single_byte() {
        // SEQUENCE, length 2, two INTEGER bytes.
        let bytes = [0x30, 0x02, 0x02, 0x01];
        let mut r = reader(&bytes);
        let (tag, value) = r.read_tlv().unwrap();
        assert_eq!(tag, tag::SEQUENCE);
        assert_eq!(value, &[0x02, 0x01]);
        assert!(r.is_empty());
    }

    #[test]
    fn long_form_length_two_bytes() {
        // SEQUENCE, length 0x0100 = 256 bytes of payload.
        let mut bytes = vec![0x30, 0x82, 0x01, 0x00];
        bytes.extend(std::iter::repeat(0xAA).take(256));
        let mut r = reader(&bytes);
        let (tag, value) = r.read_tlv().unwrap();
        assert_eq!(tag, tag::SEQUENCE);
        assert_eq!(value.len(), 256);
        assert!(value.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn indefinite_length_is_rejected() {
        // 0x80 alone means indefinite length — BER only.
        let bytes = [0x30, 0x80];
        let mut r = reader(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), Asn1Error::BadLength);
    }

    #[test]
    fn truncated_tlv_reports_truncated() {
        // SEQUENCE claims 5 bytes but only 2 are present.
        let bytes = [0x30, 0x05, 0x01, 0x02];
        let mut r = reader(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), Asn1Error::Truncated);
        // Cursor stays at the start so a caller that retries
        // against a grown buffer still sees a clean state.
        assert_eq!(r.remaining().len(), 4);
    }

    #[test]
    fn read_tagged_rejects_mismatched_tag_and_rewinds() {
        // INTEGER where the caller expected SEQUENCE.
        let bytes = [0x02, 0x01, 0x42];
        let mut r = reader(&bytes);
        let err = r.read_tagged(tag::SEQUENCE).unwrap_err();
        assert_eq!(err, Asn1Error::UnexpectedTag { expected: tag::SEQUENCE, got: tag::INTEGER },);
        // Still at position 0 after the rewind.
        let (tag, value) = r.read_tlv().unwrap();
        assert_eq!(tag, tag::INTEGER);
        assert_eq!(value, &[0x42]);
    }

    #[test]
    fn read_sequence_returns_child_reader_over_contents() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let bytes = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut r = reader(&bytes);
        let mut inner = r.read_sequence().unwrap();
        let a = inner.read_u64().unwrap();
        let b = inner.read_u64().unwrap();
        assert_eq!((a, b), (1, 2));
        assert!(inner.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn read_u64_accepts_multi_byte_integer() {
        // INTEGER 0x12345678 = 305419896
        let bytes = [0x02, 0x04, 0x12, 0x34, 0x56, 0x78];
        let mut r = reader(&bytes);
        assert_eq!(r.read_u64().unwrap(), 0x12345678);
    }

    #[test]
    fn read_u64_accepts_leading_zero_pad() {
        // INTEGER 0x00FF means 255 (leading zero keeps it positive).
        let bytes = [0x02, 0x02, 0x00, 0xFF];
        let mut r = reader(&bytes);
        assert_eq!(r.read_u64().unwrap(), 255);
    }

    #[test]
    fn read_u64_rejects_negative_integer() {
        // INTEGER 0xFF = -1 in DER's two's complement signed encoding.
        let bytes = [0x02, 0x01, 0xFF];
        let mut r = reader(&bytes);
        assert_eq!(r.read_u64().unwrap_err(), Asn1Error::InvalidValue("negative INTEGER"),);
    }

    #[test]
    fn read_u64_rejects_overflow() {
        // 9 significant bytes = cannot fit in u64.
        let bytes = [0x02, 0x09, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut r = reader(&bytes);
        assert_eq!(r.read_u64().unwrap_err(), Asn1Error::InvalidValue("INTEGER > u64"),);
    }

    #[test]
    fn read_bit_string_strips_unused_bits_byte() {
        // BIT STRING { 0x00 unused-bits, 0xDE 0xAD 0xBE 0xEF }
        let bytes = [0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut r = reader(&bytes);
        let body = r.read_bit_string().unwrap();
        assert_eq!(body, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn read_bit_string_rejects_non_zero_unused_bits() {
        // First content byte is 0x04 — BER padding byte, DER
        // refuses it for our purposes.
        let bytes = [0x03, 0x02, 0x04, 0xDE];
        let mut r = reader(&bytes);
        assert_eq!(r.read_bit_string().unwrap_err(), Asn1Error::UnsupportedBitString,);
    }

    #[test]
    fn read_bit_string_rejects_empty_body() {
        // BIT STRING tag with length 0 is technically legal
        // but our reader rejects it because every X.509 field
        // has at least the unused-bits byte.
        let bytes = [0x03, 0x00];
        let mut r = reader(&bytes);
        assert_eq!(r.read_bit_string().unwrap_err(), Asn1Error::InvalidValue("empty BIT STRING"),);
    }

    #[test]
    fn read_octet_string_returns_content() {
        let bytes = [0x04, 0x03, 0x01, 0x02, 0x03];
        let mut r = reader(&bytes);
        assert_eq!(r.read_octet_string().unwrap(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn read_null_accepts_empty_body_and_rejects_non_empty() {
        let mut r = reader(&[0x05, 0x00]);
        r.read_null().unwrap();

        let mut r = reader(&[0x05, 0x01, 0x00]);
        assert_eq!(
            r.read_null().unwrap_err(),
            Asn1Error::InvalidValue("NULL with non-empty value"),
        );
    }

    #[test]
    fn read_bool_accepts_der_true_and_false() {
        let mut r = reader(&[0x01, 0x01, 0xFF]);
        assert!(r.read_bool().unwrap());
        let mut r = reader(&[0x01, 0x01, 0x00]);
        assert!(!r.read_bool().unwrap());
    }

    #[test]
    fn read_bool_rejects_non_canonical_true() {
        // BER allows any non-zero; DER insists on 0xFF.
        let mut r = reader(&[0x01, 0x01, 0x01]);
        assert_eq!(r.read_bool().unwrap_err(), Asn1Error::InvalidValue("BOOLEAN non-DER value"),);
    }

    #[test]
    fn peek_tag_returns_next_byte_without_advancing() {
        let bytes = [0x02, 0x01, 0x05];
        let r = reader(&bytes);
        assert_eq!(r.peek_tag(), Some(tag::INTEGER));
    }

    #[test]
    fn peek_tag_returns_none_when_empty() {
        let r = reader(&[]);
        assert!(r.peek_tag().is_none());
    }

    #[test]
    fn skip_one_advances_past_a_whole_tlv() {
        // Skip a SEQUENCE then read the following INTEGER.
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09];
        let mut r = reader(&bytes);
        r.skip_one().unwrap();
        assert_eq!(r.read_u64().unwrap(), 9);
    }

    #[test]
    fn maybe_tagged_returns_some_on_match_and_none_on_miss() {
        // SEQUENCE followed by INTEGER.
        let bytes = [0x30, 0x00, 0x02, 0x01, 0x42];
        let mut r = reader(&bytes);
        assert!(r.maybe_tagged(tag::SEQUENCE).unwrap().is_some());
        assert!(r.maybe_tagged(tag::SEQUENCE).unwrap().is_none());
        // Cursor did not advance past the INTEGER on the None path.
        let (tag, value) = r.read_tlv().unwrap();
        assert_eq!(tag, tag::INTEGER);
        assert_eq!(value, &[0x42]);
    }

    #[test]
    fn long_form_tag_is_rejected() {
        // 0x1F in the low bits means "read more tag bytes" in
        // long form. We do not support that.
        let bytes = [0x5F, 0x01, 0x00];
        let mut r = reader(&bytes);
        assert_eq!(r.read_tlv().unwrap_err(), Asn1Error::Unsupported("long-form tag"),);
    }

    #[test]
    fn read_set_returns_child_reader() {
        // SET { INTEGER 1 }
        let bytes = [0x31, 0x03, 0x02, 0x01, 0x01];
        let mut r = reader(&bytes);
        let mut inner = r.read_set().unwrap();
        assert_eq!(inner.read_u64().unwrap(), 1);
    }

    #[test]
    fn consumed_and_remaining_slices_partition_the_input() {
        let bytes = [0x02, 0x01, 0x07, 0x02, 0x01, 0x09];
        let mut r = reader(&bytes);
        assert_eq!(r.consumed(), &[]);
        assert_eq!(r.remaining(), &bytes[..]);
        r.read_u64().unwrap();
        assert_eq!(r.consumed().len(), 3);
        assert_eq!(r.remaining().len(), 3);
    }

    #[test]
    fn context_tag_explicit_wraps_index_into_constructed_byte() {
        // [0] EXPLICIT → 0xA0; [1] EXPLICIT → 0xA1.
        assert_eq!(context_tag_explicit(0), 0xA0);
        assert_eq!(context_tag_explicit(1), 0xA1);
        assert_eq!(context_tag_explicit(7), 0xA7);
    }
}
