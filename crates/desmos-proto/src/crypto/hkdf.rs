//! HKDF-SHA256 wrapper built directly on `ring::hmac`.
//!
//! We sidestep `ring::hkdf` because its `Prk` type is opaque and the Noise
//! IK construction needs raw access to the chaining key. Implementing
//! RFC 5869 on top of HMAC-SHA256 is exactly the few lines below.

use ring::hmac;

use super::CryptoError;

/// Length of the PRK produced by HKDF-SHA256 (= hash output length).
pub const PRK_LEN: usize = 32;

/// HKDF-Extract. `PRK = HMAC-SHA256(salt, IKM)`. If `salt` is empty, a
/// `PRK_LEN`-long all-zero buffer is used, matching RFC 5869 §2.2.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; PRK_LEN] {
    let zero_salt = [0u8; PRK_LEN];
    let salt_bytes = if salt.is_empty() { &zero_salt[..] } else { salt };
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt_bytes);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; PRK_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Expand. Fills `out` with up to `255 * PRK_LEN` (= 8160) bytes.
/// Longer outputs return [`CryptoError::HkdfFailed`].
pub fn expand(prk: &[u8; PRK_LEN], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() > 255 * PRK_LEN {
        return Err(CryptoError::HkdfFailed);
    }
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut prev: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut counter: u8 = 1;
    while written < out.len() {
        let mut ctx = hmac::Context::with_key(&mac_key);
        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[counter]);
        let t = ctx.sign();
        let tb = t.as_ref();
        let remaining = out.len() - written;
        let take = tb.len().min(remaining);
        out[written..written + take].copy_from_slice(&tb[..take]);
        written += take;
        prev = tb.to_vec();
        counter = counter.checked_add(1).ok_or(CryptoError::HkdfFailed)?;
    }
    Ok(())
}

/// Convenience: RFC 5869 full HKDF in one call.
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let prk = extract(salt, ikm);
    expand(&prk, info, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Test Case 1 (SHA-256).
    /// IKM = 0x0b * 22, salt = 0x00..0x0c, info = 0xf0..0xf9, L = 42
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let prk = extract(&salt, &ikm);
        assert_eq!(prk, expected_prk);

        let mut okm = [0u8; 42];
        expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn derive_matches_manual_extract_expand() {
        let salt = b"salt";
        let ikm = b"input-key-material";
        let info = b"context";
        let mut via_derive = [0u8; 64];
        derive(salt, ikm, info, &mut via_derive).unwrap();

        let prk = extract(salt, ikm);
        let mut via_split = [0u8; 64];
        expand(&prk, info, &mut via_split).unwrap();

        assert_eq!(via_derive, via_split);
    }

    #[test]
    fn empty_salt_is_zero_salt() {
        let ikm = b"input";
        let a = extract(&[], ikm);
        let b = extract(&[0u8; PRK_LEN], ikm);
        assert_eq!(a, b);
    }

    #[test]
    fn expand_rejects_output_longer_than_limit() {
        let prk = [0u8; PRK_LEN];
        let mut too_long = vec![0u8; 255 * PRK_LEN + 1];
        assert_eq!(expand(&prk, b"", &mut too_long).unwrap_err(), CryptoError::HkdfFailed);
    }
}
