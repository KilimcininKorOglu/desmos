//! ChaCha20-Poly1305 wrapper. The DWP wire format uses this exact AEAD
//! for every encrypted packet; nonces are assembled deterministically
//! from the session id and the sequence number.

use ring::aead::Aad;
use ring::aead::LessSafeKey;
use ring::aead::Nonce;
use ring::aead::UnboundKey;
use ring::aead::CHACHA20_POLY1305;

use super::CryptoError;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub struct AeadKey {
    key: LessSafeKey,
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadKey(CHACHA20_POLY1305, <redacted>)")
    }
}

impl AeadKey {
    pub fn new(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        if key_bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self { key: LessSafeKey::new(unbound) })
    }

    /// Seal in place with an explicit 12-byte nonce. `buf` starts as the
    /// plaintext and is extended by `TAG_LEN` bytes on success.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::assume_unique_for_key(*nonce);
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::AeadFailed)?;
        Ok(())
    }

    /// Open in place. On success the tag is stripped and a slice pointing
    /// at the plaintext region of `buf` is returned. On failure the buffer
    /// may have been partially overwritten — the caller must treat the
    /// data as untrusted and discard the packet.
    pub fn open_in_place<'a>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        if buf.len() < TAG_LEN {
            return Err(CryptoError::InvalidCiphertextLength);
        }
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::AeadFailed)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn sample_nonce() -> [u8; NONCE_LEN] {
        [1u8; NONCE_LEN]
    }

    #[test]
    fn new_rejects_wrong_key_length() {
        assert_eq!(AeadKey::new(&[0u8; 16]).unwrap_err(), CryptoError::InvalidKeyLength);
        assert_eq!(AeadKey::new(&[0u8; 31]).unwrap_err(), CryptoError::InvalidKeyLength);
    }

    #[test]
    fn seal_then_open_returns_original_plaintext() {
        let key = AeadKey::new(&sample_key()).unwrap();
        let nonce = sample_nonce();
        let plaintext = b"hello desmos aead";
        let aad = b"session-7";

        let mut buf = plaintext.to_vec();
        key.seal_in_place(&nonce, aad, &mut buf).unwrap();
        assert_eq!(buf.len(), plaintext.len() + TAG_LEN);

        let mut ct = buf.clone();
        let pt = key.open_in_place(&nonce, aad, &mut ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let key_a = AeadKey::new(&sample_key()).unwrap();
        let mut wrong_bytes = sample_key();
        wrong_bytes[0] ^= 0xff;
        let key_b = AeadKey::new(&wrong_bytes).unwrap();

        let mut buf = b"secret payload".to_vec();
        key_a.seal_in_place(&sample_nonce(), b"aad", &mut buf).unwrap();
        let err = key_b.open_in_place(&sample_nonce(), b"aad", &mut buf).unwrap_err();
        assert_eq!(err, CryptoError::AeadFailed);
    }

    #[test]
    fn open_with_tampered_tag_fails() {
        let key = AeadKey::new(&sample_key()).unwrap();
        let mut buf = b"secret payload".to_vec();
        key.seal_in_place(&sample_nonce(), b"aad", &mut buf).unwrap();
        // Flip the last byte of the tag.
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        let err = key.open_in_place(&sample_nonce(), b"aad", &mut buf).unwrap_err();
        assert_eq!(err, CryptoError::AeadFailed);
    }

    #[test]
    fn open_with_tampered_aad_fails() {
        let key = AeadKey::new(&sample_key()).unwrap();
        let mut buf = b"secret payload".to_vec();
        key.seal_in_place(&sample_nonce(), b"correct-aad", &mut buf).unwrap();
        let err = key.open_in_place(&sample_nonce(), b"wrong-aad", &mut buf).unwrap_err();
        assert_eq!(err, CryptoError::AeadFailed);
    }

    #[test]
    fn open_rejects_short_buffer() {
        let key = AeadKey::new(&sample_key()).unwrap();
        let mut tiny = [0u8; TAG_LEN - 1];
        let err = key.open_in_place(&sample_nonce(), b"", &mut tiny).unwrap_err();
        assert_eq!(err, CryptoError::InvalidCiphertextLength);
    }
}
