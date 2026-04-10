//! Integration test for the crypto wrapper layer. Stresses AEAD round
//! trips with random plaintexts and verifies every documented failure
//! mode fails open.

use desmos_proto::crypto::aead::AeadKey;
use desmos_proto::crypto::aead::KEY_LEN;
use desmos_proto::crypto::aead::NONCE_LEN;
use desmos_proto::crypto::aead::TAG_LEN;
use desmos_proto::crypto::CryptoError;

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0xdead_beef_cafe_babe } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u64() as u8;
        }
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo)
    }
}

#[test]
fn seal_open_round_trip_100_random_messages() {
    let mut rng = Rng::new(0xface_feed_1234_5678);
    let mut key_bytes = [0u8; KEY_LEN];
    rng.fill(&mut key_bytes);
    let key = AeadKey::new(&key_bytes).unwrap();

    for i in 0..100 {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce);

        let payload_len = rng.range(0, 2048);
        let mut plaintext = vec![0u8; payload_len];
        rng.fill(&mut plaintext);

        let mut aad = vec![0u8; rng.range(0, 64)];
        rng.fill(&mut aad);

        let mut buf = plaintext.clone();
        key.seal_in_place(&nonce, &aad, &mut buf).unwrap();
        assert_eq!(buf.len(), payload_len + TAG_LEN, "case {i}");

        let mut to_open = buf.clone();
        let recovered = key.open_in_place(&nonce, &aad, &mut to_open).unwrap();
        assert_eq!(recovered, plaintext.as_slice(), "case {i}");
    }
}

#[test]
fn wrong_key_fails_open() {
    let key_a = AeadKey::new(&[0xAA; KEY_LEN]).unwrap();
    let key_b = AeadKey::new(&[0xBB; KEY_LEN]).unwrap();
    let nonce = [0u8; NONCE_LEN];
    let mut buf = b"sealed-by-A".to_vec();
    key_a.seal_in_place(&nonce, b"", &mut buf).unwrap();
    assert_eq!(key_b.open_in_place(&nonce, b"", &mut buf).unwrap_err(), CryptoError::AeadFailed);
}

#[test]
fn tag_tamper_fails_open() {
    let key = AeadKey::new(&[0u8; KEY_LEN]).unwrap();
    let nonce = [1u8; NONCE_LEN];
    let mut buf = b"important payload".to_vec();
    key.seal_in_place(&nonce, b"aad", &mut buf).unwrap();
    let tag_idx = buf.len() - 1;
    buf[tag_idx] ^= 0xff;
    assert_eq!(key.open_in_place(&nonce, b"aad", &mut buf).unwrap_err(), CryptoError::AeadFailed);
}

#[test]
fn ciphertext_body_tamper_fails_open() {
    let key = AeadKey::new(&[0u8; KEY_LEN]).unwrap();
    let nonce = [2u8; NONCE_LEN];
    let mut buf = b"important payload".to_vec();
    key.seal_in_place(&nonce, b"aad", &mut buf).unwrap();
    buf[0] ^= 0x01;
    assert_eq!(key.open_in_place(&nonce, b"aad", &mut buf).unwrap_err(), CryptoError::AeadFailed);
}

#[test]
fn wrong_nonce_fails_open() {
    let key = AeadKey::new(&[0u8; KEY_LEN]).unwrap();
    let nonce_a = [0u8; NONCE_LEN];
    let mut nonce_b = [0u8; NONCE_LEN];
    nonce_b[0] = 1;
    let mut buf = b"important payload".to_vec();
    key.seal_in_place(&nonce_a, b"", &mut buf).unwrap();
    assert_eq!(key.open_in_place(&nonce_b, b"", &mut buf).unwrap_err(), CryptoError::AeadFailed);
}
