//! BLAKE3 hasher wrapper. Used by the Noise transcript hash (Task 16)
//! and by the log redactor to fingerprint secrets without echoing them.

pub const HASH_LEN: usize = 32;

pub struct Blake3 {
    inner: ::blake3::Hasher,
}

impl Blake3 {
    pub fn new() -> Self {
        Self { inner: ::blake3::Hasher::new() }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    pub fn finalize(self) -> [u8; HASH_LEN] {
        let digest = self.inner.finalize();
        *digest.as_bytes()
    }

    /// One-shot convenience: `Blake3::hash(data)` returns 32 bytes.
    pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_empty_input_to_known_digest() {
        // BLAKE3 of empty input, documented in the BLAKE3 paper §2.
        let expected: [u8; 32] = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        assert_eq!(Blake3::hash(&[]), expected);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let data = b"desmos bonding vpn";
        let one_shot = Blake3::hash(data);

        let mut inc = Blake3::new();
        inc.update(&data[..5]);
        inc.update(&data[5..]);
        assert_eq!(inc.finalize(), one_shot);
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(Blake3::hash(b"alice"), Blake3::hash(b"bob"));
    }
}
