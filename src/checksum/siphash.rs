// SipHash-2-4 (id 5). The reference computes it with the bundled `siphash.c`,
// which is the standard SipHash-2-4 with 16-byte key and 64-bit (little-endian)
// output. `siphasher::sip::SipHasher24` reproduces it; parity is asserted by a
// differential vector against bin/srep (see scripts/verify-parity.sh).

use std::hash::Hasher;

pub const SIPHASH_TAG_LEN_BYTES: usize = 8;
pub const SIPHASH_KEY_LEN_BYTES: usize = 16;

#[derive(Clone)]
pub struct SipHash {
    key: [u8; 16],
}

impl SipHash {
    pub fn new_with_key(key: &[u8; 16]) -> SipHash {
        SipHash { key: *key }
    }

    pub fn compute(&self, data: &[u8]) -> u64 {
        let mut h = siphasher::sip::SipHasher24::new_with_key(&self.key);
        h.write(data);
        h.finish()
    }

    /// Write the 8-byte little-endian tag to `result[0..8]`.
    pub fn compute_into(&self, data: &[u8], result: &mut [u8]) {
        result[0..8].copy_from_slice(&self.compute(data).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_known_vector() {
        // Canonical SipHash-2-4 test vector: key 00..0f, empty message.
        let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let h = SipHash::new_with_key(&key);
        let v = h.compute(b"");
        assert_eq!(v, 0x726fdb47dd0e0e31);
    }
}