// HashTable match-search engine (hash_table.cpp), the m3 (digest-compare) path.
// The bit-array accelerator is omitted: a pure no-false-negative filter, it does
// not change which matches are found, only speed.

use crate::checksum::VDigest;
use crate::types::{BigHash, Chunk, NOT_FOUND};

pub const MAX_HASH_CHAIN: i32 = 12;

#[inline]
pub fn min_hash_size(n: u64) -> u64 {
    (n / 4 + 1) * 5
}

#[inline]
pub fn roundup_to_power_of_2(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let m = n - 1;
    let lb = 63 - m.leading_zeros();
    2u64 << lb
}

#[inline]
fn first_hash_slot(index: BigHash) -> u64 {
    index
}

#[inline]
fn next_hash_slot(_index: u64, h: u64) -> u64 {
    h.wrapping_mul(123_456_791)
        .wrapping_add(h >> 16)
        .wrapping_add(462_782_923)
}

pub struct HashTable {
    pub l: u64,
    pub total_chunks: u64,
    pub chunknum_mask: u32,
    pub hash_mask: u32,
    pub hs: u64,
    pub hashsize1: u64,
    pub chunkarr: Vec<u32>,
    pub hasharr: Vec<u32>,
    pub digestarr: Vec<[u8; 20]>,
    pub digest: VDigest,
}

impl HashTable {
    pub fn new(l: u64, filesize: u64) -> HashTable {
        let filesize = filesize.max(l);
        let total_chunks = filesize / l;
        let chunknum_mask = roundup_to_power_of_2(total_chunks + 2) as u32 - 1;
        let hash_mask = !chunknum_mask;
        let hs = roundup_to_power_of_2(min_hash_size(total_chunks));
        let hashsize1 = hs - 1;

        HashTable {
            l,
            total_chunks,
            chunknum_mask,
            hash_mask,
            hs,
            hashsize1,
            chunkarr: vec![0u32; hs as usize],
            hasharr: vec![0u32; total_chunks as usize],
            digestarr: vec![[0u8; 20]; total_chunks as usize],
            digest: VDigest::new(),
        }
    }

    #[inline]
    fn hash_index(&self, h: u64) -> usize {
        (h & self.hashsize1) as usize
    }

    #[inline]
    fn chunkarr_value(&self, hash: u64, chunk: u32) -> u32 {
        ((hash as u32) & self.hash_mask).wrapping_add(chunk)
    }

    #[inline]
    fn get_hash(&self, value: u32) -> u32 {
        value & self.hash_mask
    }

    #[inline]
    fn get_chunk(&self, value: u32) -> u32 {
        value & self.chunknum_mask
    }

    #[inline]
    fn stored_hash(&self, hash2: u64) -> u32 {
        (hash2 >> 32) as u32
    }

    /// Precompute per-chunk digests (PRECOMPUTE_DIGESTS), once per block read.
    pub fn prepare_buffer(&mut self, offset: u64, buf: &[u8]) {
        let l = self.l as usize;
        let mut curchunk = (offset / self.l) as usize;
        let mut p = 0usize;
        while buf.len() - p >= l {
            self.digest.compute(&buf[p..p + l], &mut self.digestarr[curchunk]);
            curchunk += 1;
            p += l;
        }
    }

    /// Find a previous chunk with same contents as buf[i..i+L]; returns NOT_FOUND
    /// if none. Compares a freshly-computed digest against the stored one.
    pub fn find_match(&self, buf: &[u8], i: usize, hash2: u64) -> Chunk {
        let stored_value = self.stored_hash(hash2);
        let saved_hash = self.chunkarr_value(hash2, 0);
        let l = self.l as usize;
        let mut h = first_hash_slot(hash2);
        let mut limit = MAX_HASH_CHAIN;
        loop {
            let value = self.chunkarr[self.hash_index(h)];
            if value == NOT_FOUND {
                break;
            }
            limit -= 1;
            if limit == 0 {
                break;
            }
            if self.get_hash(value) == saved_hash {
                let chunk = self.get_chunk(value);
                if self.hasharr[chunk as usize] == stored_value {
                    let mut d = [0u8; 20];
                    self.digest.compute(&buf[i..i + l], &mut d);
                    if d == self.digestarr[chunk as usize] {
                        return chunk;
                    }
                }
            }
            h = h.wrapping_add(1);
            if (limit & 3) == 0 {
                h = next_hash_slot(hash2, h);
            }
        }
        NOT_FOUND
    }

    /// Add the chunk at block-absolute position `block_start+i` to the table,
    /// The equivalent previous chunk (reusing its slot when found).
    pub fn add_hash(&mut self, block_start: u64, i: usize, hash2: u64) -> Chunk {
        let stored_value = self.stored_hash(hash2);
        let curchunk = ((block_start + i as u64) / self.l) as u32;

        self.hasharr[curchunk as usize] = stored_value;
        if curchunk == NOT_FOUND {
            return NOT_FOUND;
        }

        let saved_hash = self.chunkarr_value(hash2, 0);
        let mut h = first_hash_slot(hash2);
        let mut limit = MAX_HASH_CHAIN;
        let mut found = NOT_FOUND;
        loop {
            let value = self.chunkarr[self.hash_index(h)];
            if value == NOT_FOUND {
                break;
            }
            limit -= 1;
            if limit == 0 {
                break;
            }
            if self.get_hash(value) == saved_hash {
                let chunk = self.get_chunk(value);
                if self.hasharr[chunk as usize] == stored_value {
                    // -m3: compare the two precomputed digests (same key).
                    if self.digestarr[chunk as usize] == self.digestarr[curchunk as usize] {
                        found = chunk;
                        break;
                    }
                }
            }
            h = h.wrapping_add(1);
            if (limit & 3) == 0 {
                h = next_hash_slot(hash2, h);
            }
        }
        let idx = self.hash_index(h);
        let val = self.chunkarr_value(hash2, curchunk);
        self.chunkarr[idx] = val;
        found
    }

    pub fn memreq(&self) -> u64 {
        (self.hs * 4) + (self.total_chunks * (4 + 20))
    }
}