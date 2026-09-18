// HashTable match-search engine (hash_table.cpp): digest-compare (m3) and
// reread (m4/m5) paths. The bit-array accelerator is omitted — a pure
// no-false-negative filter that does not change which matches are found.

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
pub fn rounddown_to_power_of_2(n: u64) -> u64 {
    if n == 0 {
        return 1;
    }
    1u64 << (63 - n.leading_zeros())
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

/// Per-chunk slice hashes for -m5 (EXHAUSTIVE_SEARCH filter).
pub struct SliceHash {
    h: Vec<u32>,
    l: usize,
    slices_in_block: usize,
    slice_size: usize,
    check_slices: i32,
}

impl SliceHash {
    const BITS: u32 = 4;
    const ONES: u32 = (1 << Self::BITS) - 1;

    pub fn new(filesize: u64, l: usize, min_match: u64, io_accelerator: i32) -> SliceHash {
        let slices_in_block = 8usize;
        let slice_size = l / slices_in_block;
        let check_slices =
            (min_match as i64 - l as i64) / slice_size as i64 - io_accelerator as i64;
        let enabled = !(io_accelerator < 0 || check_slices <= 0);
        let h = if enabled {
            // +2: the final partial block writes one extra entry, and check()
            // reads chunk+1.
            vec![0u32; (filesize / l as u64) as usize + 2]
        } else {
            Vec::new()
        };
        SliceHash {
            h,
            l,
            slices_in_block,
            slice_size,
            check_slices: check_slices as i32,
        }
    }

    /// Hash `block[off .. off+slice_size]`, treating out-of-range bytes as zero
    /// (the reference reads the zero/uninitialized tail of an 8 MiB buffer).
    fn hash_at(&self, block: &[u8], off: usize) -> u32 {
        let mut hash: u32 = 111_222_341;
        for k in 0..self.slice_size {
            let b = block.get(off + k).copied().unwrap_or(0);
            hash = hash.wrapping_mul(123_456_791).wrapping_add(b as u32);
        }
        (hash.wrapping_mul(123_456_791)) >> (32 - Self::BITS)
    }

    pub fn prepare_buffer(&mut self, offset: u64, buf: &[u8]) {
        if self.h.is_empty() {
            return;
        }
        let mut curchunk = (offset / self.l as u64) as usize;
        let mut p = 0usize;
        while p < buf.len() {
            let mut checksum = 0u32;
            for i in 0..self.slices_in_block {
                let sh = self.hash_at(buf, p);
                checksum = checksum.wrapping_add(sh << (i as u32 * Self::BITS));
                p += self.slice_size;
            }
            self.h[curchunk] = checksum;
            curchunk += 1;
        }
    }

    fn h_entry(&self, chunk: i64) -> u32 {
        if chunk < 0 || chunk >= self.h.len() as i64 {
            0 // out-of-bounds garbage in the reference; never matches
        } else {
            self.h[chunk as usize]
        }
    }

    fn check(&self, chunk: Chunk, buf: &[u8], i: usize, block_size: usize) -> bool {
        if self.h.is_empty() {
            return true;
        }
        if i < self.l || block_size - i < 2 * self.l {
            return true;
        }
        let checksum = self.h_entry(chunk as i64 + 1);
        let mut j: i32 = 0;
        loop {
            if j == self.check_slices {
                return true;
            }
            let off = i + self.l + j as usize * self.slice_size;
            if ((checksum >> (j as u32 * Self::BITS)) & Self::ONES) != self.hash_at(buf, off) {
                break;
            }
            j += 1;
        }
        let checksum = self.h_entry(chunk as i64 - 1);
        let mut k: i32 = 0;
        loop {
            if k + j == self.check_slices {
                return true;
            }
            let sh = ((self.slices_in_block - (k as usize + 1)) as u32) * Self::BITS;
            let off = i - (k as usize + 1) * self.slice_size;
            if ((checksum >> sh) & Self::ONES) != self.hash_at(buf, off) {
                break;
            }
            k += 1;
        }
        false
    }
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
    pub compare_digests: bool,
    pub round_matches: bool,
    pub slicehash: SliceHash,
}

impl HashTable {
    pub fn new(l: u64, filesize: u64, compare_digests: bool, round_matches: bool, min_match: u64, io_accelerator: i32) -> HashTable {
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
            digestarr: if compare_digests {
                vec![[0u8; 20]; total_chunks as usize]
            } else {
                Vec::new()
            },
            digest: VDigest::new(),
            compare_digests,
            round_matches,
            slicehash: SliceHash::new(filesize, l as usize, min_match, io_accelerator),
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

    pub fn prepare_buffer(&mut self, offset: u64, buf: &[u8]) {
        if self.compare_digests {
            let l = self.l as usize;
            let mut curchunk = (offset / self.l) as usize;
            let mut p = 0usize;
            while buf.len() - p >= l {
                self.digest.compute(&buf[p..p + l], &mut self.digestarr[curchunk]);
                curchunk += 1;
                p += l;
            }
        }
        self.slicehash.prepare_buffer(offset, buf);
    }

    pub fn find_match(&self, buf: &[u8], i: usize, hash2: u64, block_size: usize) -> Chunk {
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
                    if self.compare_digests {
                        let mut d = [0u8; 20];
                        self.digest.compute(&buf[i..i + l], &mut d);
                        if d == self.digestarr[chunk as usize] {
                            return chunk;
                        }
                    } else {
                        // m4: accept directly; m5: filter via slice hashes.
                        if self.slicehash.check(chunk, buf, i, block_size) {
                            return chunk;
                        } else {
                            // speed_opt: stop searching on slice rejection.
                            return NOT_FOUND;
                        }
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

    pub fn add_hash(&mut self, block_start: u64, i: usize, hash2: u64, block_size: usize, buf: &[u8]) -> Chunk {
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
                    let ok = if self.compare_digests {
                        self.digestarr[chunk as usize] == self.digestarr[curchunk as usize]
                    } else {
                        self.slicehash.check(chunk, buf, i, block_size)
                    };
                    if ok {
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