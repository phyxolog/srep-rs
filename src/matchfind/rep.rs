// In-memory REP compressor (-m0): DictionaryCompressor (compress_inmem.cpp).

use crate::format::records::encode_lz_match;
use crate::matchfind::hash_table::{min_hash_size, roundup_to_power_of_2};
use crate::rolling::{PolynomialRollingHash, PRIME1};

const INMEM_PREFETCH: usize = 100;

pub struct DictionaryCompressor {
    pub max_dist: usize,
    pub l: usize,
    pub min_match: usize,
    pub base_len: u32,
    pub hashmask: usize,
    pub hasharr: Vec<u64>,
}

impl DictionaryCompressor {
    pub fn new(dictsize: usize, hashsize_opt: usize, min_match: usize, l: usize, base_len: u32) -> DictionaryCompressor {
        let hashsize = roundup_to_power_of_2(if hashsize_opt != 0 {
            hashsize_opt as u64
        } else {
            min_hash_size((8 * (dictsize / l)) as u64)
        }) as usize;
        let hashmask = hashsize / 8 - 1;
        DictionaryCompressor {
            max_dist: dictsize,
            l,
            min_match,
            base_len,
            hashmask,
            hasharr: vec![0u64; hashsize / 8],
        }
    }

    pub fn prepare_buffer(&self, hashptr: &mut Vec<u64>, buf: &[u8]) {
        if self.max_dist == 0 {
            return;
        }
        let l = self.l;
        let num_blocks = buf.len() / l;
        if num_blocks > 1 {
            let mut hash = PolynomialRollingHash::with_buffer(buf, l, PRIME1);
            let mut ptr = 0usize;
            for _block in 1..num_blocks {
                let mut maxhash = hash.value;
                let mut maxi: usize = 0;
                for i in 0..l {
                    if hash.value > maxhash {
                        maxhash = hash.value;
                        maxi = i;
                    }
                    hash.update_byte(buf[ptr], buf[ptr + l]);
                    ptr += 1;
                }
                hashptr.push(maxhash & self.hashmask as u64);
                hashptr.push(maxi as u64);
            }
            for _ in 0..INMEM_PREFETCH * 2 {
                hashptr.push(0);
            }
        }
    }

    /// Compress one block. `ring` is the circular dict buffer (len `ring_len`);
    /// `bufstart` is this block's offset within `ring`.
    pub fn compress(
        &mut self,
        ring: &[u8],
        ring_len: usize,
        bufstart: usize,
        buf: &[u8],
        hashptr: &[u64],
    ) -> (u32, Vec<u32>) {
        let mut literal_bytes = buf.len() as u32;
        let mut stats: Vec<u32> = Vec::new();
        if self.max_dist == 0 {
            return (literal_bytes, stats);
        }
        let bufend = bufstart + buf.len();
        let mut last_match_end = bufstart;
        let data_start = (bufstart + ring_len - self.max_dist) % ring_len;

        let mut hp = 0usize;
        let mut last_i = bufstart;
        while last_i + 2 * self.l <= bufend {
            let hash = hashptr[hp] as usize;
            hp += 1;
            let i = last_i + hashptr[hp] as usize;
            hp += 1;

            if i >= last_match_end {
                let m = self.hasharr[hash] as usize;
                if m != 0 {
                    let match_distance = if m < i {
                        i - m
                    } else {
                        ring_len - m + i
                    };
                    if match_distance > self.max_dist {
                        // no_match
                    } else {
                        let low_bound = if m >= data_start {
                            i.saturating_sub(m - data_start)
                        } else {
                            i - m
                        };
                        let high_bound = if m < i { ring_len } else { ring_len - m + i };
                        let start = find_match_start(
                            ring,
                            m,
                            i,
                            last_match_end.max(low_bound),
                        );
                        let end = find_match_end(ring, m, i, bufend.min(high_bound));
                        let match_len = end - start;
                        let lit_len = start - last_match_end;
                        if match_len >= self.min_match {
                            encode_lz_match(
                                &mut stats,
                                false,
                                self.base_len,
                                lit_len as u32,
                                match_distance as u64,
                                match_len as u32,
                            );
                            literal_bytes -= match_len as u32;
                            last_match_end = end;
                        }
                    }
                }
            }
            // no_match:
            self.hasharr[hash] = i as u64;
            last_i += self.l;
        }
        (literal_bytes, stats)
    }
}

/// Backward byte compare (find_match_start).
#[inline]
fn find_match_start(ring: &[u8], mut p: usize, mut q: usize, start: usize) -> usize {
    while q > start {
        p -= 1;
        q -= 1;
        if ring[p] != ring[q] {
            return q + 1;
        }
    }
    q
}

/// Forward byte compare (find_match_end).
#[inline]
fn find_match_end(ring: &[u8], mut p: usize, mut q: usize, end: usize) -> usize {
    while q < end && ring[p] == ring[q] {
        p += 1;
        q += 1;
    }
    q
}