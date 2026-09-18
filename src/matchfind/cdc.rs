// Content-defined chunking (m1/m2). Boundary hashing uses the polynomial path
// (clang: crc32c() is always false). Chunk hashes feed a digest/index table.

use crate::checksum::VHash;
use crate::format::records::encode_lz_match;
use crate::matchfind::hash_table::{min_hash_size, roundup_to_power_of_2, MAX_HASH_CHAIN};
use crate::rolling::{PolynomialRollingHash, PRIME1};
use crate::types::NOT_FOUND;

pub const WINSIZE: usize = 48;
pub const STRIPE: usize = 116 * 1024;
pub const MINIMAL_MIN_MATCH: u64 = 16;

fn next_hash_slot(h: u64) -> u64 {
    h.wrapping_mul(123_456_791)
        .wrapping_add(h >> 16)
        .wrapping_add(462_782_923)
}

pub struct CdcHashTable {
    total_chunks: u64,
    chunknum_mask: u32,
    hash_mask: u32,
    hashsize1: u64,
    chunkarr: Vec<u32>,
    startarr: Vec<u64>,
    digestarr: Vec<[u8; 20]>,
    curchunk: u32,
    pub vhash: VHash,
}

impl CdcHashTable {
    pub fn new(l: u64, filesize: u64) -> CdcHashTable {
        let filesize = filesize.max(l);
        let mut total_chunks = filesize / l;
        total_chunks += total_chunks / if total_chunks > 1024 { 10 } else { 1 };
        let chunknum_mask = roundup_to_power_of_2(total_chunks + 2) as u32 - 1;
        let hash_mask = !chunknum_mask;
        let hs = roundup_to_power_of_2(min_hash_size(total_chunks));
        CdcHashTable {
            total_chunks,
            chunknum_mask,
            hash_mask,
            hashsize1: hs - 1,
            chunkarr: vec![0u32; hs as usize],
            startarr: vec![0u64; total_chunks as usize],
            digestarr: vec![[0u8; 20]; total_chunks as usize],
            curchunk: 0,
            vhash: VHash::new(),
        }
    }

    fn hash_index(&self, h: u64) -> usize {
        (h & self.hashsize1) as usize
    }
    fn chunkarr_value(&self, hash: u64, chunk: u32) -> u32 {
        ((hash as u32) & self.hash_mask).wrapping_add(chunk)
    }
    fn get_hash(&self, value: u32) -> u32 {
        value & self.hash_mask
    }
    fn get_chunk(&self, value: u32) -> u32 {
        value & self.chunknum_mask
    }

    /// 20-byte digest + 8-byte index for a chunk (vhash1 tag [0..16] + vhash2 tag).
    pub fn chunk_key(&self, chunk: &[u8]) -> ([u8; 20], u64) {
        let mut tag = [0u8; 16];
        self.vhash.compute(chunk, &mut tag);
        let mut digest = [0u8; 20];
        digest[0..16].copy_from_slice(&tag);
        digest[16..20].copy_from_slice(&tag[0..4]);
        let index = u64::from_le_bytes(tag[4..12].try_into().unwrap());
        (digest, index)
    }

    pub fn find_match_cdc(&mut self, offset: u64, size: u64, digest: &[u8; 20], index: u64) -> u64 {
        self.curchunk += 1;
        if self.curchunk as u64 >= self.total_chunks {
            return 0;
        }
        let cur = self.curchunk as usize;
        self.startarr[cur] = offset;
        self.digestarr[cur] = *digest;

        let saved_hash = self.chunkarr_value(index, 0);
        let mut h = index;
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
                if self.digestarr[chunk as usize] == self.digestarr[cur] {
                    found = chunk;
                    break;
                }
            }
            h = h.wrapping_add(1);
            if (limit & 3) == 0 {
                h = next_hash_slot(h);
            }
        }
        let idx = self.hash_index(h);
        let val = self.chunkarr_value(index, self.curchunk);
        self.chunkarr[idx] = val;

        if found != NOT_FOUND
            && self.startarr[found as usize + 1] - self.startarr[found as usize] == size
        {
            offset - self.startarr[found as usize]
        } else {
            0
        }
    }
}

/// m1: 3-stream rolling hash, marks sorted after.
fn fast_find_chunks_3(
    ptr: usize,
    marks: &mut Vec<usize>,
    maxhash: u64,
    min_match: u64,
    piece: usize,
    buf: &[u8],
) {
    let mut lastp1 = ptr;
    let mut lastp2 = ptr + piece;
    let mut lastp3 = ptr + 2 * piece;
    let mut h1 = PolynomialRollingHash::with_buffer(&buf[ptr..], WINSIZE, PRIME1);
    let mut h2 = PolynomialRollingHash::with_buffer(&buf[ptr + piece..], WINSIZE, PRIME1);
    let mut h3 = PolynomialRollingHash::with_buffer(&buf[ptr + 2 * piece..], WINSIZE, PRIME1);

    let mut p = ptr + WINSIZE;
    let pend = ptr + piece;
    while p < pend {
        h1.update_byte(buf[p - WINSIZE], buf[p]);
        if h1.value > maxhash && (p - lastp1) as u64 >= min_match {
            marks.push(p);
            lastp1 = p;
        }
        h2.update_byte(buf[p + piece - WINSIZE], buf[p + piece]);
        if h2.value > maxhash && (p + piece - lastp2) as u64 >= min_match {
            marks.push(p + piece);
            lastp2 = p + piece;
        }
        h3.update_byte(buf[p + 2 * piece - WINSIZE], buf[p + 2 * piece]);
        if h3.value > maxhash && (p + 2 * piece - lastp3) as u64 >= min_match {
            marks.push(p + 2 * piece);
            lastp3 = p + 2 * piece;
        }
        p += 1;
    }
}

/// m1 chunk boundaries for one stripe [ptr, pend).
fn fast_find_chunks(ptr: usize, pend: usize, buf: &[u8], bufend: usize, l: u64, min_match: u64) -> Vec<usize> {
    let maxhash = u64::MAX - u64::MAX / l;
    let mut marks = Vec::new();
    let stripe3 = STRIPE / 3 * 3;
    if pend - ptr >= stripe3 {
        let before = marks.len();
        fast_find_chunks_3(ptr, &mut marks, maxhash, min_match, STRIPE / 3, buf);
        marks[before..].sort_unstable();
    } else if pend - ptr >= WINSIZE {
        let mut lastp = ptr;
        let mut hash = PolynomialRollingHash::with_buffer(&buf[ptr..], WINSIZE, PRIME1);
        let mut p = ptr + WINSIZE;
        while p < pend {
            hash.update_byte(buf[p - WINSIZE], buf[p]);
            if hash.value > maxhash && (p - lastp) as u64 >= min_match {
                marks.push(p);
                lastp = p;
            }
            p += 1;
        }
    }
    if pend == bufend {
        marks.push(bufend);
    }
    marks
}

/// m2 chunk boundaries (zpaq order-1 model).
fn zpaq_find_chunks(ptr: usize, pend: usize, buf: &[u8], bufend: usize, l: u64, min_match: u64) -> Vec<usize> {
    let maxhash = u32::MAX - u32::MAX / l as u32;
    let mut hash: u32 = 0;
    let mut c1: u8 = 0;
    let mut o1 = [0u8; 256];
    let start = if ptr >= 8000 { ptr - 8000 } else { 0 };
    let mut p = start;
    let mut lastp = p;
    let mut marks = Vec::new();
    while p < pend {
        let c = buf[p];
        hash = (hash.wrapping_add(c as u32).wrapping_add(1))
            .wrapping_mul(if c != o1[c1 as usize] { 271_828_182 } else { 314_159_265 });
        o1[c1 as usize] = c;
        c1 = c;
        if hash > maxhash && (p - lastp) as u64 >= min_match {
            if p > ptr {
                marks.push(p);
            }
            lastp = p;
            c1 = 0;
            hash = 0;
            o1 = [0u8; 256];
        }
        p += 1;
    }
    if pend == bufend {
        marks.push(bufend);
    }
    marks
}

/// Compress one block using CDC.
pub fn compress_cdc(
    zpaq: bool,
    l: u64,
    min_match: u64,
    block_start: u64,
    h: &mut CdcHashTable,
    buf: &[u8],
) -> (u32, Vec<u32>) {
    let mut literal_bytes: u32 = 0;
    let mut stats: Vec<u32> = Vec::new();
    let min_match = min_match.max(MINIMAL_MIN_MATCH);
    let bufend = buf.len();
    let mut last_match: usize = 0;
    let mut last_chunk: usize = 0;

    let mut ptr = 0usize;
    while ptr < bufend {
        let pend = if bufend - ptr < STRIPE { bufend } else { ptr + STRIPE };
        let marks = if zpaq {
            zpaq_find_chunks(ptr, pend, buf, bufend, l, min_match)
        } else {
            fast_find_chunks(ptr, pend, buf, bufend, l, min_match)
        };
        let mut prev = last_chunk;
        for &m in &marks {
            let chunk = &buf[prev..m];
            let sz = (m - prev) as u64;
            let (digest, index) = h.chunk_key(chunk);
            let matched = h.find_match_cdc(block_start + prev as u64, sz, &digest, index);
            if matched != 0 && sz >= min_match {
                encode_lz_match(
                    &mut stats,
                    false,
                    min_match as u32,
                    (prev - last_match) as u32,
                    matched,
                    sz as u32,
                );
                last_match = m;
            } else {
                literal_bytes += sz as u32;
            }
            prev = m;
        }
        last_chunk = prev;
        ptr = pend;
    }

    (literal_bytes, stats)
}
