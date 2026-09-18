// Single-block compressor for -m3 (digest-compare, fixed-size chunks), the
// ACCELERATOR=0 sequential loop. Produces the identical match set to the
// reference (bit-array/lookahead only skip provably-absent hashes).

use crate::format::records::encode_lz_match;
use crate::matchfind::hash_table::HashTable;
use crate::rolling::{PolynomialRollingHash, PRIME1};
use crate::types::{Chunk, NOT_FOUND};

/// Match length from a confirmed L-byte chunk match at `start_chunk` (absolute
/// source chunk) / `i` (block-relative target). Reproduces `match_len()` for the
/// digest-compare path.
fn match_len(
    h: &HashTable,
    start_chunk: Chunk,
    start_pos: usize, // block-relative i
    block_size: usize,
    block_start: u64,
    history: &[u8],
) -> u64 {
    let l = h.l as usize;
    let mut old_offset = start_chunk as u64 * h.l;
    let mut p = start_pos; // block-relative

    // Digest-based extension across chunk boundaries (old data before this block).
    loop {
        p += l;
        old_offset += h.l;
        if old_offset >= block_start {
            break;
        }
        if block_size - p < l {
            break;
        }
        let mut d = [0u8; 20];
        let abs = block_start + p as u64;
        h.digest.compute(&history[abs as usize..abs as usize + l], &mut d);
        if d != h.digestarr[(old_offset / h.l) as usize] {
            break;
        }
    }

    // Byte-compare with the data in the current block (and, when the source
    // briefly precedes the block start, the immediately-preceding data).
    let p0 = p;
    let src_rel = old_offset as i128 - block_start as i128; // absolute source offset
    // Source byte advances alongside target; both are absolute positions.
    let block_start_usize = block_start as usize;
    loop {
        if p >= block_size {
            break;
        }
        let target = history[block_start_usize + p];
        let src_abs = src_rel + (p as i128 - p0 as i128);
        if src_abs < 0 || src_abs as usize >= history.len() {
            break; // reference reads out-of-bounds here; terminate conservatively
        }
        if target != history[src_abs as usize] {
            break;
        }
        p += 1;
    }
    (p - start_pos) as u64
}

#[allow(clippy::too_many_arguments)]
fn record_match(
    h: &HashTable,
    round_matches: bool,
    l: u64,
    min_match: u64,
    base_len: u64,
    block_start: u64,
    history: &[u8],
    block_size: usize,
    stats: &mut Vec<u32>,
    last_match_end: usize,
    literal_bytes: &mut u32,
    i: usize,
    k: Chunk,
) -> Option<usize> {
    let match_len = match_len(h, k, i, block_size, block_start, history);
    if match_len >= min_match {
        let match_start = i; // add_len == 0 for m3
        let mut match_len = match_len;
        if round_matches {
            match_len = match_len / l * l;
        }
        let match_offset = block_start + i as u64 - k as u64 * l;
        encode_lz_match(
            stats,
            round_matches,
            base_len as u32,
            (match_start - last_match_end) as u32,
            match_offset,
            match_len as u32,
        );
        let match_end = match_start + match_len as usize;
        *literal_bytes -= match_len as u32;
        Some(match_end)
    } else {
        None
    }
}

/// Compress one block into `stats` (match list). `buf` is `history[block_start..]`.
pub fn compress_block(
    h: &mut HashTable,
    round_matches: bool,
    l: u64,
    min_match: u64,
    base_len: u64,
    block_start: u64,
    history: &[u8],
    block_size: usize,
) -> (u32, Vec<u32>) {
    let mut literal_bytes = block_size as u32;
    let mut stats: Vec<u32> = Vec::new();
    let mut last_match_end: usize = 0;

    if 2 * l as usize > block_size {
        return (literal_bytes, stats);
    }

    let mut hash1 = PolynomialRollingHash::new(l as usize, PRIME1);

    // Fence position (no input matches for pure m3): match_start = block_size+1,
    // so the "process input match" branch never fires.
    let mut i: usize = 0;

    // Special handling for the first L bytes.
    hash1.moveto(&history[block_start as usize..]);
    // check_match(0, hash2 == hash1)
    let k = {
        let hv = hash1.value;
        h.find_match(&history[block_start as usize..], 0, hv)
    };
    if k != NOT_FOUND {
        if let Some(mend) = record_match(
            h,
            round_matches,
            l,
            min_match,
            base_len,
            block_start,
            history,
            block_size,
            &mut stats,
            last_match_end,
            &mut literal_bytes,
            0,
            k,
        ) {
            last_match_end = mend;
        }
    }
    h.add_hash(block_start, 0, hash1.value);

    let l_usize = l as usize;
    // Main cycle, processing one L-byte chunk per outer iteration.
    while i <= block_size - 2 * l_usize {
        let next_chunk = i + l_usize;
        while i < next_chunk {
            // Fast-forward the hash across the matched region.
            let x: usize = 4;
            let y = if last_match_end > 0 { last_match_end - 1 } else { 0 };
            let next_i = (next_chunk - 1).min(y);
            if next_i >= i + l_usize / 2 {
                i = next_i & !(x - 1);
                hash1.moveto(&history[block_start as usize + i..]);
            } else {
                while i + x <= next_i {
                    let off = block_start as usize + i; // block-rel prefix
                    let window = &history[off..];
                    hash1.update_n::<4>(window);
                    i += x;
                }
            }

            let lookahead: usize = 128;
            let last_i = next_chunk.min(i + lookahead);
            // Collect candidats (positions in [last_match_end, block_end)).
            let mut candidates: Vec<(u64, usize)> = Vec::new();
            while i < last_i {
                let mut j = 0;
                while j < 4 && i < last_i {
                    hash1.update_byte(
                        history[block_start as usize + i],
                        history[block_start as usize + i + l_usize],
                    );
                    let cand_i = i + 1;
                    if cand_i >= last_match_end {
                        candidates.push((hash1.value, cand_i));
                    }
                    i += 1;
                    j += 1;
                }
            }
            // Check candidates.
            for (hv, cand_i) in candidates {
                let k = h.find_match(&history[block_start as usize..], cand_i, hv);
                if k != NOT_FOUND {
                    if let Some(mend) = record_match(
                        h,
                        round_matches,
                        l,
                        min_match,
                        base_len,
                        block_start,
                        history,
                        block_size,
                        &mut stats,
                        last_match_end,
                        &mut literal_bytes,
                        cand_i,
                        k,
                    ) {
                        last_match_end = mend;
                        break;
                    }
                }
            }
        }
        h.add_hash(block_start, i, hash1.value);
    }

    (literal_bytes, stats)
}