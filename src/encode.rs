// Single-block compressor for -m3/-m4/-m5 (fixed-size chunk matching), the
// ACCELERATOR=0 sequential loop.

use crate::format::records::{decode_lz_match, encode_lz_match};
use crate::matchfind::hash_table::HashTable;
use crate::rolling::{PolynomialRollingHash, PRIME1};
use crate::types::{Chunk, NOT_FOUND};

/// Match length from a confirmed L-byte chunk match at `start_chunk` (absolute
/// source chunk) / `start_pos` (block-relative target). `min_pos` is
/// last_match_end (block-relative). Returns (match_len, add_len).
#[allow(clippy::too_many_arguments)]
fn match_len(
    h: &HashTable,
    compare_digests: bool,
    round_matches: bool,
    start_chunk: Chunk,
    start_pos: usize,
    min_pos: usize,
    block_size: usize,
    block_start: u64,
    history: &[u8],
) -> (u64, u32) {
    let l = h.l as usize;
    let mut old_offset = start_chunk as u64 * h.l; // absolute source
    let mut p = start_pos;
    let mut add_len: u32 = 0;
    let bs = block_start as usize;

    if compare_digests {
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
            h.digest.compute(&history[bs + p..bs + p + l], &mut d);
            if d != h.digestarr[(old_offset / h.l) as usize] {
                break;
            }
        }
    } else if old_offset < block_start {
        // Source in a previous block: reread old data.
        let t = (start_pos - min_pos).min(l);
        let n = (old_offset as usize).min(t);
        if n > 0 && !round_matches {
            let mut i = 1usize;
            while i <= n && history[bs + start_pos - i] == history[old_offset as usize - i] {
                i += 1;
            }
            add_len = (i - 1) as u32;
        }
        const BUFSIZE: usize = 4096;
        loop {
            if old_offset >= block_start {
                break;
            }
            if old_offset as usize + BUFSIZE > history.len() {
                break; // short read -> stop
            }
            let old = &history[old_offset as usize..old_offset as usize + BUFSIZE];
            let mut q = 0usize;
            let mut full = true;
            while q < BUFSIZE {
                if p >= block_size || history[bs + p] != old[q] {
                    full = false;
                    break;
                }
                p += 1;
                q += 1;
            }
            if !full {
                break; // mismatch or block end
            }
            old_offset += BUFSIZE as u64;
        }
    } else if !round_matches {
        // Source within current block: backward extension.
        let t = (start_pos - min_pos).min(l);
        let n = ((old_offset - block_start) as usize).min(t);
        let mut i = 1usize;
        while i <= n
            && history[bs + start_pos - i] == history[bs + (old_offset as usize - bs) - i]
        {
            i += 1;
        }
        add_len = (i - 1) as u32;
    }

    // Byte-compare with data in the current block (and, when the source briefly
    // precedes block start, immediately-preceding data).
    let p0 = p;
    loop {
        if p >= block_size {
            break;
        }
        let target = history[bs + p];
        let src_abs = old_offset + (p as u64 - p0 as u64);
        if src_abs >= history.len() as u64 {
            break;
        }
        if target != history[src_abs as usize] {
            break;
        }
        p += 1;
    }

    ((p - start_pos) as u64, add_len)
}

#[allow(clippy::too_many_arguments)]
fn record_match(
    h: &HashTable,
    round_matches: bool,
    compare_digests: bool,
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
    let (match_len, add_len) = match_len(
        h,
        compare_digests,
        round_matches,
        k,
        i,
        last_match_end,
        block_size,
        block_start,
        history,
    );
    if match_len + add_len as u64 >= min_match {
        let match_start = i - add_len as usize;
        let mut match_len = match_len + add_len as u64;
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

/// Compress one block into a match list. `history` is the full input up to and
/// including this block; `block_start` points at this block within `history`.
#[allow(clippy::too_many_arguments)]
pub fn compress_block(
    h: &mut HashTable,
    round_matches: bool,
    l: u64,
    min_match: u64,
    base_len: u64,
    block_start: u64,
    in_stats: &[u32],
    history: &[u8],
    block_size: usize,
) -> (u32, Vec<u32>) {
    let compare_digests = h.compare_digests;
    let mut literal_bytes = block_size as u32;
    let mut stats: Vec<u32> = Vec::new();
    let mut last_match_end: usize = 0;

    // Decode the first input match (REP stream + terminating fence).
    let mut in_cur = 0usize;
    let (mut match_start, mut match_len, mut match_offset) = {
        let (_, m) = decode_lz_match(in_stats, &mut in_cur, false, round_matches, base_len as u32, block_start);
        (m.dest - block_start, m.len, m.dest - m.src)
    };

    if 2 * l as usize > block_size {
        return (literal_bytes, stats);
    }

    let mut hash1 = PolynomialRollingHash::new(l as usize, PRIME1);
    let bs = block_start as usize;

    // Special handling for the first L bytes.
    hash1.moveto(&history[bs..]);
    let k = h.find_match(&history[bs..], 0, hash1.value, block_size);
    if k != NOT_FOUND
        && let Some(mend) = record_match(
            h, round_matches, compare_digests, l, min_match, base_len, block_start, history,
            block_size, &mut stats, last_match_end, &mut literal_bytes, 0, k,
        )
    {
        last_match_end = mend;
    }
    h.add_hash(block_start, 0, hash1.value, block_size, &history[bs..]);

    let l_usize = l as usize;
    let mut i: usize = 0;
    while i <= block_size - 2 * l_usize {
        let next_chunk = i + l_usize;
        while i < next_chunk {
            // Merge an input match (REP) once the hash scan reaches its start.
            if i >= match_start as usize {
                let ms = match_start as usize;
                let mlen_orig = match_len as usize;
                if ms + mlen_orig >= base_len as usize + last_match_end {
                    let start = ms.max(last_match_end);
                    let mlen = mlen_orig - (start - ms);
                    let lit_len = start - last_match_end;
                    encode_lz_match(
                        &mut stats,
                        round_matches,
                        base_len as u32,
                        lit_len as u32,
                        match_offset,
                        mlen as u32,
                    );
                    last_match_end = start + mlen;
                    literal_bytes -= mlen as u32;
                }
                let (_, m2) = decode_lz_match(
                    in_stats,
                    &mut in_cur,
                    false,
                    round_matches,
                    base_len as u32,
                    block_start + match_start + match_len as u64,
                );
                match_start = m2.dest - block_start;
                match_len = m2.len;
                match_offset = m2.dest - m2.src;
            }

            let x: usize = 4;
            let y = if last_match_end > 0 { last_match_end - 1 } else { 0 };
            let next_i = (next_chunk - 1).min(y);
            if next_i >= i + l_usize / 2 {
                i = next_i & !(x - 1);
                hash1.moveto(&history[bs + i..]);
            } else {
                while i + x <= next_i {
                    hash1.update_n::<4>(&history[bs + i..]);
                    i += x;
                }
            }

            let lookahead: usize = 128;
            let last_i = next_chunk.min(i + lookahead);
            let mut candidates: Vec<(u64, usize)> = Vec::new();
            while i < last_i {
                let mut j = 0;
                while j < 4 && i < last_i {
                    hash1.update_byte(history[bs + i], history[bs + i + l_usize]);
                    let cand_i = i + 1;
                    if cand_i >= last_match_end {
                        candidates.push((hash1.value, cand_i));
                    }
                    i += 1;
                    j += 1;
                }
            }
            for (hv, cand_i) in candidates {
                let k = h.find_match(&history[bs..], cand_i, hv, block_size);
                if k != NOT_FOUND
                    && let Some(mend) = record_match(
                        h, round_matches, compare_digests, l, min_match, base_len, block_start, history, block_size,
                        &mut stats, last_match_end, &mut literal_bytes, cand_i, k,
                    )
                {
                    last_match_end = mend;
                    break;
                }
            }
        }
        h.add_hash(block_start, i, hash1.value, block_size, &history[bs..]);
    }

    (literal_bytes, stats)
}