// ENCODE_LZ_MATCH / DECODE_LZ_MATCH (srep.cpp:105-135) and the LZ match record
// layout. All 32-bit arithmetic here wraps exactly like the C++ unsigned math.

use crate::types::{Offset, Stat};

pub const STAT_BITS: u32 = 32;

/// Number of STAT words used to encode one LZ match.
#[inline]
pub fn stats_per_match(round_matches: bool) -> usize {
    if round_matches {
        3
    } else {
        4
    }
}

/// A decoded LZ match.
#[derive(Clone, Copy, Debug)]
pub struct LzMatch {
    pub src: Offset,
    pub dest: Offset,
    pub len: Stat,
}

/// Record-encode one LZ match into `stat` (the ENCODE_LZ_MATCH macro). The
/// caller maintains the output cursor `stat` (a `&mut [Stat]` + index).
pub fn encode_lz_match(
    out: &mut Vec<Stat>,
    round_matches: bool,
    base: u32,
    lit_len: u32,
    lz_match_offset: Offset,
    lz_match_len: u32,
) {
    let l1: u64 = if round_matches { base as u64 } else { 1 };
    let off_div = lz_match_offset / l1;
    out.push(lit_len);
    out.push(off_div as u32);
    if !round_matches {
        out.push((off_div >> STAT_BITS) as u32);
    }
    out.push(((lz_match_len - base) as u64 / l1) as u32);
}

/// Decode one LZ record from a stat cursor (the DECODE_LZ_MATCH macro).
/// `basic_pos` is the block-relative origin. Returns the match and leaves the
/// cursor advanced by STATS_PER_MATCH.
#[inline]
pub fn decode_lz_match(
    stat: &[Stat],
    cur: &mut usize,
    future_lz: bool,
    round_matches: bool,
    l: u32,
    basic_pos: Offset,
) -> (u32, LzMatch) {
    let l1: u32 = if round_matches { l } else { 1 };
    let lit_len = stat[*cur];
    *cur += 1;
    let mut lz_match_offset: Offset = stat[*cur] as Offset;
    *cur += 1;
    if !round_matches {
        lz_match_offset += (stat[*cur] as Offset) << STAT_BITS;
        *cur += 1;
    }
    lz_match_offset *= l1 as Offset;
    let len = stat[*cur].wrapping_mul(l1).wrapping_add(l);
    *cur += 1;
    if !future_lz {
        let dest = basic_pos + lit_len as Offset;
        let src = dest / l1 as Offset * l1 as Offset - lz_match_offset;
        (lit_len, LzMatch { src, dest, len })
    } else {
        let src = basic_pos + lit_len as Offset;
        let dest = src + lz_match_offset;
        (lit_len, LzMatch { src, dest, len })
    }
}

/// Byte-by-byte forward-overlap expander (memcpy_lz_match, srep.cpp:137-145).
/// NOT memcpy/memmove: overlapping copies must expand byte-at-a-time.
pub fn memcpy_lz_match(dest: &mut [u8], src_start: usize, len: usize) {
    if len == 0 {
        return;
    }
    for i in 0..len {
        let v = dest[src_start + i];
        dest[i] = v;
    }
}