// Single-block IO-LZ (v1/v2) backward decoder: decompress() from
// decompress.cpp:10-45 plus memcpy_lz_match.

use std::io::{Read, Seek};

use crate::format::records::{decode_lz_match, stats_per_match};

/// Copy `out[src_off..src_off+len]` to `out[dst_off..dst_off+len]` byte-by-byte,
/// increasing address order — the forward-overlap-expander semantics of
/// memcpy_lz_match (NOT memcpy/memmove).
#[inline]
fn overlap_copy(out: &mut [u8], dst_off: usize, src_off: usize, len: usize) {
    for i in 0..len {
        let v = out[src_off + i];
        out[dst_off + i] = v;
    }
}

/// Decompress one IO-LZ block. `statraw` is the inline match list (u32 words),
/// `literals` the literal bytes, `out` the full output block buffer. `backend` is
/// the output file, used to read match data from earlier blocks.
pub fn decompress(
    round_matches: bool,
    l: u32,
    backend: &mut (impl Read + Seek),
    block_start: u64,
    statraw: &[u32],
    literals: &[u8],
    out: &mut [u8],
) -> bool {
    let statend = statraw.len();
    let mut out_pos: usize = 0;
    let mut in_pos: usize = 0;
    let mut cur: usize = 0;

    while statsize_remaining(statend, cur, round_matches) {
        let (lit_len, lz_match) =
            decode_lz_match(statraw, &mut cur, false, round_matches, l, block_start + out_pos as u64);
        let lit_len = lit_len as usize;
        let mut len = lz_match.len as usize;
        let mut src = lz_match.src;
        if lit_len > literals.len() - in_pos
            || lit_len + len > out.len() - out_pos
            || lz_match.src >= lz_match.dest
        {
            return false;
        }

        // Copy literal data.
        out[out_pos..out_pos + lit_len].copy_from_slice(&literals[in_pos..in_pos + lit_len]);
        in_pos += lit_len;
        out_pos += lit_len;

        // Copy match data from previous blocks.
        if src < block_start {
            let bytes = len.min((block_start - src) as usize);
            if bytes > 0 {
                let mut tmp = vec![0u8; bytes];
                if backend.seek(std::io::SeekFrom::Start(src)).is_err() {
                    return false;
                }
                if backend.read_exact(&mut tmp).is_err() {
                    return false;
                }
                out[out_pos..out_pos + bytes].copy_from_slice(&tmp);
                out_pos += bytes;
                src += bytes as u64;
                len -= bytes;
            }
        }

        // Copy match data from the current block (overlap expander).
        let src_off = (src - block_start) as usize;
        overlap_copy(out, out_pos, src_off, len);
        out_pos += len;
    }

    // Copy remaining literals to the block end.
    if literals.len() - in_pos != out.len() - out_pos {
        return false;
    }
    let tail = literals.len() - in_pos;
    out[out_pos..out_pos + tail].copy_from_slice(&literals[in_pos..]);
    true
}

fn statsize_remaining(statend: usize, cur: usize, round_matches: bool) -> bool {
    statend.saturating_sub(cur) >= stats_per_match(round_matches)
}