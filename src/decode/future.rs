// Single-block Future-LZ (v3/v4) decoder: decompress_FUTURE_LZ
// (decompress.cpp:285-363).

use std::io::{Read, Seek, SeekFrom};

use crate::format::records::decode_lz_match;
use crate::decode::storage::{HeapEntry, LzMatchHeap, MemoryManager, VirtualMemoryManager, INVALID_INDEX};

/// Forward-overlap byte expander (increasing address order).
#[inline]
fn overlap_copy(out: &mut [u8], dst_off: usize, src_off: usize, len: usize) {
    for i in 0..len {
        let v = out[src_off + i];
        out[dst_off + i] = v;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn decompress_future_lz(
    round_matches: bool,
    l: u32,
    fout: &mut (impl Read + Seek),
    block_start: u64,
    statraw: &[u32],
    literals: &[u8],
    out: &mut [u8],
    mm: &mut MemoryManager,
    vm: &mut VirtualMemoryManager,
    heap: &mut LzMatchHeap,
    maximum_save: u32,
) -> Result<bool, String> {
    let block_end = block_start + out.len() as u64;
    let mut in_pos: usize = 0;

    // 1. Insert matches whose dest lies in the current block.
    {
        let mut block_pos = block_start;
        let mut cur = 0usize;
        while statraw.len().saturating_sub(cur) >= crate::format::records::stats_per_match(round_matches)
        {
            let (_lit_len, lz) =
                decode_lz_match(statraw, &mut cur, true, round_matches, l, block_pos);
            if lz.src < block_pos
                || lz.src >= block_end
                || lz.len as u64 > block_end - lz.src
                || lz.dest <= lz.src
            {
                return Ok(false);
            }
            if lz.dest < block_end {
                heap.insert(HeapEntry {
                    src: lz.src,
                    dest: lz.dest,
                    len: lz.len,
                    index: INVALID_INDEX,
                    seq: 0,
                });
            }
            block_pos = lz.src;
        }
    }

    // 2. Process matches with dest < block_end, in destination order.
    let mut out_pos: usize = 0;
    loop {
        let first = match heap.begin() {
            Some(e) => *e,
            None => break,
        };
        if first.dest >= block_end {
            break;
        }
        let e = first;
        if e.is_marking_point() {
            vm.restore_from_disk(mm, heap, &e)?;
        } else {
            let lit_len = (e.dest - block_start) - out_pos as u64;
            if e.dest < block_start + out_pos as u64
                || lit_len > (literals.len() - in_pos) as u64
                || lit_len + e.len as u64 > (out.len() - out_pos) as u64
            {
                return Ok(false);
            }
            let lit_len = lit_len as usize;
            out[out_pos..out_pos + lit_len].copy_from_slice(&literals[in_pos..in_pos + lit_len]);
            in_pos += lit_len;
            out_pos += lit_len;

            // Copy match data.
            if e.len >= maximum_save && e.src < block_start {
                let mut tmp = vec![0u8; e.len as usize];
                fout.seek(SeekFrom::Start(e.src)).map_err(|x| x.to_string())?;
                fout.read_exact(&mut tmp).map_err(|x| x.to_string())?;
                out[out_pos..out_pos + e.len as usize].copy_from_slice(&tmp);
            } else if e.index != INVALID_INDEX {
                mm.restore(e.index, &mut out[out_pos..], e.len as usize);
            } else {
                let src_off = (e.src - block_start) as usize;
                overlap_copy(out, out_pos, src_off, e.len as usize);
            }
            out_pos += e.len as usize;
            if e.index != INVALID_INDEX {
                mm.free(e.index);
            }
        }
        heap.remove(&e);
    }

    // Copy remaining literals to the block end.
    if literals.len() - in_pos != out.len() - out_pos {
        return Ok(false);
    }
    let tail = literals.len() - in_pos;
    out[out_pos..out_pos + tail].copy_from_slice(&literals[in_pos..]);

    // 3. Insert matches with dest in future blocks.
    {
        let mut block_pos = block_start;
        let mut cur = 0usize;
        while statraw.len().saturating_sub(cur) >= crate::format::records::stats_per_match(round_matches)
        {
            let (_lit_len, lz) =
                decode_lz_match(statraw, &mut cur, true, round_matches, l, block_pos);
            if lz.dest >= block_end {
                if lz.len >= maximum_save {
                    // No saved data; on demand it is reread from fout.
                } else {
                    while lz.len as u64 > mm.available_space() {
                        vm.save_to_disk(mm, heap)?;
                    }
                    let src_off = (lz.src - block_start) as usize;
                    let idx = mm.save(&out[src_off..src_off + lz.len as usize], lz.len as usize);
                    heap.insert(HeapEntry {
                        src: lz.src,
                        dest: lz.dest,
                        len: lz.len,
                        index: idx,
                        seq: 0,
                    });
                    block_pos = lz.src;
                    continue;
                }
                heap.insert(HeapEntry {
                    src: lz.src,
                    dest: lz.dest,
                    len: lz.len,
                    index: INVALID_INDEX,
                    seq: 0,
                });
            }
            block_pos = lz.src;
        }
    }

    Ok(true)
}