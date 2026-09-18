// Compression driver: pass 1 (match discovery) + pass 2 (source-ordered
// future/index re-encode) + archive/footer writing.

use crate::checksum::{hash_by_num, BlockChecksum};
use crate::encode::compress_block;
use crate::format::footer::INDEX_LZ_FOOTER_SIZE;
use crate::format::header::write_header;
use crate::format::records::{decode_lz_match, encode_lz_match, stats_per_match};
use crate::matchfind::hash_table::HashTable;
use crate::types::{Offset, Stat, SREP_FORMAT_VERSION1, SREP_FORMAT_VERSION2, SREP_FORMAT_VERSION3, SREP_FORMAT_VERSION4};

#[derive(Clone, Copy)]
pub enum Layout {
    IndexLz,
    FutureLz,
    IoLz,
}

pub struct CompressOptions {
    pub method: i8,
    pub l: u64,
    pub min_match: u64,
    pub dict_min_match: u64,
    pub bufsize: u64,
    pub layout: Layout,
    pub hash_num: u32,
    pub checksum_seed: Option<Vec<u8>>,
    pub dictsize: u64,
    pub dict_hashsize: u64,
    pub dict_chunk: u64,
}

#[inline]
fn round_up_to(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        (a + b - 1) / b * b
    }
}

#[derive(Clone, Copy)]
struct LzMatch {
    src: Offset,
    dest: Offset,
    len: u32,
}

struct PendingBlock {
    start: usize,
    size: usize,
    stats: Vec<Stat>,
    literal_bytes: usize,
}

pub fn compress(input: &[u8], opts: &CompressOptions) -> Result<Vec<u8>, String> {
    let filesize = input.len() as u64;
    let mut l = opts.l;
    let mut min_match = opts.min_match;
    let dict_min_match = opts.dict_min_match;
    let cdc = matches!(opts.method, 1 | 2);
    if l == 0 && min_match == 0 {
        min_match = if cdc { 4096 } else { 512 };
    }
    if l == 0 {
        if cdc {
            l = min_match;
            min_match = 0;
        } else if opts.method == 5 {
            // m5 performs exhaustive search: L is half the rounded power-of-two.
            l = crate::matchfind::hash_table::rounddown_to_power_of_2(min_match + 1) / 2;
        } else {
            l = min_match;
        }
    }
    if min_match == 0 {
        min_match = if cdc { 32 } else { l };
    }
    let base_len = min_match.min(dict_min_match);
    // ROUND_MATCHES requires method 3 AND no dictionary (dictsize unset).
    let round_matches = opts.method == 3 && opts.dictsize == 0;
    let compare_digests = opts.method <= 3;
    let io_lz = matches!(opts.layout, Layout::IoLz);
    let future_lz = matches!(opts.layout, Layout::FutureLz);
    let index_lz = matches!(opts.layout, Layout::IndexLz);
    let futurelz_base_len: u64 = if io_lz { base_len } else { 0 };

    let desc = hash_by_num(opts.hash_num).ok_or("bad hash num")?;
    let seed: Vec<u8> = match &opts.checksum_seed {
        Some(s) => s.clone(),
        None => {
            let mut s = vec![0u8; desc.hash_seed_size];
            if desc.hash_seed_size > 0 {
                let _ = getrandom::getrandom(&mut s);
            }
            s
        }
    };
    let checksum = if desc.hash_num == 1 {
        None
    } else {
        Some(BlockChecksum::new(desc, &seed))
    };

    let mut hash = HashTable::new(l, filesize, compare_digests, round_matches, min_match, 1);
    let mut cdc_table = if cdc {
        Some(crate::matchfind::cdc::CdcHashTable::new(l, filesize))
    } else {
        None
    };

    // REP (-m0) state.
    let dictsize = if opts.dictsize != 0 { opts.dictsize as usize } else { 512 * 1024 * 1024 };
    let dict_min_match_v = if opts.dict_min_match != 0 { opts.dict_min_match as usize } else { 512 };
    let dict_chunk = if opts.dict_chunk != 0 { opts.dict_chunk as usize } else { dict_min_match_v / 8 };
    let mut dict = crate::matchfind::rep::DictionaryCompressor::new(
        dictsize,
        opts.dict_hashsize as usize,
        dict_min_match_v,
        dict_chunk,
        base_len as u32,
    );
    let has_dict = opts.method == 0 || opts.dictsize != 0;
    let ring_len = round_up_to(dictsize, opts.bufsize as usize) + 2 * opts.bufsize as usize;
    let mut ring: Vec<u8> = if has_dict { vec![0u8; ring_len] } else { Vec::new() };

    // ---- Pass 1 ----
    let bufsize = opts.bufsize as usize;
    let mut blocks: Vec<PendingBlock> = Vec::new();
    let mut block_start: usize = 0;
    while block_start < input.len() {
        let end = (block_start + bufsize).min(input.len());
        let (literal_bytes, stats) = if opts.method == 0 {
            let bufstart = (block_start) % ring_len;
            ring[bufstart..bufstart + (end - block_start)]
                .copy_from_slice(&input[block_start..end]);
            let mut hashptr: Vec<u64> = Vec::new();
            dict.prepare_buffer(&mut hashptr, &input[block_start..end]);
            dict.compress(&ring, ring_len, bufstart, &input[block_start..end], &hashptr)
        } else if cdc {
            let t = cdc_table.as_mut().unwrap();
            crate::matchfind::cdc::compress_cdc(
                opts.method == 2,
                l,
                min_match,
                block_start as u64,
                t,
                &input[block_start..end],
            )
        } else {
            hash.prepare_buffer(block_start as u64, &input[block_start..end]);
            // Build the input-match stream: REP matches (if -d) + terminating fence.
            let mut in_stats: Vec<u32> = Vec::new();
            if opts.dictsize != 0 {
                let bufstart = (block_start) % ring_len;
                ring[bufstart..bufstart + (end - block_start)]
                    .copy_from_slice(&input[block_start..end]);
                let mut hashptr: Vec<u64> = Vec::new();
                dict.prepare_buffer(&mut hashptr, &input[block_start..end]);
                let (_lit, rep) = dict.compress(&ring, ring_len, bufstart, &input[block_start..end], &hashptr);
                in_stats.extend_from_slice(&rep);
            }
            // Fence (beyond end-of-block sentinel).
            encode_lz_match(
                &mut in_stats,
                round_matches,
                base_len as u32,
                (end - block_start + 1) as u32,
                base_len as u64,
                base_len as u32,
            );
            compress_block(
                &mut hash,
                round_matches,
                l,
                min_match,
                base_len,
                block_start as u64,
                &in_stats,
                input,
                end - block_start,
            )
        };
        blocks.push(PendingBlock {
            start: block_start,
            size: end - block_start,
            stats,
            literal_bytes: literal_bytes as usize,
        });
        block_start = end;
    }

    // ---- Archive header ----
    let version = if index_lz {
        SREP_FORMAT_VERSION4
    } else if future_lz {
        SREP_FORMAT_VERSION3
    } else if round_matches {
        SREP_FORMAT_VERSION1
    } else {
        SREP_FORMAT_VERSION2
    };
    let mut out: Vec<u8> = Vec::new();
    for w in write_header(version, desc.hash_num, desc.hash_seed_size, desc.hash_size, futurelz_base_len as u32) {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&seed);

    // ---- Output pass-1 blocks (index-lz & io-lz write now; future-lz defers) ----
    match opts.layout {
        Layout::IoLz => {
            for b in &blocks {
                let block = &input[b.start..b.start + b.size];
                let lit = extract_literals(block, &b.stats, round_matches, base_len);
                write_block_header(&mut out, b.literal_bytes as u32, b.size as u32, (b.stats.len() * 4) as u32, desc.hash_size, checksum.as_ref(), block);
                for s in &b.stats {
                    out.extend_from_slice(&s.to_le_bytes());
                }
                out.extend_from_slice(&lit);
            }
        }
        Layout::IndexLz => {
            for b in &blocks {
                let block = &input[b.start..b.start + b.size];
                let lit = extract_literals(block, &b.stats, round_matches, base_len);
                write_block_header(&mut out, b.literal_bytes as u32, b.size as u32, 0, desc.hash_size, checksum.as_ref(), block);
                out.extend_from_slice(&lit);
            }
        }
        Layout::FutureLz => {}
    }

    // ---- Pass 2: source-ordered re-encode (future-lz / index-lz) ----
    if future_lz || index_lz {
        // Decode pass-1 match lists into (src,dest,len), sorted by source.
        let mut m: Vec<LzMatch> = Vec::new();
        for b in &blocks {
            let mut block_pos = b.start as u64;
            let mut cur = 0usize;
            while b.stats.len() - cur >= stats_per_match(round_matches) {
                let (lit, mm) = decode_lz_match(&b.stats, &mut cur, false, round_matches, base_len as u32, block_pos);
                m.push(LzMatch { src: mm.src, dest: mm.dest, len: mm.len });
                block_pos += lit as u64 + mm.len as u64;
            }
        }
        m.sort_by_key(|x| x.src);
        let origsize = input.len() as u64;
        m.push(LzMatch { src: origsize, dest: 0, len: 0 });

        let mut matchlists: Vec<u8> = Vec::new();
        let mut statsize_buf: Vec<u32> = Vec::new();
        let mut future_inline: Vec<u8> = Vec::new();
        let mut total_stat_size: u64 = 0;
        let mut cursor = 0usize;

        for b in &blocks {
            let block_start = b.start as u64;
            let block_end = block_start + b.size as u64;
            let mut block_matchlist: Vec<u32> = Vec::new();
            let mut blockpos = block_start;
            let mut saved_i = cursor;
            while m[cursor].src < block_end {
                if m[cursor].src + m[cursor].len as u64 <= block_start {
                    saved_i = cursor;
                    cursor += 1;
                    continue;
                }
                let src = m[cursor].src.max(block_start);
                let mut len = m[cursor].len as u64 - (src - m[cursor].src);
                len = len.min(block_end - src);
                encode_lz_match(
                    &mut block_matchlist,
                    false,
                    futurelz_base_len as u32,
                    (src - blockpos) as u32,
                    m[cursor].dest - m[cursor].src,
                    len as u32,
                );
                blockpos = src;
                cursor += 1;
            }
            cursor = saved_i;

            let stat_size = (block_matchlist.len() * 4) as u32;
            statsize_buf.push(stat_size);
            total_stat_size += stat_size as u64;

            if future_lz {
                let block = &input[b.start..b.start + b.size];
                let lit = extract_literals(block, &b.stats, round_matches, base_len);
                // header (stat_size = re-encoded list size) + match list + literals
                write_block_header(&mut future_inline, b.literal_bytes as u32, b.size as u32, stat_size, desc.hash_size, checksum.as_ref(), block);
                for s in &block_matchlist {
                    future_inline.extend_from_slice(&s.to_le_bytes());
                }
                future_inline.extend_from_slice(&lit);
            } else {
                for s in &block_matchlist {
                    matchlists.extend_from_slice(&s.to_le_bytes());
                }
            }
        }

        if future_lz {
            out.extend_from_slice(&future_inline);
        } else {
            // index-lz: match lists + statsize array + footer
            out.extend_from_slice(&matchlists);
            for s in &statsize_buf {
                out.extend_from_slice(&s.to_le_bytes());
            }
            let footer_size = (INDEX_LZ_FOOTER_SIZE + statsize_buf.len() * 4) as u32;
            let fw = [
                total_stat_size as u32,
                (total_stat_size >> 32) as u32,
                footer_size,
                1,
                !crate::types::SREP_SIGNATURE,
                !crate::types::BULAT_ZIGANSHIN_SIGNATURE,
            ];
            for w in fw {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
    }

    Ok(out)
}

fn extract_literals(block: &[u8], stats: &[u32], round: bool, base_len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut cur = 0usize;
    let l1 = if round { base_len } else { 1 };
    let l = base_len;
    let spp = stats_per_match(round);
    while stats.len() - cur >= spp {
        let lit = stats[cur] as usize;
        let len_word = if round { stats[cur + 2] } else { stats[cur + 3] };
        let len = (len_word as u64 * l1 + l) as usize;
        out.extend_from_slice(&block[cursor..cursor + lit]);
        cursor += lit + len;
        cur += spp;
    }
    out.extend_from_slice(&block[cursor..]);
    out
}

fn write_block_header(
    out: &mut Vec<u8>,
    literal_bytes: u32,
    uncompressed: u32,
    stat_size: u32,
    hash_size: usize,
    checksum: Option<&BlockChecksum>,
    block: &[u8],
) {
    out.extend_from_slice(&literal_bytes.to_le_bytes());
    out.extend_from_slice(&uncompressed.to_le_bytes());
    out.extend_from_slice(&stat_size.to_le_bytes());
    let mut dig = [0u8; 256];
    if let Some(cs) = checksum {
        cs.compute(block, &mut dig);
    }
    out.extend_from_slice(&dig[..hash_size]);
}