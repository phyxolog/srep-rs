// Decompression driver: archive header → per-block decode dispatch (v1..v4).

pub mod backward;
pub mod future;
pub mod storage;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::checksum::BlockChecksum;
use crate::format::footer::{Footer, INDEX_LZ_FOOTER_SIZE};
use crate::format::header::check_header;
use crate::types::{MB, SREP_FORMAT_VERSION1, SREP_FORMAT_VERSION2, SREP_FORMAT_VERSION4};
use storage::{LzMatchHeap, MemoryManager, VirtualMemoryManager};

pub struct DecompressOptions {
    pub forced_checksum: Option<BlockChecksum>,
    /// -mem value (bytes); used to size the in-RAM match store.
    pub vm_mem: u64,
    /// -vmblock value (bytes).
    pub vm_block: u64,
    /// -vmfile name.
    pub vmfile_name: String,
    /// -b value (bytes); block buffer size for bounds checks.
    pub bufsize: u64,
    /// -m value (bytes): matches >= this are reread from output (default: unlimited).
    pub maximum_save: u32,
}

impl Default for DecompressOptions {
    fn default() -> Self {
        DecompressOptions {
            forced_checksum: None,
            vm_mem: (75u64 * physical_memory() / 100).max(64 * MB),
            vm_block: 8 * MB,
            vmfile_name: "srep-virtual-memory.tmp".to_string(),
            bufsize: 8 * MB,
            maximum_save: u32::MAX,
        }
    }
}

/// Best-effort physical RAM estimate (matches GetPhysicalMemory() roughly; not
/// output-relevant, only affects spill timing).
fn physical_memory() -> u64 {
    use std::io::BufRead;
    if let Ok(f) = File::open("/proc/meminfo") {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return kb * 1024;
            }
        }
    }
    // macOS fallback: read from sysctl via a trivial best effort.
    if let Ok(out) = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
    {
        if let Some(v) = String::from_utf8(out.stdout).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
            return v;
        }
    }
    8 * 1024 * MB
}

/// Decompress `fin` (archive) into `fout` (created/truncated read-write).
pub fn decompress(
    fin: &mut File,
    fout: &mut File,
    opts: &DecompressOptions,
) -> Result<(), String> {
    let filesize = fin.metadata().map_err(|e| e.to_string())?.len();

    let mut words = [0u32; 4];
    read_exact_u32s(fin, &mut words)?;
    let hdr = check_header(&words)?;

    let mut seed = vec![0u8; hdr.hash_seed_size];
    fin.read_exact(&mut seed)
        .map_err(|e| format!("unexpected EOF reading seed: {e}"))?;

    let checksum = match &opts.forced_checksum {
        Some(c) => Some(c.clone()),
        None => resolve_checksum(hdr.hash_num, &seed),
    };

    let header_size = 3 * 4 + hdr.hash_size;
    let full_archive_header_size = 16 + hdr.hash_seed_size;
    let round_matches = hdr.format_version == SREP_FORMAT_VERSION1;
    let io_lz = hdr.format_version <= SREP_FORMAT_VERSION2;
    let index_lz = hdr.format_version == SREP_FORMAT_VERSION4;

    let v4 = if index_lz {
        Some(read_index(fin, filesize, full_archive_header_size as u64)?)
    } else {
        None
    };

    // Memory/VM managers for future/index decode.
    let io_mem = opts.vm_block + opts.bufsize + opts.bufsize + opts.bufsize / 4 + 8 * MB;
    let mm_limit = if opts.vm_mem >= io_mem + opts.vm_block * 4 {
        opts.vm_mem - io_mem
    } else {
        opts.vm_block * 4
    };
    let mut mm = MemoryManager::new(mm_limit);
    let mut vm = VirtualMemoryManager::new(&opts.vmfile_name, opts.vm_block);
    let mut heap = LzMatchHeap::new();
    heap.insert_barrier();

    let mut block_start: u64 = 0;
    let mut out = Vec::new();
    let mut stat_ptr = 0usize;
    let mut statsize_ptr = 0usize;

    loop {
        // Read block header.
        let mut hbuf = vec![0u8; header_size];
        let read = fin.read(&mut hbuf).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        // EOF sentinel header: two zero words (applies to every format; an empty
        // archive's footer words are 0 and are read where a block header would be).
        if read >= 8 {
            let b0 = u32::from_le_bytes(hbuf[0..4].try_into().unwrap());
            let b1 = u32::from_le_bytes(hbuf[4..8].try_into().unwrap());
            if b0 == 0 && b1 == 0 {
                break;
            }
        }
        if read != header_size {
            return Err("unexpected end of file in block header".to_string());
        }
        let b0 = u32::from_le_bytes(hbuf[0..4].try_into().unwrap());
        let b1 = u32::from_le_bytes(hbuf[4..8].try_into().unwrap());
        let b2 = u32::from_le_bytes(hbuf[8..12].try_into().unwrap());
        let literal_bytes = b0 as usize;
        let origsize = b1 as usize;
        let statsize1 = b2 as usize;

        // Resolve the match list for this block.
        let statraw: Vec<u32>;
        if index_lz {
            let v4 = v4.as_ref().unwrap();
            let count = v4.statsize_buf[statsize_ptr] as usize;
            statsize_ptr += 1;
            statraw = v4.statbuf[stat_ptr..stat_ptr + count / 4].to_vec();
            stat_ptr += count / 4;
        } else {
            let count = statsize1;
            let mut mbuf = vec![0u8; count];
            fin.read_exact(&mut mbuf)
                .map_err(|e| format!("unexpected EOF reading match list: {e}"))?;
            statraw = mbuf.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        }

        // Read literals.
        let mut lbuf = vec![0u8; literal_bytes];
        fin.read_exact(&mut lbuf)
            .map_err(|e| format!("unexpected EOF reading literals: {e}"))?;

        out.resize(origsize, 0);
        let ok = if io_lz {
            backward::decompress(round_matches, hdr.base_len, fout, block_start, &statraw, &lbuf, &mut out)
        } else {
            let max_save = opts.maximum_save;
            future::decompress_future_lz(
                round_matches,
                hdr.base_len,
                fout,
                block_start,
                &statraw,
                &lbuf,
                &mut out,
                &mut mm,
                &mut vm,
                &mut heap,
                max_save,
            )?
        };
        if !ok {
            return Err("broken compressed data".to_string());
        }

        if let Some(cs) = &checksum {
            let mut dig = [0u8; 256];
            cs.compute(&out, &mut dig);
            if dig[..hdr.hash_size] != hbuf[12..12 + hdr.hash_size] {
                return Err("checksum mismatch".to_string());
            }
        }

        fout.seek(SeekFrom::Start(block_start)).map_err(|e| e.to_string())?;
        fout.write_all(&out).map_err(|e| e.to_string())?;

        block_start += origsize as u64;

        if index_lz && statsize_ptr == v4.as_ref().unwrap().statsize_buf.len() {
            break;
        }
    }

    fout.flush().map_err(|e| e.to_string())?;
    // Remove the VM spill file if it was created.
    let _ = std::fs::remove_file(&opts.vmfile_name);
    Ok(())
}

struct IndexData {
    statbuf: Vec<u32>,
    statsize_buf: Vec<u32>,
}

fn read_index(fin: &mut File, filesize: u64, full_archive_header_size: u64) -> Result<IndexData, String> {
    let mut footer_words = [0u32; 6];
    fin.seek(SeekFrom::Start(filesize - INDEX_LZ_FOOTER_SIZE as u64))
        .map_err(|e| e.to_string())?;
    for w in footer_words.iter_mut() {
        let mut b = [0u8; 4];
        fin.read_exact(&mut b).map_err(|e| e.to_string())?;
        *w = u32::from_le_bytes(b);
    }
    let footer = Footer::parse(&footer_words);
    footer.check(&footer_words)?;
    let stat_size = footer.total_stat_size;
    let footer_size = footer.footer_size as u64;

    if stat_size + footer_size > filesize - 16 {
        return Err("broken SREP footer".to_string());
    }

    // Read the full match list.
    let mut statbuf = vec![0u8; stat_size as usize];
    fin.seek(SeekFrom::Start(filesize - footer_size - stat_size))
        .map_err(|e| e.to_string())?;
    fin.read_exact(&mut statbuf).map_err(|e| e.to_string())?;
    let statbuf: Vec<u32> = statbuf
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    // Read per-block stat_size array.
    let total_blocks = footer.total_blocks();
    let mut statsize_buf = vec![0u32; total_blocks];
    for w in statsize_buf.iter_mut() {
        let mut b = [0u8; 4];
        fin.read_exact(&mut b).map_err(|e| e.to_string())?;
        *w = u32::from_le_bytes(b);
    }

    // Rewind to the first block header.
    fin.seek(SeekFrom::Start(full_archive_header_size))
        .map_err(|e| e.to_string())?;
    Ok(IndexData {
        statbuf,
        statsize_buf,
    })
}

fn resolve_checksum(hash_num: u32, seed: &[u8]) -> Option<BlockChecksum> {
    use crate::checksum::hash_by_num;
    let desc = hash_by_num(hash_num)?;
    if desc.hash_num == 1 {
        return None;
    }
    Some(BlockChecksum::new(desc, seed))
}

fn read_exact_u32s(fin: &mut File, words: &mut [u32]) -> Result<(), String> {
    let mut buf = vec![0u8; words.len() * 4];
    fin.read_exact(&mut buf).map_err(|e| e.to_string())?;
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap());
    }
    Ok(())
}