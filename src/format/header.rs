// Archive header: 4 u32 words + hash seed (srep.cpp header write/read).

use crate::types::{Stat, ARCHIVE_HEADER_SIZE, BULAT_ZIGANSHIN_SIGNATURE, SREP_FORMAT_VERSION1, SREP_FORMAT_VERSION4, SREP_SIGNATURE};

pub struct ArchiveHeader {
    pub format_version: u32,
    pub hash_num: u32,
    pub hash_seed_size: usize,
    pub hash_size: usize,
    pub base_len: u32,
}

/// Parse the 4-word archive header from the start of the file's first 16 bytes.
pub fn parse_header(words: &[u32; 4]) -> ArchiveHeader {
    ArchiveHeader {
        format_version: words[2] & 0xff,
        hash_num: (words[2] >> 8) & 0xff,
        hash_seed_size: ((words[2] >> 16) & 0xff) as usize,
        hash_size: (((words[2] >> 24) + 16) & 0xff) as usize,
        base_len: words[3],
    }
}

/// Validate signature and version; returns the header or an error string.
pub fn check_header(words: &[u32; 4]) -> Result<ArchiveHeader, String> {
    if words[0] != BULAT_ZIGANSHIN_SIGNATURE || words[1] != SREP_SIGNATURE {
        return Err("Not an SREP compressed file".to_string());
    }
    let h = parse_header(words);
    if h.format_version < SREP_FORMAT_VERSION1 || h.format_version > SREP_FORMAT_VERSION4 {
        return Err(format!("Incompatible compressed data format: v{}", h.format_version));
    }
    Ok(h)
}

/// Serialize a 4-word archive header (compression side).
pub fn write_header(
    version: u32,
    hash_num: u32,
    hash_seed_size: usize,
    hash_size: usize,
    base_len: u32,
) -> [Stat; 4] {
    let mut h = [0u32; ARCHIVE_HEADER_SIZE];
    h[0] = BULAT_ZIGANSHIN_SIGNATURE;
    h[1] = SREP_SIGNATURE;
    let hs: u32 = ((hash_size as u32).wrapping_sub(16)) & 0xff;
    h[2] = version | (hash_num << 8) | ((hash_seed_size as u32) << 16) | (hs << 24);
    h[3] = base_len;
    h
}