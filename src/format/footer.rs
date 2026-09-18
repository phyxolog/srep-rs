// v4 (INDEX_LZ) trailing footer: `[concat match lists][per-block stat_size
// words][24-byte footer]` (srep.cpp pass 2 writer + INDEX_LZ loader).

use crate::types::{Offset, Stat, BLOCK_HEADER_SIZE};

/// 24-byte footer = six u32 words; between the match lists and the footer is the
/// per-block `stat_size` array (`footer_size - 24` bytes).
pub const INDEX_LZ_FOOTER_SIZE: usize = 24;
pub const SREP_FOOTER_VERSION1: u32 = 1;

pub struct Footer {
    pub total_stat_size: Offset,
    pub footer_size: u32,
    pub footer_version: u32,
}

impl Footer {
    pub fn parse(words: &[Stat; 6]) -> Footer {
        Footer {
            total_stat_size: (words[0] as Offset) | ((words[1] as Offset) << 32),
            footer_size: words[2],
            footer_version: words[3],
        }
    }

    pub fn write(footer_size: u32) -> [Stat; 6] {
        // total_stat_size filled by caller after block list is known.
        [
            0,
            0,
            footer_size,
            SREP_FOOTER_VERSION1,
            !crate::types::SREP_SIGNATURE,
            !crate::types::BULAT_ZIGANSHIN_SIGNATURE,
        ]
    }

    /// Validate footer signature and version words.
    pub fn check(&self, words: &[Stat; 6]) -> Result<(), String> {
        if words[5] != !crate::types::BULAT_ZIGANSHIN_SIGNATURE
            || words[4] != !crate::types::SREP_SIGNATURE
        {
            return Err("Not found SREP compressed file footer".to_string());
        }
        if self.footer_version != SREP_FOOTER_VERSION1 {
            return Err(format!(
                "Incompatible compressed file footer format: v{}",
                self.footer_version
            ));
        }
        Ok(())
    }

    pub fn total_blocks(&self) -> usize {
        (self.footer_size as usize - INDEX_LZ_FOOTER_SIZE) / std::mem::size_of::<Stat>()
    }
}

#[allow(dead_code)]
pub fn block_header_size(hash_size: usize) -> usize {
    BLOCK_HEADER_SIZE * std::mem::size_of::<Stat>() + hash_size
}