// Block header: 3 u32 words (literal_bytes, uncompressed size, stat_size) plus
// `hash_size` checksum bytes (srep.cpp BLOCK_HEADER_SIZE).

use crate::types::Stat;

#[derive(Clone, Copy, Debug)]
pub struct BlockHeader {
    pub literal_bytes: u32,
    pub uncompressed_size: u32,
    pub stat_size: u32,
}

impl BlockHeader {
    pub fn parse(words: &[Stat; 3]) -> BlockHeader {
        BlockHeader {
            literal_bytes: words[0],
            uncompressed_size: words[1],
            stat_size: words[2],
        }
    }

    pub fn write(&self) -> [Stat; 3] {
        [self.literal_bytes, self.uncompressed_size, self.stat_size]
    }

    /// EOF header: two zero 32-bit words (srep.cpp decompression loop).
    pub fn is_eof(&self) -> bool {
        self.literal_bytes == 0 && self.uncompressed_size == 0
    }
}