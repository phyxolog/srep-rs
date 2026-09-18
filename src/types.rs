// Type aliases matching the C reference exactly. Widths are output-bearing.

pub type Offset = u64;
pub type Stat = u32;
pub type Chunk = u32;
pub type BigHash = u64;
pub type HashValue = usize;
pub type StoredHashValue = u32;
pub type TIndex = usize;
pub type NUMBER = usize;

pub const MAX_CHUNK: Chunk = u32::MAX;
pub const NOT_FOUND: Chunk = 0;
pub const INVALID_INDEX: u32 = 0;

// Memory-unit constants (Compression/Compression.h)
pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * KB;
pub const GB: u64 = 1024 * MB;

// Format constants (srep.cpp)
pub const SREP_SIGNATURE: u32 = 0x5045_5253;
pub const SREP_FORMAT_VERSION1: u32 = 1;
pub const SREP_FORMAT_VERSION2: u32 = 2;
pub const SREP_FORMAT_VERSION3: u32 = 3;
pub const SREP_FORMAT_VERSION4: u32 = 4;
pub const SREP_FOOTER_VERSION1: u32 = 1;
pub const ARCHIVE_HEADER_SIZE: usize = 4;
pub const BLOCK_HEADER_SIZE: usize = 3;
pub const MAX_HEADER_SIZE: usize = 4;
pub const MAX_HASH_SIZE: usize = 256;

pub const MINIMAL_MIN_MATCH: usize = 16;
pub const DEFAULT_MIN_MATCH: usize = 32;

pub const BULAT_ZIGANSHIN_SIGNATURE: u32 = 0x2635_1817;