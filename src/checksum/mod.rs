// Hash descriptor registry and seed handling (hashes.cpp:417-422), plus the
// standardized-hash wrappers. Block checksums (md5/sha1/sha512/vmac/siphash)
// are computed per block and stored in the 3-word block header's trailing
// `hash_size` bytes.

pub mod siphash;
pub mod vhash;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha512};

pub use siphash::SipHash;
pub use vhash::{VHash, VDigest};

/// A single checksum descriptor mirroring `hash_descriptors[]`.
pub struct HashDescriptor {
    pub hash_name: &'static str,
    pub hash_num: u32,
    pub hash_seed_size: usize,
    pub hash_size: usize,
}

pub const HASH_DESCRIPTORS: &[HashDescriptor] = &[
    HashDescriptor {
        hash_name: "md5",
        hash_num: 0,
        hash_seed_size: 0,
        hash_size: 16,
    },
    HashDescriptor {
        hash_name: "",
        hash_num: 1,
        hash_seed_size: 0,
        hash_size: 16,
    },
    HashDescriptor {
        hash_name: "sha1",
        hash_num: 2,
        hash_seed_size: 0,
        hash_size: 20,
    },
    HashDescriptor {
        hash_name: "sha512",
        hash_num: 3,
        hash_seed_size: 0,
        hash_size: 64,
    },
    HashDescriptor {
        hash_name: "vmac",
        hash_num: 4,
        hash_seed_size: 32,
        hash_size: 16,
    },
    HashDescriptor {
        hash_name: "siphash",
        hash_num: 5,
        hash_seed_size: 16,
        hash_size: 8,
    },
];

pub const DEFAULT_HASH_NAME: &str = "vmac";

/// Look up a descriptor by its `-hash=` name (case-insensitive).
pub fn hash_by_name(name: &str) -> Option<&'static HashDescriptor> {
    HASH_DESCRIPTORS
        .iter()
        .find(|d| d.hash_name.eq_ignore_ascii_case(name))
}

/// Look up a descriptor by its numeric archive tag.
pub fn hash_by_num(num: u32) -> Option<&'static HashDescriptor> {
    HASH_DESCRIPTORS.iter().find(|d| d.hash_num == num)
}

pub fn compute_md5(buf: &[u8]) -> [u8; 16] {
    Md5::digest(buf).into()
}

pub fn compute_sha1(buf: &[u8]) -> [u8; 20] {
    Sha1::digest(buf).into()
}

pub fn compute_sha512(buf: &[u8]) -> [u8; 64] {
    Sha512::digest(buf).into()
}

/// A resolved, stateful checksum object used for block checksums (the `hash_obj`
/// role in the reference). Keyed hashes (vmac/siphash) carry their seed.
#[derive(Clone)]
pub enum BlockChecksum {
    Md5,
    Sha1,
    Sha512,
    Vmac(Box<VHash>),
    SipHash(SipHash),
    None,
}

impl BlockChecksum {
    /// Build the checksum object for a descriptor + optional seed bytes.
    pub fn new(desc: &HashDescriptor, seed: &[u8]) -> BlockChecksum {
        match desc.hash_num {
            0 => BlockChecksum::Md5,
            2 => BlockChecksum::Sha1,
            3 => BlockChecksum::Sha512,
            4 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&seed[..32]);
                BlockChecksum::Vmac(Box::new(VHash::new_with_key(&key)))
            }
            5 => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&seed[..16]);
                BlockChecksum::SipHash(SipHash::new_with_key(&key))
            }
            _ => BlockChecksum::None,
        }
    }

    /// Compute the block checksum into `result` (exactly `hash_size` bytes).
    pub fn compute(&self, buf: &[u8], result: &mut [u8]) {
        match self {
            BlockChecksum::Md5 => result[..16].copy_from_slice(&compute_md5(buf)),
            BlockChecksum::Sha1 => result[..20].copy_from_slice(&compute_sha1(buf)),
            BlockChecksum::Sha512 => result[..64].copy_from_slice(&compute_sha512(buf)),
            BlockChecksum::Vmac(h) => h.compute(buf, result),
            BlockChecksum::SipHash(s) => s.compute_into(buf, result),
            BlockChecksum::None => {}
        }
    }
}