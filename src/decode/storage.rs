// MEMORY_MANAGER + VIRTUAL_MEMORY_MANAGER (decompress.cpp). Chunk/block layout
// is output-relevant only in that save/restore must round-trip bytes; it mirrors
// the reference 1 MiB blocks of 64-byte chunks (4-byte next-index + 60 payload).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::types::MB;

const CHUNK_SIZE: usize = 64;
const USEFUL_CHUNK_SPACE: usize = CHUNK_SIZE - 4;
const A_BLOCK_SIZE: usize = MB as usize;
const K: u32 = (A_BLOCK_SIZE / CHUNK_SIZE) as u32; // 16384
const K1: u32 = K - 1;
const LBK: u32 = 14;
pub const INVALID_INDEX: u32 = 0;

pub struct MemoryManager {
    block_addr: Vec<Box<[u8; A_BLOCK_SIZE]>>,
    first_free: u32,
    used_chunks: u64,
    useful_memory: u64,
    pub total_chunks: u32,
}

impl MemoryManager {
    pub fn new(memlimit: u64) -> MemoryManager {
        // Matches the reference's size_t arithmetic exactly (wraps when memlimit
        // is below one block, yielding a huge useful_memory — i.e. no spill).
        let useful_memory = (memlimit / A_BLOCK_SIZE as u64)
            .wrapping_mul(A_BLOCK_SIZE as u64)
            .wrapping_div(CHUNK_SIZE as u64)
            .wrapping_sub(1)
            .wrapping_mul(USEFUL_CHUNK_SPACE as u64);
        MemoryManager {
            block_addr: Vec::new(),
            first_free: INVALID_INDEX,
            used_chunks: 0,
            useful_memory,
            total_chunks: 0,
        }
    }

    #[inline]
    pub fn needmem(len: u64) -> u64 {
        ((len - 1) / USEFUL_CHUNK_SPACE as u64 + 1) * CHUNK_SIZE as u64
    }

    pub fn available_space(&self) -> u64 {
        let used = self.used_chunks * USEFUL_CHUNK_SPACE as u64;
        self.useful_memory.saturating_sub(used)
    }

    pub fn current_mem(&self) -> u64 {
        self.used_chunks * CHUNK_SIZE as u64
    }

    pub fn max_mem(&self) -> u64 {
        self.block_addr.len() as u64 * A_BLOCK_SIZE as u64
    }

    #[inline]
    fn chunk_ptr(&self, index: u32) -> usize {
        (index >> LBK) as usize * A_BLOCK_SIZE + (index & K1) as usize * CHUNK_SIZE
    }

    #[inline]
    fn next_index(&self, index: u32) -> u32 {
        let off = self.chunk_ptr(index);
        u32::from_le_bytes(self.block_addr[off / A_BLOCK_SIZE][off % A_BLOCK_SIZE..][0..4].try_into().unwrap())
    }

    #[inline]
    fn set_next_index(&mut self, index: u32, next_index: u32) {
        let off = self.chunk_ptr(index);
        let blk = off / A_BLOCK_SIZE;
        let bo = off % A_BLOCK_SIZE;
        self.block_addr[blk][bo..bo + 4].copy_from_slice(&next_index.to_le_bytes());
    }

    #[inline]
    fn data_ptr(&self, index: u32) -> usize {
        self.chunk_ptr(index) + 4
    }

    fn allocate(&mut self) -> u32 {
        if self.first_free == INVALID_INDEX {
            self.allocate_block();
        }
        let free_chunk = self.first_free;
        self.first_free = self.next_index(free_chunk);
        self.used_chunks += 1;
        free_chunk
    }

    fn mark_as_free(&mut self, index: u32) {
        let ff = self.first_free;
        self.set_next_index(index, ff);
        self.first_free = index;
        self.used_chunks -= 1;
    }

    fn allocate_block(&mut self) {
        let block = self.block_addr.len() as u32;
        self.block_addr.push(Box::new([0u8; A_BLOCK_SIZE]));
        let mut i: u32 = block * K;
        while i < (block + 1) * K - 1 {
            self.set_next_index(i, i + 1);
            i += 1;
        }
        let ff = self.first_free;
        self.set_next_index((block + 1) * K - 1, ff);
        self.first_free = block * K;
        if self.first_free == INVALID_INDEX {
            self.first_free += 1;
        }
        self.total_chunks = (block + 1) * K;
    }

    /// Save `len` bytes to a chunk chain; return the head index.
    pub fn save(&mut self, ptr: &[u8], len: usize) -> u32 {
        let mut index = INVALID_INDEX;
        let mut first_index = INVALID_INDEX;
        let mut prev_index = INVALID_INDEX;
        let mut off = 0usize;
        let mut len = len;
        while len > 0 {
            index = self.allocate();
            if prev_index != INVALID_INDEX {
                self.set_next_index(prev_index, index);
            } else {
                first_index = index;
            }
            prev_index = index;
            let bytes = len.min(USEFUL_CHUNK_SPACE);
            let dp = self.data_ptr(index);
            let blk = dp / A_BLOCK_SIZE;
            let bo = dp % A_BLOCK_SIZE;
            self.block_addr[blk][bo..bo + bytes].copy_from_slice(&ptr[off..off + bytes]);
            off += bytes;
            len -= bytes;
        }
        self.set_next_index(index, INVALID_INDEX);
        first_index
    }

    /// Restore `len` bytes from chunk chain `index` into `ptr`.
    pub fn restore(&self, index: u32, ptr: &mut [u8], len: usize) {
        let mut index = index;
        let mut off = 0usize;
        let mut len = len;
        while len > 0 {
            let bytes = len.min(USEFUL_CHUNK_SPACE);
            let dp = self.data_ptr(index);
            let blk = dp / A_BLOCK_SIZE;
            let bo = dp % A_BLOCK_SIZE;
            ptr[off..off + bytes].copy_from_slice(&self.block_addr[blk][bo..bo + bytes]);
            off += bytes;
            len -= bytes;
            index = self.next_index(index);
        }
    }

    /// Free a chunk chain.
    pub fn free(&mut self, index: u32) {
        let mut index = index;
        while index != INVALID_INDEX {
            let next = self.next_index(index);
            self.mark_as_free(index);
            index = next;
        }
    }
}

/// Spill records: `[u32 len][u64 src][u64 dest][payload]` + 4-byte zero end mark.
pub const SPILL_HEADER: u64 = 20;

pub struct VirtualMemoryManager {
    pub vmfile_name: String,
    vmfile: Option<File>,
    pub vmblock_size: u64,
    vmbuf: Vec<u8>,
    free_blocks: Vec<u32>,
    new_block: u32,
    pub total_read: u64,
    pub total_write: u64,
}

impl VirtualMemoryManager {
    pub fn new(vmfile_name: &str, vmblock_size: u64) -> VirtualMemoryManager {
        VirtualMemoryManager {
            vmfile_name: vmfile_name.to_string(),
            vmfile: None,
            vmblock_size,
            vmbuf: Vec::new(),
            free_blocks: Vec::new(),
            new_block: 0,
            total_read: 0,
            total_write: 0,
        }
    }

    /// Ensure the vmbuf and vmfile exist.
    fn ensure_open(&mut self) -> Result<(), String> {
        if self.vmbuf.is_empty() {
            self.vmbuf = vec![0u8; self.vmblock_size as usize];
        }
        if self.vmfile.is_none() {
            self.vmfile = Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&self.vmfile_name)
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(())
    }

    /// Save matches with largest dest to disk.
    pub fn save_to_disk(
        &mut self,
        mm: &mut MemoryManager,
        heap: &mut LzMatchHeap,
    ) -> Result<bool, String> {
        self.ensure_open()?;
        let vs = self.vmblock_size as usize;
        let mut vmbuf = std::mem::take(&mut self.vmbuf);
        let mut spilled = false;

        // Descending dest order; the very first (largest) is the barrier.
        let mut to_erase = Vec::new();
        let mut min_dest = u64::MAX;
        let mut p: usize = 0;
        let desc: Vec<HeapEntry> = heap.set.iter().rev().cloned().collect();
        let mut first = true;
        for e in &desc {
            if first {
                first = false;
                continue; // skip barrier (largest dest)
            }
            if e.index == INVALID_INDEX {
                continue; // no saved data (max-save match, marking point, barrier)
            }
            if vs - p < (24 + e.len as usize) {
                break;
            }
            vmbuf[p..p + 4].copy_from_slice(&e.len.to_le_bytes());
            vmbuf[p + 4..p + 12].copy_from_slice(&e.src.to_le_bytes());
            vmbuf[p + 12..p + 20].copy_from_slice(&e.dest.to_le_bytes());
            min_dest = e.dest;
            mm.restore(e.index, &mut vmbuf[p + 20..p + 20 + e.len as usize], e.len as usize);
            let idx = e.index;
            mm.free(idx);
            p += 20 + e.len as usize;
            spilled = true;
            to_erase.push(*e);
        }
        vmbuf[p..p + 4].copy_from_slice(&0u32.to_le_bytes());

        // Write the block to disk.
        let block = match self.free_blocks.pop() {
            Some(b) => b,
            None => {
                let b = self.new_block;
                self.new_block += 1;
                b
            }
        };
        let vmfile = self.vmfile.as_mut().unwrap();
        vmfile
            .seek(SeekFrom::Start(block as u64 * self.vmblock_size))
            .map_err(|e| e.to_string())?;
        vmfile.write_all(&vmbuf).map_err(|e| e.to_string())?;
        self.total_write += self.vmblock_size;

        self.vmbuf = vmbuf;

        for e in &to_erase {
            heap.set.remove(e);
        }
        let mark = HeapEntry {
            src: block as u64,
            dest: min_dest,
            len: 0,
            index: INVALID_INDEX,
            seq: 0,
        };
        heap.insert(mark);
        Ok(spilled)
    }

    /// Restore matches pointed to by `mark` from disk.
    pub fn restore_from_disk(
        &mut self,
        mm: &mut MemoryManager,
        heap: &mut LzMatchHeap,
        mark: &HeapEntry,
    ) -> Result<(), String> {
        while mm.available_space() < self.vmblock_size {
            if !self.save_to_disk(mm, heap)? {
                return Err("VM spill stalled: a match exceeds the VM block size".to_string());
            }
        }
        self.ensure_open()?;
        let block = mark.src as u32;
        let vmfile = self.vmfile.as_mut().unwrap();
        vmfile
            .seek(SeekFrom::Start(block as u64 * self.vmblock_size))
            .map_err(|e| e.to_string())?;
        vmfile
            .read_exact(&mut self.vmbuf)
            .map_err(|e| e.to_string())?;
        self.total_read += self.vmblock_size;
        self.free_blocks.push(block);

        let vmbuf = std::mem::take(&mut self.vmbuf);
        let vs = self.vmblock_size as usize;
        let mut p = 0usize;
        while u32::from_le_bytes(vmbuf[p..p + 4].try_into().unwrap()) != 0 {
            // Bounds-check (the C does not) so corrupt archives error, not OOB.
            if p + 20 > vs {
                self.vmbuf = vmbuf;
                return Err("corrupt VM block".to_string());
            }
            let len = u32::from_le_bytes(vmbuf[p..p + 4].try_into().unwrap());
            let src = u64::from_le_bytes(vmbuf[p + 4..p + 12].try_into().unwrap());
            let dest = u64::from_le_bytes(vmbuf[p + 12..p + 20].try_into().unwrap());
            if p + 20 + len as usize > vs {
                self.vmbuf = vmbuf;
                return Err("corrupt VM block".to_string());
            }
            let idx = mm.save(&vmbuf[p + 20..p + 20 + len as usize], len as usize);
            let e = HeapEntry {
                src,
                dest,
                len,
                index: idx,
                seq: 0,
            };
            heap.insert(e);
            p += 20 + len as usize;
        }
        self.vmbuf = vmbuf;
        Ok(())
    }

    pub fn current_mem(&self) -> u64 {
        (self.new_block as u64 - self.free_blocks.len() as u64) * self.vmblock_size
    }
}

/// A future-LZ match stored in the destination-ordered heap.
#[derive(Clone, Copy, Debug)]
pub struct HeapEntry {
    pub src: u64,
    pub dest: u64,
    pub len: u32,
    pub index: u32,
    pub seq: u64,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.dest == other.dest && self.seq == other.seq
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.dest, self.seq).cmp(&(other.dest, other.seq))
    }
}

impl HeapEntry {
    pub fn is_marking_point(&self) -> bool {
        self.len == 0
    }
}

/// `std::multiset<FUTURE_LZ_MATCH>` ordered by dest; Rust models the multiset
/// with a (dest, seq) key, preserving insertion order among equal destinations.
pub struct LzMatchHeap {
    set: std::collections::BTreeSet<HeapEntry>,
    seq_counter: u64,
}

impl LzMatchHeap {
    pub fn new() -> LzMatchHeap {
        LzMatchHeap {
            set: std::collections::BTreeSet::new(),
            seq_counter: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let s = self.seq_counter;
        self.seq_counter += 1;
        s
    }

    pub fn insert(&mut self, mut e: HeapEntry) {
        e.seq = self.next_seq();
        self.set.insert(e);
    }

    pub fn begin(&self) -> Option<&HeapEntry> {
        self.set.iter().next()
    }

    pub fn remove(&mut self, e: &HeapEntry) {
        self.set.remove(e);
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn insert_barrier(&mut self) {
        let e = HeapEntry {
            src: u64::MAX,
            dest: u64::MAX,
            len: u32::MAX,
            index: INVALID_INDEX,
            seq: 0,
        };
        self.insert(e);
    }
}

impl Default for LzMatchHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_spill_stalls_when_match_exceeds_block() {
        let mut mm = MemoryManager::new(MB);
        let mut vm = VirtualMemoryManager::new("vm_spill_test.tmp", 64);
        let mut heap = LzMatchHeap::new();
        heap.insert_barrier();

        // A saved match whose spill record (20 + len + 4 > vmblock_size) cannot
        // fit in one 64-byte VM block: 20 + 41 + 4 = 65 > 64.
        let idx = mm.save(&[0u8; 41], 41);
        heap.insert(HeapEntry {
            src: 0,
            dest: 1,
            len: 41,
            index: idx,
            seq: 0,
        });

        // Exhaust the allocator below one VM block so restore_from_disk must spill.
        let _keep = mm.save(&[0u8; 16382 * USEFUL_CHUNK_SPACE], 16382 * USEFUL_CHUNK_SPACE);
        assert!(mm.available_space() < vm.vmblock_size);

        let mark = HeapEntry {
            src: 0,
            dest: 0,
            len: 0,
            index: INVALID_INDEX,
            seq: 0,
        };
        let result = vm.restore_from_disk(&mut mm, &mut heap, &mark);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("VM spill stalled"));

        drop(vm);
        let _ = std::fs::remove_file("vm_spill_test.tmp");
    }
}