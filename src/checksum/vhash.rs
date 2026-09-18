// Verbatim port of _Encryption/hashes/vmac/vmac.c (VMAC-128, VMAC_KEY_LEN=256,
// VMAC_NHBYTES=4096) as configured by hashes.cpp on a 64-bit little-endian
// (aarch64/x86-64, FREEARC_INTEL_BYTE_ORDER) host.
//
// The 64-bit generic MUL64/PMUL64/ADD128 macros are expressed with u128
// multiplication and 64-bit wrapping adds — mathematically identical to the
// carry-propagating macro versions.

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

const P64: u64 = 0xffff_ffff_ffff_feff; /* 2^64 - 257 prime  */
const M62: u64 = 0x3fffffff_ffffffff; /* 62-bit mask       */
const M63: u64 = 0x7fffffff_ffffffff; /* 63-bit mask       */
const M64: u64 = 0xffffffff_ffffffff; /* 64-bit mask       */
const MPOLY: u64 = 0x1fffffff_1fffffff; /* Poly key mask     */

const VMAC_NHBYTES: usize = 4096;

/// (rh:rl) += (ih:il) as a single 128-bit addition with carry (wrapping).
#[inline]
fn add128(rh: &mut u64, rl: &mut u64, ih: u64, il: u64) {
    let new_rl = rl.wrapping_add(il);
    let carry = (new_rl < il) as u64;
    *rl = new_rl;
    *rh = rh.wrapping_add(ih).wrapping_add(carry);
}

/// 128-bit product (rh:rl) = i1 * i2 (MUL64/PMUL64 generic implementation).
#[inline]
fn mul128(i1: u64, i2: u64) -> (u64, u64) {
    let prod = (i1 as u128) * (i2 as u128);
    ((prod >> 64) as u64, prod as u64)
}

#[inline]
fn get64le(m: &[u8], word_off: usize) -> u64 {
    let i = word_off * 8;
    u64::from_le_bytes(m[i..i + 8].try_into().unwrap())
}

#[inline]
fn get64be(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[0..8].try_into().unwrap())
}

/// L1 NH hash for full 4096-byte blocks, two accumulators (VMAC_TAG_LEN=128).
/// `m_off` is a word offset into `m`; `kp` is the full 514-word nhkey buffer,
/// always indexed from 0 (the C never advances `kptr` between blocks).
fn nh_vmac_nhbytes_2(m: &[u8], m_off: usize, kp: &[u64]) -> (u64, u64, u64, u64) {
    let mut acc: u128 = 0; // rh:rl
    let mut acc2: u128 = 0; // rh2:rl2
    let mut i = 0usize;
    while i < VMAC_NHBYTES / 8 {
        let a0 = get64le(m, m_off + i).wrapping_add(kp[i]);
        let a1 = get64le(m, m_off + i + 1).wrapping_add(kp[i + 1]);
        let a2 = get64le(m, m_off + i + 2).wrapping_add(kp[i + 2]);
        let a3 = get64le(m, m_off + i + 3).wrapping_add(kp[i + 3]);
        let a4 = get64le(m, m_off + i + 4).wrapping_add(kp[i + 4]);
        let a5 = get64le(m, m_off + i + 5).wrapping_add(kp[i + 5]);
        let a6 = get64le(m, m_off + i + 6).wrapping_add(kp[i + 6]);
        let a7 = get64le(m, m_off + i + 7).wrapping_add(kp[i + 7]);
        acc = acc
            .wrapping_add((a0 as u128) * (a1 as u128))
            .wrapping_add((a2 as u128) * (a3 as u128))
            .wrapping_add((a4 as u128) * (a5 as u128))
            .wrapping_add((a6 as u128) * (a7 as u128));

        let b0 = get64le(m, m_off + i).wrapping_add(kp[i + 2]);
        let b1 = get64le(m, m_off + i + 1).wrapping_add(kp[i + 3]);
        let b2 = get64le(m, m_off + i + 2).wrapping_add(kp[i + 4]);
        let b3 = get64le(m, m_off + i + 3).wrapping_add(kp[i + 5]);
        let b4 = get64le(m, m_off + i + 4).wrapping_add(kp[i + 6]);
        let b5 = get64le(m, m_off + i + 5).wrapping_add(kp[i + 7]);
        let b6 = get64le(m, m_off + i + 6).wrapping_add(kp[i + 8]);
        let b7 = get64le(m, m_off + i + 7).wrapping_add(kp[i + 9]);
        acc2 = acc2
            .wrapping_add((b0 as u128) * (b1 as u128))
            .wrapping_add((b2 as u128) * (b3 as u128))
            .wrapping_add((b4 as u128) * (b5 as u128))
            .wrapping_add((b6 as u128) * (b7 as u128));
        i += 8;
    }
    (
        (acc >> 64) as u64,
        acc as u64,
        (acc2 >> 64) as u64,
        acc2 as u64,
    )
}

/// NH over a message tail of `remaining` (< 4096) bytes: full 16-byte blocks
/// plus a zero-padded final fragment (the `#else` / non-FILL16 branch).
fn nh_tail(m: &[u8], m_word_base: usize, kp: &[u64], remaining: usize) -> (u64, u64, u64, u64) {
    let full_words = 2 * (remaining / 16);
    let mut acc: u128 = 0;
    let mut acc2: u128 = 0;

    if remaining / 16 > 0 {
        let mut i = 0usize;
        while i < full_words {
            let a0 = get64le(m, m_word_base + i).wrapping_add(kp[i]);
            let a1 = get64le(m, m_word_base + i + 1).wrapping_add(kp[i + 1]);
            acc = acc.wrapping_add((a0 as u128) * (a1 as u128));
            let b0 = get64le(m, m_word_base + i).wrapping_add(kp[i + 2]);
            let b1 = get64le(m, m_word_base + i + 1).wrapping_add(kp[i + 3]);
            acc2 = acc2.wrapping_add((b0 as u128) * (b1 as u128));
            i += 2;
        }
    }

    if !remaining.is_multiple_of(16) {
        let mut buf = [0u8; 16];
        let tail_start = m_word_base * 8 + (remaining / 16) * 16;
        let tlen = remaining % 16;
        buf[..tlen].copy_from_slice(&m[tail_start..tail_start + tlen]);
        let ko = full_words; // kptr advanced by 2*(remaining/16) words
        let a0 = get64le(&buf, 0).wrapping_add(kp[ko]);
        let a1 = get64le(&buf, 1).wrapping_add(kp[ko + 1]);
        acc = acc.wrapping_add((a0 as u128) * (a1 as u128));
        let b0 = get64le(&buf, 0).wrapping_add(kp[ko + 2]);
        let b1 = get64le(&buf, 1).wrapping_add(kp[ko + 3]);
        acc2 = acc2.wrapping_add((b0 as u128) * (b1 as u128));
    }

    (
        (acc >> 64) as u64,
        acc as u64,
        (acc2 >> 64) as u64,
        acc2 as u64,
    )
}

/// Poly128 multiply-reduce step (`poly_step` from the VMAC_ARCH_64 path).
#[inline]
fn poly_step(ah: &mut u64, al: &mut u64, kh: u64, kl: u64, mh: u64, ml: u64) {
    let a = *ah;
    let l = *al;

    let (t3h, t3l) = mul128(l, kh);
    let (t2h, t2l) = mul128(a, kl);
    let (t1h, t1l) = mul128(a, kh.wrapping_mul(2));
    let (mut ahi, mut alo) = mul128(l, kl);

    add128(&mut ahi, &mut alo, t1h, t1l);

    let mut t2h = t2h;
    let mut t2l = t2l;
    add128(&mut t2h, &mut t2l, t3h, t3l);
    add128(&mut t2h, &mut ahi, 0, t2l);

    let t2hv = t2h.wrapping_mul(2).wrapping_add(ahi >> 63);
    ahi &= M63;

    add128(&mut ahi, &mut alo, mh, ml);
    add128(&mut ahi, &mut alo, 0, t2hv);

    *ah = ahi;
    *al = alo;
}

/// L3 hash (`l3hash`), reducing the two L2 accumulators and mixing keys.
#[inline]
fn l3hash(p1: u64, p2: u64, k1: u64, k2: u64, len: u64) -> u64 {
    let mut p1 = p1;
    let mut p2 = p2;

    let t = p1 >> 63;
    p1 &= M63;
    {
        let mut rh = p1;
        let mut rl = p2;
        add128(&mut rh, &mut rl, len, t);
        p1 = rh;
        p2 = rl;
    }
    let t = (p1 > M63) as u64 + ((p1 == M63) && (p2 == M64)) as u64;
    {
        let mut rh = p1;
        let mut rl = p2;
        add128(&mut rh, &mut rl, 0, t);
        p1 = rh;
        p2 = rl;
    }
    p1 &= M63;

    let mut t = p1.wrapping_add(p2 >> 32);
    t = t.wrapping_add(t >> 32);
    t = t.wrapping_add((t as u32 > 0xffff_fffe) as u64);
    p1 = p1.wrapping_add(t >> 32);
    p2 = p2.wrapping_add(p1 << 32);

    p1 = p1.wrapping_add(k1);
    p1 = p1.wrapping_add(0u64.wrapping_sub((p1 < k1) as u64) & 257);
    p2 = p2.wrapping_add(k2);
    p2 = p2.wrapping_add(0u64.wrapping_sub((p2 < k2) as u64) & 257);

    let (rh, rl) = mul128(p1, p2);
    let mut rl = rl;
    let mut t = rh >> 56;
    add128(&mut t, &mut rl, 0, rh);
    let rh_shl = rh.wrapping_shl(8);
    add128(&mut t, &mut rl, 0, rh_shl);
    t = t.wrapping_add(t << 8);
    rl = rl.wrapping_add(t);
    rl = rl.wrapping_add(0u64.wrapping_sub((rl < t) as u64) & 257);
    rl = rl.wrapping_add(0u64.wrapping_sub((rl > P64 - 1) as u64) & 257);
    rl
}

/// The `vmac_ctx_t` key material: 514 NH key words, 4 polykey, 4 l3key words.
#[derive(Clone)]
pub struct VmacCtx {
    nhkey: [u64; 514],
    polykey: [u64; 4],
    l3key: [u64; 4],
}

fn aes_encrypt_block(cipher: &Aes256, input: &[u8; 16]) -> [u8; 16] {
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// `vmac_set_key`: derive nhkey/polykey/l3key from a 32-byte user key via AES-256.
pub fn vmac_set_key(user_key: &[u8; 32]) -> VmacCtx {
    let cipher = Aes256::new_from_slice(user_key).expect("AES-256 key is 32 bytes");

    let mut nhkey = [0u64; 514];
    let mut polykey = [0u64; 4];
    let mut l3key = [0u64; 4];

    // Fill nh key: in = {0x80,0,...,0}, counter in byte 15.
    let mut inn = [0u8; 16];
    inn[0] = 0x80;
    let mut i = 0usize;
    while i < 514 {
        let out = aes_encrypt_block(&cipher, &inn);
        nhkey[i] = get64be(&out);
        nhkey[i + 1] = get64be(&out[8..]);
        inn[15] = inn[15].wrapping_add(1);
        i += 2;
    }

    // Fill poly key: in = {0xC0,0,...,0}.
    inn = [0u8; 16];
    inn[0] = 0xC0;
    let mut i = 0usize;
    while i < 4 {
        let out = aes_encrypt_block(&cipher, &inn);
        polykey[i] = get64be(&out) & MPOLY;
        polykey[i + 1] = get64be(&out[8..]) & MPOLY;
        inn[15] = inn[15].wrapping_add(1);
        i += 2;
    }

    // Fill l3 key: in = {0xE0,0,...,0}; reject words >= p64.
    inn = [0u8; 16];
    inn[0] = 0xE0;
    let mut i = 0usize;
    while i < 4 {
        loop {
            let out = aes_encrypt_block(&cipher, &inn);
            l3key[i] = get64be(&out);
            l3key[i + 1] = get64be(&out[8..]);
            inn[15] = inn[15].wrapping_add(1);
            if l3key[i] < P64 && l3key[i + 1] < P64 {
                break;
            }
        }
        i += 2;
    }

    VmacCtx {
        nhkey,
        polykey,
        l3key,
    }
}

/// `vhash`: the full (non-incremental) VHASH-128 over `m`. Entry is always taken
/// with `first_block_processed == 0` in SREP. Returns (res, tagl).
pub fn vhash(ctx: &VmacCtx, m: &[u8]) -> (u64, u64) {
    let kp = &ctx.nhkey;
    let pkh = ctx.polykey[0];
    let pkl = ctx.polykey[1];
    let pkh2 = ctx.polykey[2];
    let pkl2 = ctx.polykey[3];

    let mbytes = m.len();
    let nblocks = mbytes / VMAC_NHBYTES;
    let remaining = mbytes % VMAC_NHBYTES;
    let remaining_bits = (remaining * 8) as u64;

    let mut ch: u64;
    let mut cl: u64;
    let mut ch2: u64;
    let mut cl2: u64;

    if nblocks > 0 {
        // First full 4096-byte block, then add the poly key.
        let (rh, rl, rh2, rl2) = nh_vmac_nhbytes_2(m, 0, kp);
        let mut c = rh & M62;
        let mut cl_ = rl;
        let mut c2 = rh2 & M62;
        let mut cl2_ = rl2;
        add128(&mut c2, &mut cl2_, pkh2, pkl2);
        add128(&mut c, &mut cl_, pkh, pkl);
        ch = c;
        cl = cl_;
        ch2 = c2;
        cl2 = cl2_;
        let mut nb = nblocks - 1;
        let mut word_off = VMAC_NHBYTES / 8;
        while nb > 0 {
            let (rh, rl, rh2, rl2) = nh_vmac_nhbytes_2(m, word_off, kp);
            let rh = rh & M62;
            let rh2 = rh2 & M62;
            poly_step(&mut ch, &mut cl, pkh, pkl, rh, rl);
            poly_step(&mut ch2, &mut cl2, pkh2, pkl2, rh2, rl2);
            word_off += VMAC_NHBYTES / 8;
            nb -= 1;
        }
        if remaining > 0 {
            let (rh, rl, rh2, rl2) = nh_tail(m, word_off, kp, remaining);
            let rh = rh & M62;
            let rh2 = rh2 & M62;
            poly_step(&mut ch, &mut cl, pkh, pkl, rh, rl);
            poly_step(&mut ch2, &mut cl2, pkh2, pkl2, rh2, rl2);
        }
    } else if remaining > 0 {
        // Entire message is under 4096 bytes: NH then add the poly key (no poly_step).
        let (rh, rl, rh2, rl2) = nh_tail(m, 0, kp, remaining);
        let mut c = rh & M62;
        let mut cl_ = rl;
        let mut c2 = rh2 & M62;
        let mut cl2_ = rl2;
        add128(&mut c2, &mut cl2_, pkh2, pkl2);
        add128(&mut c, &mut cl_, pkh, pkl);
        ch = c;
        cl = cl_;
        ch2 = c2;
        cl2 = cl2_;
    } else {
        // Empty string.
        ch = pkh;
        cl = pkl;
        ch2 = pkh2;
        cl2 = pkl2;
    }

    let tagl = l3hash(ch2, cl2, ctx.l3key[2], ctx.l3key[3], remaining_bits);
    let res = l3hash(ch, cl, ctx.l3key[0], ctx.l3key[1], remaining_bits);
    (res, tagl)
}

// ==== Higher-level wrappers used by checksum/mod.rs ====

/// Stateful VHash object: persistent key, stateless compute (matches `VHash`).
#[derive(Clone)]
pub struct VHash {
    ctx: VmacCtx,
}

impl VHash {
    /// `init(None)` on the reference generates a random key; SREP uses a fixed
    /// all-zero key in Rust because match decisions are key-independent.
    pub fn new() -> VHash {
        VHash {
            ctx: vmac_set_key(&[0u8; 32]),
        }
    }

    pub fn new_with_key(key: &[u8; 32]) -> VHash {
        VHash {
            ctx: vmac_set_key(key),
        }
    }

    /// Write the 16-byte VMAC-128 tag to `result[0..16]` (res, then tagl as LE).
    pub fn compute(&self, data: &[u8], result: &mut [u8]) {
        let (res, tagl) = vhash(&self.ctx, data);
        result[0..8].copy_from_slice(&res.to_le_bytes());
        result[8..16].copy_from_slice(&tagl.to_le_bytes());
    }
}

impl Default for VHash {
    fn default() -> Self {
        Self::new()
    }
}

/// `VDigest`: two VHash instances sharing one key; 20-byte digest output.
#[derive(Clone)]
pub struct VDigest {
    vhash1: VHash,
    vhash2: VHash,
}

impl VDigest {
    pub fn new() -> VDigest {
        let vhash1 = VHash::new();
        let vhash2 = vhash1.clone();
        VDigest { vhash1, vhash2 }
    }

    /// Write 20 bytes: vhash1 tag at [0..16], vhash2 tag at [4..20].
    pub fn compute(&self, data: &[u8], result: &mut [u8]) {
        self.vhash1.compute(data, result);
        let mut second = [0u8; 16];
        self.vhash2.compute(data, &mut second);
        result[4..20].copy_from_slice(&second);
    }
}

impl Default for VDigest {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // Differential vector captured from `bin/srep -m3 -hash=vmac` on this host:
    // the 16-byte block checksum is `vhash(input, 109)` under the seed stored in
    // the archive header. Oracle-grounded proof that vmac_set_key/vhash reproduce
    // the reference bit-for-bit.
    #[test]
    fn reproduces_oracle_vmac_vector() {
        let seed: [u8; 32] = [
            0x6a, 0x75, 0x4d, 0x07, 0x61, 0xa4, 0x16, 0xf1, 0xb7, 0xb6, 0x29, 0xc3, 0x1c, 0xea,
            0x7b, 0xb2, 0x43, 0x96, 0x06, 0x75, 0x43, 0x0b, 0x39, 0xb1, 0x1a, 0x9c, 0x56, 0x6e,
            0x89, 0xab, 0xd3, 0xc6,
        ];
        let input = b"The quick brown fox jumps over the lazy dog. 0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let ctx = vmac_set_key(&seed);
        let (res, tagl) = vhash(&ctx, input);
        assert_eq!(res, 0x8ab3d0d5c8b5f4f1u64);
        assert_eq!(tagl, 0x7bf1957cbfac8c82u64);
    }

    // Exercises the full-block (nh_vmac_nhbytes_2) + poly_step + tail path.
    #[test]
    fn reproduces_oracle_vmac_vector_multiblock() {
        use sha2::{Digest as _, Sha256};
        let mut input = Vec::new();
        let mut i = 0u8;
        while input.len() < 9000 {
            input.extend_from_slice(&Sha256::digest(vec![i; 64]));
            i = i.wrapping_add(1);
        }
        input.truncate(9000);
        let seed: [u8; 32] = [
            0x47, 0x86, 0x41, 0xfb, 0x70, 0x87, 0xc9, 0x78, 0x38, 0xf9, 0x8e, 0xdb, 0x46, 0xe4,
            0xa8, 0x9e, 0x16, 0x83, 0x32, 0xc7, 0xc8, 0xa2, 0x6a, 0x3f, 0x23, 0x13, 0x64, 0x6a,
            0x47, 0x08, 0xf3, 0xe6,
        ];
        let ctx = vmac_set_key(&seed);
        let (res, tagl) = vhash(&ctx, &input);
        assert_eq!(res, 0xba1296df06639e0fu64);
        assert_eq!(tagl, 0x6f6c12f34628a8d0u64);
    }
}
