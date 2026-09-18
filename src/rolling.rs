// PolynomialRollingHash<ValueT> from hashes.cpp:130-192. All instantiation
// sites in SREP use ValueT = u64 (BigHash) or ValueT = size_t, and size_t is
// u64 on the 64-bit targets (aarch64/x86-64). All arithmetic wraps exactly like
// the C++ fixed-width unsigned math.

pub const PRIME1: u64 = 153191;
pub const PRIME2: u64 = 3141601;

#[inline]
pub fn power(base: u64, n: u32) -> u64 {
    let mut base = base;
    let mut n = n;
    let mut result: u64 = 1;
    while n != 0 {
        if n % 2 != 0 {
            result = result.wrapping_mul(base);
            n -= 1;
        }
        n /= 2;
        base = base.wrapping_mul(base);
    }
    result
}

#[derive(Clone)]
pub struct PolynomialRollingHash {
    pub value: u64,
    prime: u64,
    prime2: u64,
    prime3: u64,
    prime4: u64,
    _prime5: u64,
    _prime6: u64,
    _prime7: u64,
    _prime8: u64,
    prime_l: u64,
    prime_l1: u64,
    prime_l2: u64,
    prime_l3: u64,
    l: usize,
}

impl PolynomialRollingHash {
    pub fn new(l: usize, seed: u64) -> PolynomialRollingHash {
        // PRIME8 = seed*(PRIME7 = seed*(... = seed*(PRIME = seed))))
        let prime = seed;
        let prime2 = seed.wrapping_mul(prime);
        let prime3 = seed.wrapping_mul(prime2);
        let prime4 = seed.wrapping_mul(prime3);
        let prime5 = seed.wrapping_mul(prime4);
        let prime6 = seed.wrapping_mul(prime5);
        let prime7 = seed.wrapping_mul(prime6);
        let prime8 = seed.wrapping_mul(prime7);
        // PRIME_L3 = seed*(PRIME_L2 = seed*(PRIME_L1 = seed*(PRIME_L = power(PRIME,L))))
        let prime_l = power(prime, l as u32);
        let prime_l1 = seed.wrapping_mul(prime_l);
        let prime_l2 = seed.wrapping_mul(prime_l1);
        let prime_l3 = seed.wrapping_mul(prime_l2);

        PolynomialRollingHash {
            value: 0,
            prime,
            prime2,
            prime3,
            prime4,
            _prime5: prime5,
            _prime6: prime6,
            _prime7: prime7,
            _prime8: prime8,
            prime_l,
            prime_l1,
            prime_l2,
            prime_l3,
            l,
        }
    }

    pub fn with_buffer(buf: &[u8], l: usize, seed: u64) -> PolynomialRollingHash {
        let mut h = PolynomialRollingHash::new(l, seed);
        h.moveto(buf);
        h
    }

    /// Single-byte roll: value = value*PRIME + add - PRIME_L*sub.
    #[inline]
    pub fn update_byte(&mut self, sub: u8, add: u8) {
        self.value = self
            .value
            .wrapping_mul(self.prime)
            .wrapping_add(add as u64)
            .wrapping_sub(self.prime_l.wrapping_mul(sub as u64));
    }

    /// Roll by N bytes (generalized; the C `update<N>` template). `ptr` must be
    /// at least `l + N` bytes readable (callers guarantee this).
    #[inline]
    pub fn update_n<const N: usize>(&mut self, ptr: &[u8]) {
        let l = self.l;
        let m = N % 4;
        match m {
            0 => {}
            1 => {
                self.value = self
                    .value
                    .wrapping_mul(self.prime)
                    .wrapping_add(ptr[l] as u64)
                    .wrapping_sub(self.prime_l.wrapping_mul(ptr[0] as u64));
            }
            2 => {
                self.value = self
                    .value
                    .wrapping_mul(self.prime2)
                    .wrapping_add(self.prime.wrapping_mul(ptr[l] as u64))
                    .wrapping_add(ptr[l + 1] as u64)
                    .wrapping_sub(self.prime_l1.wrapping_mul(ptr[0] as u64))
                    .wrapping_sub(self.prime_l.wrapping_mul(ptr[1] as u64));
            }
            3 => {
                self.value = self
                    .value
                    .wrapping_mul(self.prime3)
                    .wrapping_add(self.prime2.wrapping_mul(ptr[l] as u64))
                    .wrapping_add(self.prime.wrapping_mul(ptr[l + 1] as u64))
                    .wrapping_add(ptr[l + 2] as u64)
                    .wrapping_sub(self.prime_l2.wrapping_mul(ptr[0] as u64))
                    .wrapping_sub(self.prime_l1.wrapping_mul(ptr[1] as u64))
                    .wrapping_sub(self.prime_l.wrapping_mul(ptr[2] as u64));
            }
            _ => unreachable!(),
        }
        let mut off = m;
        while off < N {
            self.value = self
                .value
                .wrapping_mul(self.prime4)
                .wrapping_add(self.prime3.wrapping_mul(ptr[off + l] as u64))
                .wrapping_add(self.prime2.wrapping_mul(ptr[off + l + 1] as u64))
                .wrapping_add(self.prime.wrapping_mul(ptr[off + l + 2] as u64))
                .wrapping_add(ptr[off + l + 3] as u64)
                .wrapping_sub(self.prime_l3.wrapping_mul(ptr[off] as u64))
                .wrapping_sub(self.prime_l2.wrapping_mul(ptr[off + 1] as u64))
                .wrapping_sub(self.prime_l1.wrapping_mul(ptr[off + 2] as u64))
                .wrapping_sub(self.prime_l.wrapping_mul(ptr[off + 3] as u64));
            off += 4;
        }
    }

    /// `moveto`: compute the hash of `buf[0..l]`.
    pub fn moveto(&mut self, buf: &[u8]) {
        self.value = 0;
        let l = self.l;
        let mut i = 0usize;
        while i < l & !15 {
            for j in 0..4 {
                let b = i + j * 4;
                self.value = self
                    .value
                    .wrapping_mul(self.prime4)
                    .wrapping_add(self.prime3.wrapping_mul(buf[b] as u64))
                    .wrapping_add(self.prime2.wrapping_mul(buf[b + 1] as u64))
                    .wrapping_add(self.prime.wrapping_mul(buf[b + 2] as u64))
                    .wrapping_add(buf[b + 3] as u64);
            }
            i += 16;
        }
        while i < l {
            self.value = self.value.wrapping_mul(self.prime).wrapping_add(buf[i] as u64);
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moveto_matches_naive_polynomial() {
        // Hash of a known buffer against the naive definition to catch the
        // batched moveto/update path.
        let buf: Vec<u8> = (0..64u8).collect();
        let l = 8usize;
        let seed = PRIME1;
        let mut h = PolynomialRollingHash::with_buffer(&buf, l, seed);

        let mut naive: u64 = 0;
        for i in 0..l {
            naive = naive.wrapping_mul(seed).wrapping_add(buf[i] as u64);
        }
        assert_eq!(h.value, naive);

        // Roll by 3 bytes.
        h.update_n::<3>(&buf);
        let mut naive2: u64 = 0;
        for i in 3..3 + l {
            naive2 = naive2.wrapping_mul(seed).wrapping_add(buf[i] as u64);
        }
        assert_eq!(h.value, naive2);
    }
}