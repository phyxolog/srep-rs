#!/usr/bin/env python3
"""Deterministically generate the SREP parity corpus into a target directory."""
import hashlib
import os
import sys


def deterministic(seed, size):
    """Deterministic pseudo-random bytes via a counter-seeded SHA-256 stream."""
    out = bytearray()
    i = seed
    while len(out) < size:
        out += hashlib.sha256(i.to_bytes(8, "little") * 8).digest()
        i += 1
    return bytes(out[:size])


def main(outdir):
    os.makedirs(outdir, exist_ok=True)

    def w(name, data):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)

    w("empty.bin", b"")
    w("one-byte.bin", b"\x00")
    for n in (511, 512, 513):
        w(f"len{n}.bin", bytes((i * 251) % 256 for i in range(n)))
    text = (b"The quick brown fox jumps over the lazy dog. " * 4000) \
        + (b"0123456789abcdefghijklmnopqrstuvwxyz\n" * 2000)
    w("text.txt", text)
    w("zero-4mb.bin", b"\x00" * (4 * 1024 * 1024))
    w("rand-4mb.bin", deterministic(1, 4 * 1024 * 1024))
    pat = deterministic(7, 64 * 1024)
    w("repeat-4mb.bin", pat * (4 * 1024 * 1024 // len(pat)))
    print(f"corpus written to {outdir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/data")