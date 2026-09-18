# srep-rs

`srep-rs` is a research project that rewrites the original SREP preprocessor from C/C++ in Rust.

The aim is compatibility with the original implementation — not a new or
improved compression tool. This port intentionally makes no changes to the compression or decompression logic and does not add further optimizations.

## What SREP does

SREP is a huge-dictionary LZ77 preprocessor. It finds long repeated sequences in the input and represents them as LZ matches, making the result more suitable for subsequent compression. The original implementation supports several match finding methods and archive layouts with different memory and I/O trade-offs.

The original SREP was written by **Bulat Ziganshin**. Its preserved source code, documentation in code, and reference executable are stored in [`legacy/`](legacy/).
In particular, [`legacy/Compression/SREP/srep.cpp`](legacy/Compression/SREP/srep.cpp) is the main reference for the program's behavior, file format, modes, options, and compression/decompression flow.

## Build and use

Build the Rust implementation in release mode:

```sh
cargo build --release
```

Compress a file:

```sh
./target/release/srep-rs input.bin output.srep
```

Decompress an archive:

```sh
./target/release/srep-rs -d output.srep restored.bin
```

## Compatibility verification

The reference implementation used as the compatibility oracle is:

```text
./legacy/bin/srep
```

After building `srep-rs` in release mode, run the parity suite with:

```sh
./scripts/verify-parity.sh
```

The script exercises compression methods, archive layouts, checksums,
parameters, boundary cases, and stream/file operation. For each applicable case it:

1. Compresses the same input with the original SREP and `srep-rs`.
2. Compares deterministic archives byte for byte.
3. Decompresses both archives with both implementations.
4. Verifies every decoded result against the original input.

Methods `-m1` and `-m2` use a private random content-defined chunking key, so their compressed bytes are not expected to be deterministic. Those cases are still verified through cross-decompression in both directions.

This parity suite is the project's compatibility gate: the Rust rewrite is expected to produce archives compatible with the original application while preserving its compression and decompression behavior.

## Project scope

This repository exists for research and implementation-study purposes. It is not an attempt to redesign SREP, introduce a new archive format, change its compression ratio, or optimize the original algorithms. The code under [`legacy/`](legacy/) remains the authoritative reference for the original SREP implementation and retains its original copyright and licensing notices.
