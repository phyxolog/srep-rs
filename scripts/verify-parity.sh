#!/usr/bin/env bash
# Byte-parity gate: bin/srep (reference oracle) vs target/release/srep-rs.
#
# Deterministic methods (m0 m3 m4 m5) are byte-compared across layouts and
# checksums. m1/m2 (CDC) are excluded from *compression* byte-parity: the
# reference derives its CDC chunk digest/index from a per-run random key, so its
# m1/m2 output is not reproducible run-to-run. m1/m2 decode round-trip parity is
# still asserted.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ORACLE="$ROOT/bin/srep"
RS="$ROOT/srep-rs/target/release/srep-rs"
WORK="$(mktemp -d)"
PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); }
fail() { echo "FAIL: $*"; FAIL=$((FAIL + 1)); }

if [ ! -x "$ORACLE" ]; then echo "oracle missing; run make"; exit 2; fi
if [ ! -x "$RS" ]; then echo "srep-rs missing; run cargo build --release"; exit 2; fi

python3 "$ROOT/srep-rs/scripts/gen-corpus.py" "$WORK/data" >/dev/null

DMODE="m0 m3 m4 m5"
ALL="m0 m1 m2 m3 m4 m5"

# ----------------------------------------------------------------------------
# 1. Decompression parity: every oracle-produced archive decodes byte-identically.
# ----------------------------------------------------------------------------
echo "== decompression parity =="
for f in empty.bin one-byte.bin len511.bin len512.bin len513.bin text.txt zero-4mb.bin rand-4mb.bin repeat-4mb.bin; do
  src="$WORK/data/$f"
  for m in $ALL; do
    for layout in "" f o; do
      "$ORACLE" "-$m$layout" -hash- "$src" "$WORK/ref.srep" 2>/dev/null \
        || { fail "oracle $m$layout $f"; continue; }
      "$RS" -d "$WORK/ref.srep" "$WORK/dec.bin" 2>/dev/null \
        || { fail "decode $m$layout $f"; continue; }
      cmp -s "$src" "$WORK/dec.bin" && pass || fail "decode-bytes $m$layout $f"
    done
  done
done

# Multi-block decode (small -b forces cross-block history).
echo "== multi-block decompression parity =="
for bsz in 512k 2m; do
  for f in repeat-4mb.bin rand-4mb.bin; do
    src="$WORK/data/$f"
    "$ORACLE" -m3 -hash- -b"$bsz" "$src" "$WORK/ref.srep" 2>/dev/null
    "$RS" -d "$WORK/ref.srep" "$WORK/dec.bin" 2>/dev/null
    cmp -s "$src" "$WORK/dec.bin" && pass || fail "multiblock $bsz $f"
  done
done

# ----------------------------------------------------------------------------
# 2. Cross-decode: srep-rs archives decoded by the oracle.
# ----------------------------------------------------------------------------
echo "== cross-decode parity =="
for f in text.txt repeat-4mb.bin rand-4mb.bin; do
  src="$WORK/data/$f"
  for m in $DMODE m1 m2; do
    "$RS" "-$m" -hash- "$src" "$WORK/my.srep" 2>/dev/null \
      || { fail "compress $m $f"; continue; }
    "$ORACLE" -d "$WORK/my.srep" "$WORK/dec.bin" 2>/dev/null \
      || { fail "oracle-decode $m $f"; continue; }
    cmp -s "$src" "$WORK/dec.bin" && pass || fail "cross-decode $m $f"
  done
done

# ----------------------------------------------------------------------------
# 3. Compression parity, deterministic modes + layouts + checksums.
# ----------------------------------------------------------------------------
echo "== compression parity (deterministic) =="
for f in empty.bin one-byte.bin len512.bin text.txt repeat-4mb.bin rand-4mb.bin; do
  src="$WORK/data/$f"
  for m in $DMODE; do
    for layout in "" f o; do
      for hash in -hash- -hash=md5 -hash=sha1 -hash=sha512; do
        "$ORACLE" "-$m$layout" "$hash" "$src" "$WORK/ref.srep" 2>/dev/null \
          && "$RS" "-$m$layout" "$hash" "$src" "$WORK/out.srep" 2>/dev/null \
          && { cmp -s "$WORK/ref.srep" "$WORK/out.srep" && pass || fail "$m$layout $hash $f"; }
      done
    done
  done
done

# ----------------------------------------------------------------------------
# 3b. Compression parity, dictionary (hybrid -d) modes.
# ----------------------------------------------------------------------------
echo "== compression parity (hybrid -d) =="
for f in text.txt repeat-4mb.bin; do
  src="$WORK/data/$f"
  for opt in "-m3 -d32m" "-m4f -d32m" "-m5o -d32m"; do
    "$ORACLE" $opt -hash- "$src" "$WORK/ref.srep" 2>/dev/null
    "$RS" $opt -hash- "$src" "$WORK/out.srep" 2>/dev/null
    cmp -s "$WORK/ref.srep" "$WORK/out.srep" && pass || fail "$opt $f"
  done
done

# ----------------------------------------------------------------------------
# 4. Compression parity, keyed modes (vmac/siphash) via seed replay.
# ----------------------------------------------------------------------------
echo "== compression parity (keyed, seed replay) =="
for f in text.txt repeat-4mb.bin; do
  src="$WORK/data/$f"
  for m in $DMODE; do
    for hash in vmac siphash; do
      "$ORACLE" "-$m" "-hash=$hash" "$src" "$WORK/ref.srep" 2>/dev/null || { fail "oracle $m $hash $f"; continue; }
      case "$hash" in vmac) sel=32;; siphash) sel=16;; esac
      seed="$(xxd -p -s 16 -l "$sel" "$WORK/ref.srep" | tr -d '\n')"
      "$RS" "-$m" "-hash=$hash" "--checksum-seed=$seed" "$src" "$WORK/out.srep" 2>/dev/null
      cmp -s "$WORK/ref.srep" "$WORK/out.srep" && pass || fail "$m -hash=$hash $f"
    done
  done
done

rm -f srep-virtual-memory.tmp
echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]