#!/usr/bin/env bash
# Compatibility gate for the reference SREP binary and srep-rs.
#
# Every compression case is checked in both directions:
#   1. reference and Rust compression must succeed;
#   2. deterministic archives must be byte-for-byte identical;
#   3. each archive is decoded by both implementations;
#   4. all four decoded files must be byte-for-byte identical to the input.
#
# The VMAC/SipHash seed is random but serialized in the archive. We copy the
# reference seed into srep-rs with --checksum-seed, making those archives
# deterministic too. Methods m1/m2 have an additional private random CDC key,
# so their compressed bytes are intentionally not compared; their four
# cross-decoding checks still have to pass.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORACLE="$ROOT/legacy/bin/srep"
RS="$ROOT/target/release/srep-rs"
WORK="$(mktemp -d)"
PASS=0
FAIL=0
SKIP=0
CASE=0

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

pass() { PASS=$((PASS + 1)); }
skip() { SKIP=$((SKIP + 1)); }
fail() {
  echo "FAIL: $*"
  FAIL=$((FAIL + 1))
}

run_logged() {
  local label="$1"
  shift
  if "$@" 2>"$WORK/command.stderr"; then
    pass
    return 0
  fi
  fail "$label"
  sed -n '1,8p' "$WORK/command.stderr" | sed 's/^/  /'
  return 1
}

same_as_source() {
  local label="$1"
  local source_file="$2"
  local decoded_file="$3"
  if cmp -s "$source_file" "$decoded_file"; then
    pass
    return 0
  fi
  local source_size
  local decoded_size
  source_size="$(wc -c <"$source_file" | tr -d ' ')"
  decoded_size="$(wc -c <"$decoded_file" 2>/dev/null | tr -d ' ')"
  fail "$label (source=$source_size bytes, decoded=$decoded_size bytes)"
  return 1
}

checksum_seed_size() {
  # The default checksum is VMAC. Later checksum options override earlier ones.
  local seed_size=32
  local option
  for option in "$@"; do
    case "$option" in
      -hash-|-nomd5|-hash=md5|-hash=sha1|-hash=sha512) seed_size=0 ;;
      -hash=vmac) seed_size=32 ;;
      -hash=siphash) seed_size=16 ;;
    esac
  done
  echo "$seed_size"
}

compress_case() {
  local label="$1"
  local source_file="$2"
  local exact_archive="$3"
  shift 3
  local options=("$@")
  local ref_archive rust_archive ref_ref_out ref_rust_out rust_ref_out rust_rust_out
  local seed_size seed first_difference
  CASE=$((CASE + 1))

  ref_archive="$WORK/ref-$CASE.srep"
  rust_archive="$WORK/rust-$CASE.srep"
  ref_ref_out="$WORK/ref-ref-$CASE.out"
  ref_rust_out="$WORK/ref-rust-$CASE.out"
  rust_ref_out="$WORK/rust-ref-$CASE.out"
  rust_rust_out="$WORK/rust-rust-$CASE.out"

  if ! run_logged "$label: reference compression" \
      "$ORACLE" "${options[@]}" "$source_file" "$ref_archive"; then
    return
  fi

  seed_size="$(checksum_seed_size "${options[@]}")"
  if [ "$seed_size" -ne 0 ]; then
    seed="$(xxd -p -s 16 -l "$seed_size" "$ref_archive" | tr -d '\n')"
    if [ "${#seed}" -ne $((seed_size * 2)) ]; then
      fail "$label: could not read the serialized checksum seed"
      return
    fi
    if ! run_logged "$label: Rust compression" \
        "$RS" "${options[@]}" "--checksum-seed=$seed" "$source_file" "$rust_archive"; then
      return
    fi
  else
    if ! run_logged "$label: Rust compression" \
        "$RS" "${options[@]}" "$source_file" "$rust_archive"; then
      return
    fi
  fi

  if [ "$exact_archive" = yes ]; then
    if cmp -s "$ref_archive" "$rust_archive"; then
      pass
    else
      first_difference="$(cmp -l "$ref_archive" "$rust_archive" 2>/dev/null | sed -n '1p')"
      fail "$label: compressed archives differ${first_difference:+ (first difference: $first_difference)}"
    fi
  else
    # m1/m2 use a private, per-process random CDC key. This is the one check
    # that cannot be made deterministic from the command line/archive.
    skip
  fi

  if run_logged "$label: reference decodes reference archive" \
      "$ORACLE" -d "$ref_archive" "$ref_ref_out"; then
    same_as_source "$label: reference/reference round trip" "$source_file" "$ref_ref_out"
  fi
  if run_logged "$label: Rust decodes reference archive" \
      "$RS" -d "$ref_archive" "$ref_rust_out"; then
    same_as_source "$label: reference/Rust round trip" "$source_file" "$ref_rust_out"
  fi
  if run_logged "$label: reference decodes Rust archive" \
      "$ORACLE" -d "$rust_archive" "$rust_ref_out"; then
    same_as_source "$label: Rust/reference round trip" "$source_file" "$rust_ref_out"
  fi
  if run_logged "$label: Rust decodes Rust archive" \
      "$RS" -d "$rust_archive" "$rust_rust_out"; then
    same_as_source "$label: Rust/Rust round trip" "$source_file" "$rust_rust_out"
  fi
}

decode_option_case() {
  local label="$1"
  local source_file="$2"
  local archive="$3"
  shift 3
  local ref_decoded rust_decoded
  CASE=$((CASE + 1))
  ref_decoded="$WORK/ref-decode-option-$CASE.out"
  rust_decoded="$WORK/rust-decode-option-$CASE.out"
  if run_logged "$label: reference decode" "$ORACLE" -d "$@" "$archive" "$ref_decoded"; then
    same_as_source "$label: reference decoded bytes" "$source_file" "$ref_decoded"
  fi
  if run_logged "$label: Rust decode" "$RS" -d "$@" "$archive" "$rust_decoded"; then
    same_as_source "$label: Rust decoded bytes" "$source_file" "$rust_decoded"
  fi
  if cmp -s "$ref_decoded" "$rust_decoded"; then
    pass
  else
    fail "$label: reference and Rust decoded files differ"
  fi
}

rust_decode_case() {
  local label="$1"
  local source_file="$2"
  local archive="$3"
  shift 3
  CASE=$((CASE + 1))
  local decoded="$WORK/rust-decode-option-$CASE.out"
  if run_logged "$label: Rust decode" "$RS" -d "$@" "$archive" "$decoded"; then
    same_as_source "$label: Rust decoded bytes" "$source_file" "$decoded"
  fi
}

if [ ! -x "$ORACLE" ]; then
  echo "oracle missing: $ORACLE" >&2
  echo "build it for this architecture with:" >&2
  echo "  make -C \"$ROOT/legacy\"" >&2
  exit 2
fi
if [ ! -x "$RS" ]; then
  echo "srep-rs missing: run cargo build --release" >&2
  exit 2
fi

python3 "$ROOT/scripts/gen-corpus.py" "$WORK/data" >/dev/null
# Keep all default VM/temp files inside the disposable directory too.
cd "$WORK" || exit 2

echo "== method/layout/boundary matrix =="
for name in empty.bin one-byte.bin len511.bin len512.bin len513.bin text.txt zero-4mb.bin rand-4mb.bin repeat-4mb.bin; do
  source_file="$WORK/data/$name"
  for method in m0 m1 m2 m3 m4 m5; do
    case "$method" in m1|m2) exact=no ;; *) exact=yes ;; esac
    for layout in "" f o; do
      compress_case "$name -$method$layout" "$source_file" "$exact" \
        "-$method$layout"
    done
  done
done

echo "== checksum matrix =="
source_file="$WORK/data/text.txt"
for method in m0 m1 m2 m3 m4 m5; do
  case "$method" in m1|m2) exact=no ;; *) exact=yes ;; esac
  for checksum in -hash- -nomd5 -hash=md5 -hash=sha1 -hash=sha512 -hash=vmac -hash=siphash; do
    compress_case "text.txt -$method $checksum" "$source_file" "$exact" \
      "-$method" "$checksum"
  done
done

echo "== compression parameter matrix =="
source_file="$WORK/data/repeat-4mb.bin"
# Representative values for every compression parameter supported by srep-rs.
# Cross-products already covered above are not repeated here.
compress_case "method alias -mx"             "$source_file" yes -mx -hash-
compress_case "layout alias -f"              "$source_file" yes -m4 -f -hash-
compress_case "minimum match -l1k"           "$source_file" yes -m3 -l1k -hash-
compress_case "chunk/min match -c1k -l2k"    "$source_file" yes -m3 -c1k -l2k -hash-
compress_case "m4 chunk/min match"           "$source_file" yes -m4 -c256 -l1k -hash-
compress_case "m5 chunk/min match"           "$source_file" yes -m5 -c128 -l1k -hash-
compress_case "m1 chunk/min match"           "$source_file" no  -m1 -c1k -l32 -hash-
compress_case "m2 chunk/min match"           "$source_file" no  -m2 -c1k -l32 -hash-
compress_case "small blocks -b512k"          "$source_file" yes -m3 -b512k -hash-
compress_case "multi blocks -b2m"            "$source_file" yes -m4 -b2m -hash-
compress_case "dictionary disabled -d-"      "$source_file" yes -m3 -d- -hash-
compress_case "dictionary size -d1m"         "$source_file" yes -m3 -d1m -hash-
compress_case "dictionary m4 -d1m"           "$source_file" yes -m4 -d1m -hash-
compress_case "dictionary m5 -d1m"           "$source_file" yes -m5 -d1m -hash-
compress_case "dictionary sub-options"       "$source_file" yes -m3 -d1m:h1m:c128:l1k:a1 -hash-

echo "== decompression parameter matrix =="
# Build small-block future/index archives once, then vary every decoder tuning
# option. Tiny -mem values exercise VM spill instead of merely parsing flags.
future_archive="$WORK/future-options.srep"
index_archive="$WORK/index-options.srep"
"$ORACLE" -m4f -b512k -hash- "$source_file" "$future_archive" 2>/dev/null \
  || fail "decoder fixture: future archive"
"$ORACLE" -m4 -b512k -hash- "$source_file" "$index_archive" 2>/dev/null \
  || fail "decoder fixture: index archive"

decode_option_case "decode -hash-"             "$source_file" "$index_archive" -hash-
decode_option_case "decode buffer -b512k"      "$source_file" "$index_archive" -b512k
decode_option_case "decode memory bytes"       "$source_file" "$future_archive" -mem1m
decode_option_case "decode memory percent"     "$source_file" "$future_archive" -mem25%
decode_option_case "decode maximum save"       "$source_file" "$future_archive" -m1k
# The reference parser consumes -vmblock/-vmfile as malformed -v options, so
# these documented settings can only be exercised on the Rust implementation.
rust_decode_case "decode VM block/file"        "$source_file" "$future_archive" \
  -mem1m -vmblock=1m "-vmfile=$WORK/custom-vm.tmp"
decode_option_case "decode named temp"         "$source_file" "$index_archive" \
  "-temp=$WORK/unused-regular-file.tmp"

echo "== stdin/stdout and implicit-file matrix =="
pipe_source="$WORK/data/text.txt"
normal_archive="$WORK/normal-pipe.srep"
stdin_archive="$WORK/stdin-pipe.srep"
implicit_archive="$WORK/implicit-pipe.srep"
pipe_out="$WORK/pipe.out"
implicit_out="$WORK/implicit.out"
"$RS" -m3 -hash- "$pipe_source" "$normal_archive" 2>"$WORK/command.stderr" \
  && pass || fail "transport fixture compression"
"$RS" -m3 -hash- - - <"$pipe_source" >"$stdin_archive" 2>"$WORK/command.stderr" \
  && pass || fail "explicit stdin/stdout compression"
cmp -s "$normal_archive" "$stdin_archive" \
  && pass || fail "explicit stdin/stdout compressed bytes"
"$RS" -m3 -hash- <"$pipe_source" >"$implicit_archive" 2>"$WORK/command.stderr" \
  && pass || fail "implicit stdin/stdout compression"
cmp -s "$normal_archive" "$implicit_archive" \
  && pass || fail "implicit stdin/stdout compressed bytes"
"$RS" -d "-temp=$WORK/explicit-spool.tmp" - - <"$normal_archive" >"$pipe_out" 2>"$WORK/command.stderr" \
  && pass || fail "explicit stdin/stdout decompression"
same_as_source "explicit stdin/stdout decompressed bytes" "$pipe_source" "$pipe_out"
"$RS" -d "-temp=$WORK/implicit-spool.tmp" <"$normal_archive" >"$implicit_out" 2>"$WORK/command.stderr" \
  && pass || fail "implicit stdin/stdout decompression"
same_as_source "implicit stdin/stdout decompressed bytes" "$pipe_source" "$implicit_out"
if [ ! -e "$WORK/explicit-spool.tmp" ] && [ ! -e "$WORK/implicit-spool.tmp" ]; then
  pass
else
  fail "stdin/stdout temporary files were not cleaned up"
fi

echo
echo "CASES=$CASE PASS=$PASS SKIP=$SKIP FAIL=$FAIL"
if [ "$SKIP" -ne 0 ]; then
  echo "SKIP is compressed-byte comparison for m1/m2 only (private random CDC key)."
fi
[ "$FAIL" -eq 0 ]
