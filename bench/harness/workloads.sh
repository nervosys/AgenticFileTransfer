#!/bin/bash
# workloads.sh -- generate the benchmark corpus.
#
# Content is reproducible pseudo-random (AES-CTR keystream over a fixed
# passphrase), NOT /dev/zero. Zero-filled or otherwise compressible data would
# unfairly flatter any tool with compression enabled and would make on-the-wire
# byte counts meaningless.
set -euo pipefail

ROOT=${1:-${BENCH_ROOT:-$HOME/aft-bench}/data}

# Deterministic incompressible stream of $1 bytes seeded by label $2.
prand() {
  local bytes=$1 seed=$2
  # Bound the INPUT rather than the output: piping unbounded openssl into
  # `head -c` kills openssl with SIGPIPE, which pipefail then turns into a
  # spurious script failure. AES-CTR is a stream cipher, so out_len == in_len.
  head -c "$bytes" /dev/zero \
    | openssl enc -aes-256-ctr -pass "pass:aft-bench-$seed" -nosalt 2>/dev/null
}

mkfile() { # path bytes seed
  [ -f "$1" ] && [ "$(stat -c%s "$1")" = "$2" ] && return 0
  mkdir -p "$(dirname "$1")"
  prand "$2" "$3" > "$1"
}

mktree() { # dir count bytes-each seedbase
  local dir=$1 count=$2 each=$3 seed=$4
  if [ -d "$dir" ] && [ "$(find "$dir" -type f | wc -l)" = "$count" ]; then return 0; fi
  rm -rf "$dir"; mkdir -p "$dir"
  # One keystream carved into $count slices: fast, still incompressible, and
  # every file has distinct content.
  local total=$((count * each))
  prand "$total" "$seed" > "$dir/.blob"
  local i=0
  while [ $i -lt "$count" ]; do
    # fan out over subdirs so no single directory has 2000 entries
    local sub=$((i / 100))
    mkdir -p "$dir/d$sub"
    dd if="$dir/.blob" of="$dir/d$sub/f$i.bin" bs="$each" skip=$i count=1 \
       status=none
    i=$((i + 1))
  done
  rm -f "$dir/.blob"
}

mkdir -p "$ROOT"

mkfile "$ROOT/small_500k/file.bin"  $((500 * 1024))        s500k
mkfile "$ROOT/single_50m/file.bin"  $((50 * 1024 * 1024))  s50m
mkfile "$ROOT/single_500m/file.bin" $((500 * 1024 * 1024)) s500m
mktree "$ROOT/tree_2000x1k"  2000 1024              t2000
mktree "$ROOT/tree_400x1m"   400  $((1024 * 1024))  t400

echo "workloads under $ROOT:"
du -sh "$ROOT"/* | sed 's/^/  /'
find "$ROOT" -type f | wc -l | xargs echo "  total files:"
