#!/usr/bin/env bash
# Time `git shield scan` on a real repository and range (read-only).
#   scripts/bench-real.sh <repo> <range> [runs]
# e.g. scripts/bench-real.sh ~/src/linux v6.9..v6.10
# Uses hyperfine when installed, else a plain loop. Results go into
# docs/PROGRESS.md by hand; this is not run in CI.
set -euo pipefail
repo=${1:?repo path}
range=${2:?revision range}
runs=${3:-5}
here=$(cd "$(dirname "$0")/.." && pwd)
cargo build --release --locked -p git-shield --manifest-path "$here/Cargo.toml" >&2
bin="$here/target/release/git-shield"
cmd=("$bin" scan "$range" -C "$repo" --json)
echo "git-shield $("$bin" --version | cut -d' ' -f2) · $(git -C "$repo" rev-list --count "$range") commits in $range" >&2
if command -v hyperfine >/dev/null; then
  hyperfine --warmup 1 --runs "$runs" -i "$(printf '%q ' "${cmd[@]}")"
else
  for _ in $(seq "$runs"); do
    start=$(date +%s.%N 2>/dev/null || python3 -c 'import time;print(time.time())')
    "${cmd[@]}" >/dev/null || true
    end=$(date +%s.%N 2>/dev/null || python3 -c 'import time;print(time.time())')
    echo "$end - $start" | bc
  done | sort -n | awk '{a[NR]=$1} END {printf "runs %d  min %.3fs  median %.3fs  max %.3fs\n", NR, a[1], a[int((NR+1)/2)], a[NR]}'
fi
