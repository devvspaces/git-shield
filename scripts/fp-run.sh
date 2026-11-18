#!/usr/bin/env bash
# False-positive budget run: scan the last N commits of popular public repos.
# Usage: scripts/fp-run.sh <work-dir> [commits]
# Clones are shallow and --no-checkout: nothing from these repos is ever
# checked out or executed. Target: 0 High/Critical findings.
set -euo pipefail
WORK=${1:?work dir}
N=${2:-300}
BIN=${GIT_SHIELD_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/git-shield}
REPOS=(
  microsoft/vscode
  facebook/react
  vercel/next.js
  django/django
  rust-lang/cargo
  kubernetes/kubernetes
  langchain-ai/langchain
  supabase/supabase
  home-assistant/core
  anthropics/claude-code
)
mkdir -p "$WORK"
export GIT_SHIELD_HOME="$WORK/.shield-home" GIT_SHIELD_CONFIG="$WORK/none.toml"
printf '%-28s %6s %6s %5s %5s %5s %5s %5s\n' repo commits ms crit high med low info
for r in "${REPOS[@]}"; do
  d="$WORK/${r//\//__}"
  if [ ! -d "$d" ]; then
    git -c core.hooksPath=/dev/null clone -q --no-checkout --single-branch --depth $((N + 1)) "https://github.com/$r.git" "$d"
  fi
  start=$(python3 -c 'import time; print(int(time.time()*1000))')
  "$BIN" scan -C "$d" "HEAD~$N..HEAD" --json > "$d.json" 2>/dev/null || true
  end=$(python3 -c 'import time; print(int(time.time()*1000))')
  python3 - "$r" "$d.json" $((end - start)) <<'PY'
import json, sys, collections
r, path, ms = sys.argv[1], sys.argv[2], sys.argv[3]
v = json.load(open(path))
c = collections.Counter(f["severity"] for f in v["findings"])
print(f'{r:<28} {v["commits_scanned"]:>6} {ms:>6} {c["critical"]:>5} {c["high"]:>5} {c["medium"]:>5} {c["low"]:>5} {c["info"]:>5}')
for f in v["findings"]:
    if f["severity"] in ("critical", "high"):
        print(f'    {f["severity"].upper():8} {f["rule"]:32} {f.get("path","")}  {f["title"][:70]}')
PY
done
