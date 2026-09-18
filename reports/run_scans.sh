#!/bin/bash
# Polite bulk scan loop: one read-only scan per endpoint, single retry on failure.
#
# READ-ONLY BY DESIGN. Write-performing detectors (open-dcr) are off unless a scan is given
# --unsafe-writes, and this script never passes it. An earlier version of this file passed
# neither --safe nor --tier, so running it as documented performed a real OAuth client
# registration against every third-party endpoint that advertised one.
#
# Output goes to a NEW directory per run (reports/raw-<label>/), so a re-run cannot
# overwrite the raw evidence that published tables cite.
#
# Usage:
#   bash reports/run_scans.sh                 # all tiers, read-only, into reports/raw-<date>/
#   bash reports/run_scans.sh --tier 1        # Tier-1 only
#   OUT=reports/raw bash reports/run_scans.sh # explicit output dir (will refuse if non-empty)

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

EP="reports/endpoints.txt"
OUT="${OUT:-reports/raw-$(date +%Y%m%d-%H%M%S)}"
EXTRA=("$@")

if [[ ! -f "$EP" ]]; then
  echo "missing endpoint list: $EP" >&2
  exit 2
fi
if [[ -d "$OUT" ]] && [[ -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
  echo "refusing to overwrite non-empty output dir $OUT — set OUT=... to a fresh path" >&2
  exit 2
fi
mkdir -p "$OUT"

clean=0; gaps=0; failed=0; total=0

while IFS='|' read -r name url; do
  [[ "$name" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${name// }" ]] && continue
  name="$(echo "$name" | xargs)"
  url="$(echo "$url" | xargs)"
  [[ -z "$url" ]] && { echo "!! skipping '$name': no URL column" >&2; continue; }

  total=$((total + 1))
  echo "=== scanning $name :: $url ==="
  out="$OUT/$name.json"
  err="$OUT/$name.err"

  uv run mcpauth scan "$url" --json "${EXTRA[@]}" >"$out" 2>"$err"
  rc=$?

  # Exit codes: 0 clean, 1 gap found, 2 scan failed/unreachable, 3 usage error.
  # Retry only a *scan failure*; a clean or gap-found result is a real answer.
  if [[ $rc -eq 2 ]]; then
    echo "  retry $name (scan failed)"
    sleep 2
    uv run mcpauth scan "$url" --json "${EXTRA[@]}" >"$out" 2>"$err"
    rc=$?
  fi

  case $rc in
    0) clean=$((clean + 1)); verdict="clean" ;;
    1) gaps=$((gaps + 1));   verdict="HAS_GAP" ;;
    2) failed=$((failed + 1)); verdict="scan failed" ;;
    *) failed=$((failed + 1)); verdict="usage error (rc=$rc)" ;;
  esac

  summary=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("no parseable report:", e)
else:
    print(d.get("protocol_version"), json.dumps(d.get("summary", {})))
' "$out" 2>/dev/null || echo "no parseable report")
  echo "  -> $verdict | $summary"
  sleep 1
done <"$EP"

echo "=== done: $total scanned | $clean clean | $gaps with gaps | $failed failed ==="
echo "=== raw output: $OUT ==="
