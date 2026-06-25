#!/bin/bash
# Polite scan loop: one scan per endpoint, single retry on empty/error output.
set -u
cd "/Users/yamitkfi/Documents/CS deg/MCProject/YamAmit-MCP-auth" || exit 1
RAW="reports/raw"
EP="reports/endpoints.txt"

while IFS='|' read -r name url; do
  [[ "$name" =~ ^#.*$ || -z "$name" ]] && continue
  name="$(echo "$name" | xargs)"
  url="$(echo "$url" | xargs)"
  echo "=== scanning $name :: $url ==="
  out="$RAW/$name.json"
  uv run mcpauth scan "$url" --json > "$out" 2>"$RAW/$name.err"
  rc=$?
  # retry once if file is empty or not valid json start
  if [[ $rc -ne 0 || ! -s "$out" ]] || ! head -c1 "$out" | grep -q '{'; then
    echo "  retry $name"
    sleep 2
    uv run mcpauth scan "$url" --json > "$out" 2>"$RAW/$name.err"
  fi
  # quick summary line
  python3 -c "import json,sys;
try:
    d=json.load(open('$out'));
    print('  ->', d.get('protocol_version'), json.dumps(d.get('summary',{})))
except Exception as e:
    print('  -> PARSE_FAIL', open('$RAW/$name.err').read()[:200])
" 2>/dev/null || echo "  -> no-json (see $RAW/$name.err)"
  sleep 1
done < "$EP"
echo "=== done ==="
