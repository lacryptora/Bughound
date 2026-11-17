#!/usr/bin/env bash
# Walk an entire scope file: wildcards (*.x) get subdomain enumeration,
# exact hosts get tested directly. Every run is filtered against the same
# scope file, so nothing out of scope is touched.
#
# Usage:
#   ./run_scope.sh scope.remitly.txt                       # detect only
#   ./run_scope.sh scope.remitly.txt --llm --llm-provider claude-code
#
# Pass any extra crlf_hunt.py flags after the scope file (they apply to every run).
set -u

SCOPE="${1:-scope.txt}"
shift || true
EXTRA="$*"

[ -f "$SCOPE" ] || { echo "[!] scope file not found: $SCOPE"; exit 1; }

# read non-comment, non-blank lines
HOSTS=$(grep -vE '^\s*#|^\s*$' "$SCOPE")

echo "[*] Scope: $SCOPE"
echo "[*] Extra flags: ${EXTRA:-(none)}"
echo "[*] Starting at $(date)"
echo

while IFS= read -r host; do
  host=$(echo "$host" | tr -d '[:space:]')
  [ -z "$host" ] && continue
  case "$host" in
    \*.*)
      echo "=== wildcard: $host (subdomain enum) ==="
      python3 crlf_hunt.py -d "$host" --scope "$SCOPE" $EXTRA
      ;;
    *)
      echo "=== host: $host ==="
      python3 crlf_hunt.py -u "https://$host" --scope "$SCOPE" $EXTRA
      ;;
  esac
  echo
  sleep 2   # be polite between targets
done <<< "$HOSTS"

echo "[*] Finished at $(date)"
echo "[*] Per-target output is in crlf_<host>/ folders."
echo "[*] Combined findings:"
# summary across all result folders
python3 - <<'PY'
import glob, json, os
rows = []
for f in glob.glob("crlf_*/findings.json"):
    try:
        data = json.load(open(f))
    except Exception:
        continue
    for d in data:
        rows.append((d.get("confirmed"), d.get("engine"), d.get("param"), d.get("url")))
conf = [r for r in rows if r[0]]
print(f"    total findings: {len(rows)}  |  double-confirmed: {len(conf)}")
for r in conf:
    print(f"    [CONFIRMED] {r[2]} @ {r[3]}")
PY
