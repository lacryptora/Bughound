#!/usr/bin/env bash
# Installs the external recon + CRLF tools. Safe to re-run.
set -u
echo "[*] Installing Go-based tools (needs Go on PATH)..."
if ! command -v go >/dev/null 2>&1; then
  echo "[!] Go not found. Install Go first (sudo apt install -y golang-go), then re-run."
  exit 1
fi
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)
for t in "${GO_TOOLS[@]}"; do
  echo "    go install $t"
  go install "$t" || echo "    [!] failed: $t (skipped)"
done

echo "[*] Installing CRLFsuite (Python)..."
if command -v pipx >/dev/null 2>&1; then pipx install crlfsuite || true
else pip3 install --user crlfsuite 2>/dev/null || pip3 install --break-system-packages crlfsuite 2>/dev/null || echo "    [!] crlfsuite skipped"; fi

echo "[*] Python deps..."
pip3 install -r requirements.txt 2>/dev/null || pip3 install --break-system-packages -r requirements.txt

echo
echo "[*] Done. Verify with: python3 crlf_hunt.py -h"
echo "    Any tool that failed is optional; the built-in fuzzer always runs."
