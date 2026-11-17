#!/bin/sh
# Run from the mounted /data dir so outputs persist; fall back to /app.
cd /data 2>/dev/null || cd /app
# make the default payload list resolvable from the working dir
ln -sf /opt/crlf-hunter/crlf_payloads.txt ./crlf_payloads.txt 2>/dev/null || true
exec python3 /opt/crlf-hunter/crlf_hunt.py "$@"
