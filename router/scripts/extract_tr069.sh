#!/usr/bin/env bash
# attempt to find ACS/TR-069 references (ACS URLs, port 7547 usage in tcpdump filter, etc.)
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/tr069_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# Search for ACS/7547 mentions in conf files and page html
grep -nEi --binary-files=without-match "ACS|acs-url|acs_url|cwmp|7547|tr-069|tr069|remote ?admin" "$CONF_DIR" > "$OUT_DIR/tr069_hits.txt" 2>/dev/null || true

# If tcpdump_passive_capture.sh exists, show filter and look for port 7547
if [ -f "$CONF_DIR/tcpdump_passive_capture.sh" ]; then
  sed -n '1,240p' "$CONF_DIR/tcpdump_passive_capture.sh" > "$OUT_DIR/tcpdump_passive_capture.sh.txt"
  grep -n "7547" "$CONF_DIR/tcpdump_passive_capture.sh" >> "$OUT_DIR/tr069_hits.txt" 2>/dev/null || true
fi

# Heuristic: find http(s) URLs with 'acs' or 'tr069'
grep -oEi "https?://[A-Za-z0-9._:/-]*acs[A-Za-z0-9._:/-]*" "$CONF_DIR"/* 2>/dev/null | sort -u > "$OUT_DIR/acs_url_candidates.txt" || true
grep -oEi "https?://[A-Za-z0-9._:/-]*7547[A-Za-z0-9._:/-]*" "$CONF_DIR"/* 2>/dev/null | sort -u >> "$OUT_DIR/acs_url_candidates.txt" || true

echo "TR-069/ACS candidates & tcpdump filter saved in: $OUT_DIR"
