#!/usr/bin/env bash
# best-effort extraction of port-forward / port-mapping entries from saved UI html
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/portforwards_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# Search patterns that often indicate port forwarding table rows
grep -nEi --binary-files=without-match "port|external|internal|protocol|mapping|host|service|forward|virtual server|external port|internal port" \
  "$CONF_DIR"/pagebody_port_mapping_*.html "$CONF_DIR"/page_port_mapping_*.html 2>/dev/null > "$OUT_DIR/portforwards_raw.txt" || true

# Clean and present nearest context lines (10 lines context) - idempotent
if [ -s "$OUT_DIR/portforwards_raw.txt" ]; then
  awk -F: '{ print $1 ":" $2 }' "$OUT_DIR/portforwards_raw.txt" | cut -d: -f1 | sort -u | while read -r file; do
    echo "==== $file ====" >> "$OUT_DIR/portforwards_extract.txt"
    sed -n '1,400p' "$file" >> "$OUT_DIR/portforwards_extract.txt" || true
    echo >> "$OUT_DIR/portforwards_extract.txt"
  done
fi

# Also save a small CSV attempt: find lines with "IPv4" "external" etc
grep -nEi "external.*port|internal.*port|virtual server|external port|internal port" "$CONF_DIR"/* 2>/dev/null | sed 's/:/ | /' > "$OUT_DIR/portforwards_hits_summary.txt" || true

echo "Port mapping extracts: $OUT_DIR/portforwards_extract.txt (if empty, check raw file)"
