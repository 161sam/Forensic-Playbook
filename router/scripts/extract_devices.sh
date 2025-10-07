#!/usr/bin/env bash
# extract LAN/WLAN device summary (hostname, IPv4, MAC) from overview/root pages
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/devices_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# Attempt to find blocks that include Name, IPv4, MAC
# Heuristic: look for 'Name:' 'IPv4:' 'MAC:' strings near each other
sed -n '1,4000p' "$CONF_DIR"/pagebody_root_*.html "$CONF_DIR"/page_root_*.html 2>/dev/null > "$OUT_DIR/root_pages_concat.html" || true

# Extract lines containing IPv4/MAC
grep -iE --line-number "IPv4:|IPv6:|MAC:|Name:" "$OUT_DIR/root_pages_concat.html" > "$OUT_DIR/devices_raw_lines.txt" || true

# Try to produce a simple CSV: name,ipv4,mac
awk 'BEGIN{FS=":"; OFS=","}
  /Name:/{name=$0; sub(/.*Name:[ \t]*/,"",name)}
  /IPv4:/{ip=$0; sub(/.*IPv4:[ \t]*/,"",ip)}
  /MAC:/{mac=$0; sub(/.*MAC:[ \t]*/,"",mac); print name,ip,mac; name="";ip="";mac=""}
' "$OUT_DIR/root_pages_concat.html" > "$OUT_DIR/devices_extracted.csv" 2>/dev/null || true

echo "Device extractions saved: $OUT_DIR/devices_extracted.csv (check devices_raw_lines.txt if CSV empty)"
