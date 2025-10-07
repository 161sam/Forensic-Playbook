#!/usr/bin/env bash
# extract DDNS/DynDNS config occurrences from UI HTML
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/ddns_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# Grep for DDNS provider strings and likely fields
grep -nEi --binary-files=without-match "ddns|dyndns|dynamic dns|no-ip|duckdns|dynservice|dynamic-host|dyndns.org|hostname|provider|server|username|password" \
  "$CONF_DIR"/pagebody_ddns_*.html "$CONF_DIR"/page_ddns_*.html "$CONF_DIR" 2>/dev/null > "$OUT_DIR/ddns_hits_raw.txt" || true

# Attempt to extract probable hostnames / provider names
grep -oEi "(dyndns\.org|no-ip\.com|duckdns\.org|dynhost|dynservice|ddns|hostname|provider)[-A-Za-z0-9@._:/]*" "$OUT_DIR/ddns_hits_raw.txt" | sort -u > "$OUT_DIR/ddns_candidates.txt" || true

echo "DDNS extractions saved in: $OUT_DIR (ddns_hits_raw.txt, ddns_candidates.txt)"
