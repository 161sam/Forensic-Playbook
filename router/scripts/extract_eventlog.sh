#!/usr/bin/env bash
# extract event/log entries from saved event_log page(s)
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/eventlog_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# Dump full event_log pages (if present)
sed -n '1,10000p' "$CONF_DIR"/pagebody_event_log_*.html 2>/dev/null > "$OUT_DIR/event_log_full.html" || true

# Search for important event keywords
grep -iE --line-number "reboot|restart|firmware|update|backup|restore|ddns|dyn|acs|tr-069|tr069|config|remote|admin" \
  "$CONF_DIR"/pagebody_event_log_*.html "$CONF_DIR"/page_event_log_*.html 2>/dev/null > "$OUT_DIR/eventlog_hits.txt" || true

# Also search general pages for event-like messages
grep -iE --line-number "reboot|restart|firmware|update|backup|restore|ddns|acs|tr-069|config" "$CONF_DIR"/* 2>/dev/null >> "$OUT_DIR/eventlog_hits.txt" || true

echo "Event log extractions: $OUT_DIR"
