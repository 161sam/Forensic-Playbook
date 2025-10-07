#!/usr/bin/env bash
# extract session IDs, cookies, CSRF nonces etc from saved curl scripts and html
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/session_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# PHPSESSID in curl_replay scripts
grep -n --binary-files=without-match "PHPSESSID" "$CONF_DIR"/curl_replay_*.sh 2>/dev/null > "$OUT_DIR/php_session_ids.txt" || true

# csrf nonce usage / storage keys in html/js
grep -nEi --binary-files=without-match "csrf_nonce|csrfNonce|getSessionStorage|setRequestHeader\\(\"csrfNonce\"|csrf" "$CONF_DIR"/*.html "$CONF_DIR"/pagebody_*.html 2>/dev/null > "$OUT_DIR/csrf_hits.txt" || true

# nonces in script tags (csp_nonce)
grep -nEi --binary-files=without-match "csp_nonce|nonce-[A-Za-z0-9+/=]+" "$CONF_DIR"/*.html "$CONF_DIR"/pagebody_*.html 2>/dev/null > "$OUT_DIR/csp_nonce_hits.txt" || true

echo "Session & CSRF artifacts saved in: $OUT_DIR"
