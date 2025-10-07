#!/usr/bin/env bash
# compile a concise text + html report from run artifacts
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
RUN_DIR="${2:-/mnt/FORNSIC_20251006/logs}"
REPORT_DIR="${3:-/mnt/FORNSIC_20251006/reports}"
mkdir -p "$REPORT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_TXT="$REPORT_DIR/report_${TS}.txt"
REPORT_HTML="$REPORT_DIR/report_${TS}.html"

{
  echo "Forensic analysis report"
  echo "Timestamp (UTC): $TS"
  echo
  echo "Base/conf dir: $CONF_DIR"
  echo "Run dir used: $RUN_DIR"
  echo
  echo "--- Quick stats ---"
  echo "UI files (pagebody_*.html) count: $(ls -1 "$CONF_DIR"/pagebody_*.html 2>/dev/null | wc -l || true)"
  echo "curl_replay scripts: $(ls -1 "$CONF_DIR"/curl_replay_*.sh 2>/dev/null | wc -l || true)"
  echo
  echo "TR-069/ACS hits:"
  grep -iR --line-number --binary-files=without-match -E "tr-069|tr069|7547|ACS|acs-url|acs_url|cwmp" "$CONF_DIR" 2>/dev/null | sed -n '1,50p' || true
  echo
  echo "DDNS hits:"
  grep -iR --line-number --binary-files=without-match -E "ddns|dyndns|no-ip|duckdns|dynservice|dynamic-host|hostname" "$CONF_DIR" 2>/dev/null | sed -n '1,50p' || true
  echo
  echo "Port-forward/UPnP hits (nav/page):"
  grep -iR --line-number --binary-files=without-match -E "port mapping|port-forward|virtual server|upnp|portforward|external port|internal port" "$CONF_DIR" 2>/dev/null | sed -n '1,50p' || true
  echo
  echo "Session/CSRF tokens found (examples):"
  grep -n --binary-files=without-match "PHPSESSID" "$CONF_DIR" 2>/dev/null | sed -n '1,20p' || true
  grep -nEi --binary-files=without-match "csrf_nonce|csrfNonce|csp_nonce|nonce-" "$CONF_DIR" 2>/dev/null | sed -n '1,20p' || true
  echo
  echo "Device summary (head):"
  awk 'NR<=20 {print}' "$RUN_DIR"/devices_*/*.csv 2>/dev/null || true
  echo
  echo "Produced artifact directories (recent):"
  ls -1d "$RUN_DIR"/* 2>/dev/null | sed -n '1,200p' || true
  echo
  echo "Detailed artifacts are stored in run dir(s)."
  echo
  echo "End of quick report."
} > "$REPORT_TXT"

# small HTML wrapper
cat > "$REPORT_HTML" <<EOF
<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Forensic Report $TS</title></head>
<body>
<h1>Forensic analysis report</h1>
<p><strong>Timestamp (UTC):</strong> $TS</p>
<pre style="white-space:pre-wrap; font-family:monospace;">
$(sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$REPORT_TXT")
</pre>
</body>
</html>
EOF

echo "Reports created:"
echo " - $REPORT_TXT"
echo " - $REPORT_HTML"
