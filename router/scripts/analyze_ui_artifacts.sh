#!/usr/bin/env bash
# analyze_ui_artifacts.sh
# Idempotent forensic analysis of collected router UI artifacts
# - searches for TR-069/ACS, DDNS, UPnP, Backup/Restore, DNS/NTP etc.
# - extracts external URLs
# - dumps HTTP headers files preview
# - extracts TLS cert from router (read-only)
# - shows Wi-Fi and Port-Forward sections (best-effort)
#
# Usage:
#   sudo /mnt/FORNSIC_20251006/conf/analyze_ui_artifacts.sh [--force] [--iface eth0] [--router-ip 192.168.0.1]
#
set -euo pipefail
IFS=$'\n\t'

OUTDIR="/mnt/FORNSIC_20251006"
CONF_DIR="${OUTDIR}/conf"
LOG_DIR="${OUTDIR}/logs"
HASH_DIR="${OUTDIR}/hashes"
PCAP_DIR="${OUTDIR}/pcap"

mkdir -p "$CONF_DIR" "$LOG_DIR" "$HASH_DIR" "$PCAP_DIR"

FORCE=0
IFACE="eth0"
ROUTER_IP="192.168.0.1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --iface) IFACE="$2"; shift 2 ;;
    --router-ip) ROUTER_IP="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [--force] [--iface eth0] [--router-ip 192.168.0.1]
  --force      : allow overwriting recent captures (script still creates timestamped files)
  --iface      : network interface (for future use)
  --router-ip  : router LAN IP (default 192.168.0.1)
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

now() { date -u +%Y%m%dT%H%M%SZ; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

COC="${HASH_DIR}/chain_of_custody_analysis_$(now).txt"
echo "$(iso_now) | ANALYSIS_START | user=$(id -un) | host=$(hostname -f) | router=${ROUTER_IP}" >> "$COC"

log() { echo "$(iso_now) | $*" >> "$COC"; }

log "INFO | Starting analyze_ui_artifacts.sh"

# safe find helper ensures we only pass existing files
find_conf_files() {
  find "$CONF_DIR" -type f 2>/dev/null || true
}

# 1A: TR-069 / ACS / Remote management related (recursively search conf dir)
TR069_OUT="${LOG_DIR}/tr069_hits_$(now).txt"
log "TR-069 search -> $TR069_OUT"
# use find + xargs to avoid shell glob pitfalls
if find_conf_files | xargs -r grep -iE --line-number --binary-files=without-match "tr-069|tr069|tr-064|tr064|ACS|acs-url|acs_url|7547|remote ?admin|remote ?mgmt|remoteadmin" > "$TR069_OUT" 2>/dev/null; then
  : # results written
else
  : > "$TR069_OUT"
fi
log "TR069_SEARCH_DONE lines=$(wc -l <"$TR069_OUT")"

# 1B: DynDNS / DDNS / Dynamic host entries
DDNS_OUT="${LOG_DIR}/ddns_hits_$(now).txt"
log "DDNS search -> $DDNS_OUT"
if find_conf_files | xargs -r grep -iE --line-number --binary-files=without-match "ddns|dyndns|dynamic dns|no-ip|duckdns|dynservice|dynamic-host|dyndns.org|hostname" > "$DDNS_OUT" 2>/dev/null; then
  :
else
  : > "$DDNS_OUT"
fi
log "DDNS_SEARCH_DONE lines=$(wc -l <"$DDNS_OUT")"

# 1C: UPnP / Port-Forwarding / Virtual server / mappings
UPNP_OUT="${LOG_DIR}/upnp_pf_hits_$(now).txt"
log "UPnP/Port-Forward search -> $UPNP_OUT"
if find_conf_files | xargs -r grep -iE --line-number --binary-files=without-match "upnp|universal plug|port mapping|port-forward|portforward|virtual server|external port|internal port|mapping|forward" > "$UPNP_OUT" 2>/dev/null; then
  :
else
  : > "$UPNP_OUT"
fi
log "UPNP_PF_SEARCH_DONE lines=$(wc -l <"$UPNP_OUT")"

# 1D: Backup / Restore / Config export / syslog export URLs
BACKUP_OUT="${LOG_DIR}/backup_hits_$(now).txt"
log "Backup/Restore search -> $BACKUP_OUT"
if find_conf_files | xargs -r grep -iE --line-number --binary-files=without-match "backup|restore|configuration|config|export|import|system_log|syslog|download config|backupsettings|restoresettings|backup_restore" > "$BACKUP_OUT" 2>/dev/null; then
  :
else
  : > "$BACKUP_OUT"
fi
log "BACKUP_SEARCH_DONE lines=$(wc -l <"$BACKUP_OUT")"

# 1E: DNS servers, DHCP options, WAN IP, NTP
NETWORK_OUT="${LOG_DIR}/network_hits_$(now).txt"
log "Network (DNS/DHCP/NTP) search -> $NETWORK_OUT"
if find_conf_files | xargs -r grep -iE --line-number --binary-files=without-match "dns|nameserver|dhcp|option 3|option 6|option 15|option 252|gateway|wan|inet addr|ntp|time server|timezone|dnsserver|dhcp-server" > "$NETWORK_OUT" 2>/dev/null; then
  :
else
  : > "$NETWORK_OUT"
fi
log "NETWORK_SEARCH_DONE lines=$(wc -l <"$NETWORK_OUT")"

# 1F: extract all external URLs (http/https)
EXTERNAL_URLS="${LOG_DIR}/external_urls_$(now).txt"
log "Extract external http/https URLs -> $EXTERNAL_URLS"
# Use find to pass filenames safely
: > "$EXTERNAL_URLS"
while IFS= read -r -d '' f; do
  # extract urls from each file
  grep -Eoi "https?://[a-zA-Z0-9\.\-_%:/?=&#]+" "$f" 2>/dev/null || true
done < <(find "$CONF_DIR" -type f -print0 2>/dev/null) | sort -u > "$EXTERNAL_URLS" || true
log "EXTERNAL_URLS_EXTRACTED lines=$(wc -l <"$EXTERNAL_URLS")"

# 2) Show first ~80 lines of each headers_* file (safe)
HDR_PREVIEW="${LOG_DIR}/headers_preview_$(now).txt"
: > "$HDR_PREVIEW"
for f in "$CONF_DIR"/headers_*.txt; do
  if [[ -f "$f" ]]; then
    echo "---- $f ----" >> "$HDR_PREVIEW"
    sed -n '1,80p' "$f" >> "$HDR_PREVIEW" || true
    echo "" >> "$HDR_PREVIEW"
  fi
done
log "HEADERS_PREVIEW_WRITTEN -> $HDR_PREVIEW"

# 3) Extract TLS cert from router (read-only)
CERT_FILE="${CONF_DIR}/router_cert_$(now).txt"
if [[ $FORCE -eq 0 ]]; then
  # skip capture if any cert file exists and is recent (< 1 hour)
  existing=$(ls "${CONF_DIR}/router_cert_"* 2>/dev/null || true)
  if [[ -n "$existing" ]]; then
    # if any existing file is older than 1 hour we still capture; otherwise skip
    newest=$(ls -1rt "${CONF_DIR}/router_cert_"* 2>/dev/null | tail -n1 || true)
    if [[ -n "$newest" ]]; then
      # age in seconds
      age=$(( $(date +%s) - $(stat -c %Y "$newest") ))
      if [[ $age -lt 3600 ]]; then
        log "ROUTER_CERT_SKIP (recent exists: $newest)"
        CERT_FILE="$newest"
      fi
    fi
  fi
fi

if [[ ! -f "$CERT_FILE" || $FORCE -eq 1 ]]; then
  log "Attempting TLS cert extraction from ${ROUTER_IP}:443 -> $CERT_FILE"
  set +e
  # capture full cert chain then format the leaf cert
  openssl s_client -connect "${ROUTER_IP}:443" -servername "${ROUTER_IP}" -showcerts </dev/null 2>/dev/null > "${CONF_DIR}/router_cert_raw_$(now).pem" || true
  # try to extract the first cert block and parse it
  awk 'BEGIN{flag=0} /-BEGIN CERTIFICATE-/{flag=1} flag{print} /-END CERTIFICATE-/{flag=0}' "${CONF_DIR}/router_cert_raw_"* 2>/dev/null | sed -n '1,5000p' > "${CONF_DIR}/router_cert_chain_$(now).pem" || true
  if [[ -s "${CONF_DIR}/router_cert_chain_"* ]]; then
    # try to get leaf (first cert) to human readable
    head -c 20000 "${CONF_DIR}/router_cert_chain_"* | openssl x509 -noout -text > "$CERT_FILE" 2>/dev/null || true
    if [[ -s "$CERT_FILE" ]]; then
      log "ROUTER_CERT_SAVED -> $CERT_FILE"
    else
      log "ROUTER_CERT_PARSE_FAILED"
    fi
  else
    log "ROUTER_CERT_CAPTURE_FAILED"
  fi
  set -e
fi

# 4) HTTP HEAD fingerprint via curl (safe)
HTTP_HEADERS_OUT="${CONF_DIR}/http_headers_router_$(now).txt"
if [[ -f "$HTTP_HEADERS_OUT" && $FORCE -eq 0 ]]; then
  log "HTTP_HEADERS_SKIP (exists): $HTTP_HEADERS_OUT"
else
  log "Fetching HTTP headers (HEAD) from https://${ROUTER_IP}/ -> $HTTP_HEADERS_OUT"
  set +e
  curl -k -I "https://${ROUTER_IP}/" -sS -D - > "$HTTP_HEADERS_OUT" 2>/dev/null
  rc=$?
  set -e
  if [[ $rc -eq 0 && -s "$HTTP_HEADERS_OUT" ]]; then
    log "HTTP_HEADERS_SAVED -> $HTTP_HEADERS_OUT"
  else
    log "HTTP_HEADERS_FAILED rc=$rc"
  fi
fi

# 5) Extract Wi-Fi settings from saved page body (best-effort)
WIFI_HTML_FILE=$(ls -1 "${CONF_DIR}"/page_wifi_*.html 2>/dev/null | tail -n1 || true)
WIFI_OUT="${LOG_DIR}/wifi_extract_$(now).txt"
: > "$WIFI_OUT"
if [[ -n "$WIFI_HTML_FILE" && -f "$WIFI_HTML_FILE" ]]; then
  echo "file: $WIFI_HTML_FILE" >> "$WIFI_OUT"
  grep -nEi "ssid|network name|wpa|wpa2|wpa3|encryption|cipher|psk|wps|open|security|hidden|guest|passphrase" "$WIFI_HTML_FILE" | sed -n '1,200p' >> "$WIFI_OUT" || true
  echo "" >> "$WIFI_OUT"
  sed -n '1,240p' "$WIFI_HTML_FILE" >> "$WIFI_OUT" || true
  log "WIFI_EXTRACT_WRITTEN -> $WIFI_OUT"
else
  log "WIFI_HTML_NOT_FOUND"
fi

# 6) Extract Port-Forward/Port-Mapping entries (best-effort)
PF_HTML_FILE=$(ls -1 "${CONF_DIR}"/page_port_mapping_*.html 2>/dev/null | tail -n1 || true)
PF_OUT="${LOG_DIR}/portforwards_extract_$(now).txt"
: > "$PF_OUT"
if [[ -n "$PF_HTML_FILE" && -f "$PF_HTML_FILE" ]]; then
  echo "file: $PF_HTML_FILE" >> "$PF_OUT"
  grep -nEi "port|external|internal|protocol|mapping|host|service|forward|virtual server" "$PF_HTML_FILE" | sed -n '1,400p' >> "$PF_OUT" || true
  echo "" >> "$PF_OUT"
  sed -n '1,400p' "$PF_HTML_FILE" >> "$PF_OUT" || true
  log "PF_EXTRACT_WRITTEN -> $PF_OUT"
else
  log "PF_HTML_NOT_FOUND"
fi

# 7) Summary / print locations (do not print secrets)
cat <<EOF

ANALYSIS COMPLETE
Chain-of-Custody log: $COC

Generated files (examples):
 - TR-069 hits:    $TR069_OUT
 - DDNS hits:      $DDNS_OUT
 - UPnP/Port hits: $UPNP_OUT
 - Backups hits:   $BACKUP_OUT
 - Network hits:   $NETWORK_OUT
 - External URLs:  $EXTERNAL_URLS
 - Headers preview: $HDR_PREVIEW
 - TLS cert (if captured): $CERT_FILE
 - HTTP HEAD:       $HTTP_HEADERS_OUT
 - WiFi extract:    $WIFI_OUT
 - Port-forward extract: $PF_OUT

Check the files above for details. The script is read-only to the router and only reads saved artifacts or performs safe HEAD/cert reads.

EOF

log "ANALYSIS_END"
exit 0
