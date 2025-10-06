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
  --force      : overwrite timestamped outputs (still writes new timestamped files)
  --iface      : network interface for optional tcpdump helper scripts (default eth0)
  --router-ip  : router LAN IP (default 192.168.0.1)
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

now() { date -u +%Y%m%dT%H%M%SZ; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

COC="${HASH_DIR}/chain_of_custody_analysis.txt"
echo "$(iso_now) | ANALYSIS_START | user=$(id -un) | host=$(hostname -f) | router=${ROUTER_IP}" >> "$COC"

OUT_PREFIX="${LOG_DIR}/analysis_$(now)"
EXTERNAL_URLS="${LOG_DIR}/external_urls_$(now).txt"
CERT_FILE="${CONF_DIR}/router_cert_$(now).txt"
HTTP_HEADERS_OUT="${CONF_DIR}/http_headers_router_$(now).txt"

echo "$(iso_now) | INFO | starting analysis outputs: ${OUT_PREFIX}*" >> "$COC"

# 1A: TR-069 / ACS / Remote management related
GREP_OPTS="-n -R --binary-files=without-match"
TR069_OUT="${LOG_DIR}/tr069_hits_$(now).txt"
grep -iE "tr-069|tr069|tr-064|tr064|ACS|acs-url|acs_url|7547|remote ?admin|remote ?mgmt|remoteadmin" $GREP_OPTS "${CONF_DIR}"* 2>/dev/null | sort -u > "$TR069_OUT" || true
echo "$(iso_now) | TR069_SEARCH | results=$(wc -l <"$TR069_OUT") | file=$TR069_OUT" >> "$COC"

# 1B: DynDNS / DDNS
DDNS_OUT="${LOG_DIR}/ddns_hits_$(now).txt"
grep -iE "ddns|dyndns|dynamic dns|no-ip|duckdns|dynservice|hostname|dynamic-host|dyndns.org" $GREP_OPTS "${CONF_DIR}"* 2>/dev/null | sort -u > "$DDNS_OUT" || true
echo "$(iso_now) | DDNS_SEARCH | results=$(wc -l <"$DDNS_OUT") | file=$DDNS_OUT" >> "$COC"

# 1C: UPnP / Port-Forwarding / Virtual server / mappings
UPNP_OUT="${LOG_DIR}/upnp_pf_hits_$(now).txt"
grep -iE "upnp|universal plug|port mapping|port-forward|portforward|virtual server|forward|external port|internal port|mapping" $GREP_OPTS "${CONF_DIR}"* 2>/dev/null | sort -u > "$UPNP_OUT" || true
echo "$(iso_now) | UPNP_PF_SEARCH | results=$(wc -l <"$UPNP_OUT") | file=$UPNP_OUT" >> "$COC"

# 1D: Backup / Restore / Config export / syslog export URLs
BACKUP_OUT="${LOG_DIR}/backup_hits_$(now).txt"
grep -iE "backup|restore|configuration|config|export|import|system_log|syslog|download config|backupsettings|restoresettings" $GREP_OPTS "${CONF_DIR}"* 2>/dev/null | sort -u > "$BACKUP_OUT" || true
echo "$(iso_now) | BACKUP_SEARCH | results=$(wc -l <"$BACKUP_OUT") | file=$BACKUP_OUT" >> "$COC"

# 1E: DNS servers, DHCP options, WAN IP, NTP
NETWORK_OUT="${LOG_DIR}/network_hits_$(now).txt"
grep -iE "dns|nameserver|dhcp|option 3|option 6|option 15|option 252|gateway|wan|inet addr|ntp|time server|timezone|dnsserver" $GREP_OPTS "${CONF_DIR}"* 2>/dev/null | sort -u > "$NETWORK_OUT" || true
echo "$(iso_now) | NETWORK_SEARCH | results=$(wc -l <"$NETWORK_OUT") | file=$NETWORK_OUT" >> "$COC"

# 1F: extract all external URLs (http/https)
# best-effort: search conf files for http(s) strings
grep -Eoi "https?://[a-zA-Z0-9._:/?&=%@\-]+" "${CONF_DIR}"* 2>/dev/null | sort -u > "$EXTERNAL_URLS" || true
echo "$(iso_now) | EXTERNAL_URLS_EXTRACTED | file=$EXTERNAL_URLS | lines=$(wc -l <"$EXTERNAL_URLS")" >> "$COC"

# 2) Show first ~80 lines of each headers_* file (safe)
HDR_PREVIEW="${LOG_DIR}/headers_preview_$(now).txt"
: > "$HDR_PREVIEW"
for f in "${CONF_DIR}"/headers_*.txt 2>/dev/null; do
  if [[ -f "$f" ]]; then
    echo "---- $f ----" >> "$HDR_PREVIEW"
    sed -n '1,80p' "$f" >> "$HDR_PREVIEW" || true
    echo "" >> "$HDR_PREVIEW"
  fi
done
echo "$(iso_now) | HEADERS_PREVIEW_WRITTEN | file=$HDR_PREVIEW" >> "$COC"

# 3) Extract TLS cert from router (read-only). If file exists recently, skip unless --force
if [[ -n "${ROUTER_IP:-}" ]]; then
  if ls "${CONF_DIR}/router_cert_"* 1>/dev/null 2>&1 && [[ $FORCE -eq 0 ]]; then
    echo "$(iso_now) | ROUTER_CERT_SKIP (exists)" >> "$COC"
  else
    # capture cert using openssl s_client -> x509 text
    set +e
    openssl s_client -connect "${ROUTER_IP}:443" -servername "${ROUTER_IP}" -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text > "$CERT_FILE" 2>/dev/null
    rc=$?
    set -e
    if [[ $rc -eq 0 && -s "$CERT_FILE" ]]; then
      echo "$(iso_now) | ROUTER_CERT_SAVED | file=$CERT_FILE" >> "$COC"
    else
      echo "$(iso_now) | ROUTER_CERT_FAILED | rc=$rc" >> "$COC"
    fi
  fi
fi

# 4) HTTP HEAD fingerprint via curl (writes one file)
if [[ -f "$HTTP_HEADERS_OUT" && $FORCE -eq 0 ]]; then
  echo "$(iso_now) | HTTP_HEADERS_SKIP (exists)" >> "$COC"
else
  set +e
  curl -k -I "https://${ROUTER_IP}/" -sS -D - > "$HTTP_HEADERS_OUT" 2>/dev/null
  rc=$?
  set -e
  if [[ $rc -eq 0 && -s "$HTTP_HEADERS_OUT" ]]; then
    echo "$(iso_now) | HTTP_HEADERS_SAVED | file=$HTTP_HEADERS_OUT" >> "$COC"
  else
    echo "$(iso_now) | HTTP_HEADERS_FAILED | rc=$rc" >> "$COC"
  fi
fi

# 5) Extract Wi-Fi settings from saved page body
WIFI_HTML_FILE=$(ls -1 "${CONF_DIR}"/page_wifi_*.html 2>/dev/null | tail -n1 || true)
WIFI_OUT="${LOG_DIR}/wifi_extract_$(now).txt"
: > "$WIFI_OUT"
if [[ -n "$WIFI_HTML_FILE" && -f "$WIFI_HTML_FILE" ]]; then
  echo "file: $WIFI_HTML_FILE" >> "$WIFI_OUT"
  # grep common wifi keywords and context
  grep -nEi "ssid|network name|wpa|wpa2|wpa3|encryption|cipher|psk|wps|open|security|hidden|guest" "$WIFI_HTML_FILE" | sed -n '1,200p' >> "$WIFI_OUT" || true
  echo "" >> "$WIFI_OUT"
  # include a small snippet for manual review (first 240 lines)
  sed -n '1,240p' "$WIFI_HTML_FILE" >> "$WIFI_OUT" || true
  echo "$(iso_now) | WIFI_EXTRACT_WRITTEN | file=$WIFI_OUT" >> "$COC"
else
  echo "$(iso_now) | WIFI_HTML_NOT_FOUND" >> "$COC"
fi

# 6) Extract Port-Forward/Port-Mapping entries
PF_HTML_FILE=$(ls -1 "${CONF_DIR}"/page_port_mapping_*.html 2>/dev/null | tail -n1 || true)
PF_OUT="${LOG_DIR}/portforwards_extract_$(now).txt"
: > "$PF_OUT"
if [[ -n "$PF_HTML_FILE" && -f "$PF_HTML_FILE" ]]; then
  echo "file: $PF_HTML_FILE" >> "$PF_OUT"
  grep -nEi "port|external|internal|protocol|mapping|host|service|forward" "$PF_HTML_FILE" | sed -n '1,400p' >> "$PF_OUT" || true
  echo "" >> "$PF_OUT"
  sed -n '1,400p' "$PF_HTML_FILE" >> "$PF_OUT" || true
  echo "$(iso_now) | PF_EXTRACT_WRITTEN | file=$PF_OUT" >> "$COC"
else
  echo "$(iso_now) | PF_HTML_NOT_FOUND" >> "$COC"
fi

# 7) Print summary to STDOUT (paths only)
cat <<EOF

ANALYSIS COMPLETE
Chain-of-Custody: $COC

Generated files:
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

All files are timestamped and stored under $LOG_DIR or $CONF_DIR.

EOF

echo "$(iso_now) | ANALYSIS_END" >> "$COC"
exit 0
