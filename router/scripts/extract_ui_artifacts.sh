#!/usr/bin/env bash
# extract general UI artifacts: copies pagebody and page files and greps for network-related hits
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/ui_artifacts_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# copy relevant conf/html files (idempotent overwrite)
cp -f "$CONF_DIR"/page*.html "$OUT_DIR/" 2>/dev/null || true
cp -f "$CONF_DIR"/pagebody_*.html "$OUT_DIR/" 2>/dev/null || true
cp -f "$CONF_DIR"/*.sh "$OUT_DIR/" 2>/dev/null || true

# Searches (TR-069, DDNS, UPnP, port mapping etc.)
grep -iR --line-number --binary-files=without-match -E "tr-069|tr069|tr-064|tr064|ACS|acs-url|acs_url|7547|remote ?admin|remote ?mgmt|remoteadmin" "$CONF_DIR" > "$OUT_DIR/tr069_hits_$(date -u +%Y%m%dT%H%M%SZ).txt" 2>/dev/null || true
grep -iR --line-number --binary-files=without-match -E "ddns|dyndns|dynamic dns|no-ip|duckdns|dynservice|dynamic-host|dyndns.org|hostname|provider|server" "$CONF_DIR" > "$OUT_DIR/ddns_hits_$(date -u +%Y%m%dT%H%M%SZ).txt" 2>/dev/null || true
grep -iR --line-number --binary-files=without-match -E "upnp|universal plug|port mapping|port-forward|portforward|virtual server|external port|internal port|mapping|forward" "$CONF_DIR" > "$OUT_DIR/upnp_pf_hits_$(date -u +%Y%m%dT%H%M%SZ).txt" 2>/dev/null || true

# network navigation hits summary (useful)
grep -iR --line-number --binary-files=without-match "NetDDNS|NetPortMapping|NetFirewall|NetGeneral|NetIPv6HostExposure" "$CONF_DIR" > "$OUT_DIR/network_hits_$(date -u +%Y%m%dT%H%M%SZ).txt" 2>/dev/null || true

echo "UI artifacts & search hits saved to: $OUT_DIR"
