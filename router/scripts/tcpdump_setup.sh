#!/usr/bin/env bash
# prepare tcpdump wrapper for passive capture (write file but do NOT auto-run)
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/tcpdump_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

ROUTER_IP="${ROUTER_IP:-192.168.0.1}"   # override at runtime if needed
PCAP_FILE="$OUT_DIR/passive_capture_$ROUTER_IP.pcap"
WRAPPER="$OUT_DIR/tcpdump_passive_capture_wrapper.sh"

cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
# Wrapper to run tcpdump targeted at router traffic (created by tcpdump_setup.sh)
# Edit ROUTER_IP at top of this file or set env var ROUTER_IP before running.
ROUTER_IP="${ROUTER_IP}"
OUTFILE="${PCAP_FILE}"
# safe filter: only traffic to/from router and ports DNS(53), TR-069(7547), HTTP/HTTPS (80,443)
FILTER="host \${ROUTER_IP} and (port 53 or port 7547 or port 80 or port 443)"
echo "tcpdump -i any -w \"\${OUTFILE}\" -s 0 -nn -U \${FILTER}"
# To actually run, uncomment the next line (be deliberate): sudo tcpdump -i any -w "\${OUTFILE}" -s 0 -nn -U \${FILTER}
EOF

chmod +x "$WRAPPER"
echo "tcpdump wrapper created at: $WRAPPER"
echo "It will write to: $PCAP_FILE (command is commented out; enable manually if you intend to capture)"
