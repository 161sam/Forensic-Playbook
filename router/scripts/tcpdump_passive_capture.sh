#!/usr/bin/env bash
# tcpdump_passive_capture.sh
# - simple idempotent wrapper to start a tcpdump capture for router traffic (DNS/TR-069/HTTP(S))
# - creates pidfile and pcap filename under /mnt/FORNSIC_20251006/pcap
#
# Usage:
#   sudo /mnt/FORNSIC_20251006/conf/tcpdump_passive_capture.sh [--iface eth0] [--router-ip 192.168.0.1] [--duration 300]
#
set -euo pipefail
IFS=$'\n\t'

OUTDIR="/mnt/FORNSIC_20251006"
PCAP_DIR="${OUTDIR}/pcap"
PIDFILE="${PCAP_DIR}/tcpdump_router.pid"

IFACE="eth0"
ROUTER_IP="192.168.0.1"
DURATION=""  # seconds, if set will stop after this many seconds via timeout

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2 ;;
    --router-ip) ROUTER_IP="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    -h|--help) echo "Usage: $(basename $0) [--iface eth0] [--router-ip 192.168.0.1] [--duration seconds]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

mkdir -p "$PCAP_DIR"

if [[ -f "$PIDFILE" ]]; then
  pid=$(cat "$PIDFILE")
  if kill -0 "$pid" 2>/dev/null; then
    echo "tcpdump already running with pid $pid (pidfile: $PIDFILE). Stop it first: tcpdump_passive_stop.sh"
    exit 1
  else
    echo "Stale pidfile found, removing."
    rm -f "$PIDFILE"
  fi
fi

PCAP="${PCAP_DIR}/router_followup_$(date -u +%Y%m%dT%H%M%SZ).pcap"

# safe filter: only traffic to/from router and ports DNS(53), TR-069(7547), HTTP/HTTPS (80,443)
FILTER="host ${ROUTER_IP} and (port 53 or port 7547 or port 80 or port 443)"

echo "Starting tcpdump on ${IFACE} -> ${PCAP} (filter: ${FILTER})"
if [[ -z "$DURATION" ]]; then
  sudo tcpdump -i "$IFACE" $FILTER -s 0 -w "$PCAP" &
  pid=$!
else
  # run under timeout to auto-stop
  sudo timeout "$DURATION" tcpdump -i "$IFACE" $FILTER -s 0 -w "$PCAP" &
  pid=$!
fi

# detach and write pidfile
echo "$pid" > "$PIDFILE"
echo "tcpdump started pid=$pid pcap=$PCAP pidfile=$PIDFILE"
exit 0
