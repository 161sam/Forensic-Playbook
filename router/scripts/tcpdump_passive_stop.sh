#!/usr/bin/env bash
# tcpdump_passive_stop.sh
PCAP_DIR="/mnt/FORNSIC_20251006/pcap"
PIDFILE="${PCAP_DIR}/tcpdump_router.pid"
if [[ ! -f "$PIDFILE" ]]; then
  echo "No pidfile found at $PIDFILE"
  exit 1
fi
pid=$(cat "$PIDFILE")
if kill -0 "$pid" 2>/dev/null; then
  sudo kill "$pid"
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "Could not kill $pid; try sudo kill -9 $pid"
    exit 2
  fi
  echo "tcpdump (pid $pid) stopped. Removing pidfile."
  rm -f "$PIDFILE"
else
  echo "Process $pid not running. Removing stale pidfile."
  rm -f "$PIDFILE"
fi
exit 0
