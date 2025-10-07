#!/usr/bin/env bash
set -euo pipefail
OUTDIR="${1:-./ioc_grep_results}"
mkdir -p "$OUTDIR"
IOCLIST="/mnt/data/IoCs.txt"
if [ ! -f "$IOCLIST" ]; then echo "IoCs file missing: $IOCLIST"; exit 1; fi

# prepare grep pattern (escape dots)
PATTERN=$(sed 's/\./\\./g' "$IOCLIST" | sed '/^$/d' | head -n 2000 | tr '\n' '|' | sed 's/|$//')
# list of target paths (adjust accordingly)
TARGETS=( "/var/log" "/home" "/etc" "/root" "/tmp" "/var/lib/docker" "/var/lib/dhcp" "/var/log/syslog" "/var/log/auth.log" "/var/log/messages" "/home/saschi/.npm" "/home/saschi/.npmrc" "/var/spool/cron" )

> "$OUTDIR/network_ioc_hits.txt"

for t in "${TARGETS[@]}"; do
  if [ -e "$t" ]; then
    echo "=== SCANNING PATH: $t ===" | tee -a "$OUTDIR/network_ioc_hits.txt"
    sudo grep -RIn --binary-files=text -E "$PATTERN" "$t" 2>/dev/null | tee -a "$OUTDIR/network_ioc_hits.txt" || true
  fi
done

# Additional scan: npm cache index-v5
if [ -d "/home/saschi/.npm/_cacache/index-v5" ]; then
  echo "=== SCANNING npm _cacache index-v5 metadata ===" | tee -a "$OUTDIR/network_ioc_hits.txt"
  sudo grep -RIn --binary-files=text -E "$PATTERN" /home/saschi/.npm/_cacache/index-v5 2>/dev/null | tee -a "$OUTDIR/network_ioc_hits.txt" || true
fi

echo "Done. Results: $OUTDIR/network_ioc_hits.txt"
