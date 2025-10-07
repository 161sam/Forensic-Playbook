#!/usr/bin/env bash
set -euo pipefail
OUTDIR="${1:-./ioc_scan_results}"
mkdir -p "$OUTDIR"
> "$OUTDIR/npm_ioc_hits.txt"

# Pfade anpassen: liste hier Wurzelpfade deiner Projekte
ROOTS=( "/home/saschi/InfoTerminal" "/home/saschi/Sprachassistent" "/home/saschi/agent-nn" )

for r in "${ROOTS[@]}"; do
  if [ -d "$r" ]; then
    echo "=== SCANNING: $r ===" | tee -a "$OUTDIR/npm_ioc_hits.txt"
    pushd "$r" >/dev/null
      # run bundled scanner (falls IoC_Scan.py in /mnt/data)
      python3 /mnt/data/IoC_Scan.py | tee -a "$OUTDIR/npm_ioc_hits.txt" || true
      # also record modtimes of lockfiles
      if [ -f package-lock.json ]; then stat -c "%y %n" package-lock.json >> "$OUTDIR/npm_ioc_hits.txt"; fi
      if [ -f yarn.lock ]; then stat -c "%y %n" yarn.lock >> "$OUTDIR/npm_ioc_hits.txt"; fi
    popd >/dev/null
  else
    echo "MISSING: $r (skip)" | tee -a "$OUTDIR/npm_ioc_hits.txt"
  fi
done

echo "Done. Results: $OUTDIR/npm_ioc_hits.txt"
