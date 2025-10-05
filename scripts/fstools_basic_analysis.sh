#!/usr/bin/env bash
# fstools_basic_analysis.sh <image> <workdir>
set -euo pipefail
IMG="$1"
WORKDIR="${2:-./workdir_$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$WORKDIR"
echo "[*] Arbeit: $WORKDIR"

# Partitions
mmls "$IMG" > "$WORKDIR/mmls.txt" 2>/dev/null || true
echo "[*] Partition table -> $WORKDIR/mmls.txt"

# For each partition (example for partition 1 offset)
# parse offsets from mmls, run fls to list files
awk '/^ *[0-9]+:/ {print $1,$3}' "$WORKDIR/mmls.txt" | while read -r num type; do
  echo "[*] Partition $num type $type"
done > "$WORKDIR/partitions_summary.txt"

# Example: list root filesystem file entries for partition with PATH '00:...'
# User should inspect mmls.txt and run fls on e.g. -o OFFSET
echo "Hinweis: für fls/icat brauchen wir den Offset (Sektor * 512). Siehe mmls.txt"
