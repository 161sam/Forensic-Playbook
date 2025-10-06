#!/usr/bin/env bash
# generate_evidence_manifest.sh
# - computes sha256sum for the collected evidence directories and writes timestamped manifest
# - idempotent: creates new manifest file each run (timestamped)
#
# Usage:
#   /mnt/FORNSIC_20251006/conf/generate_evidence_manifest.sh [--force] [--outdir /mnt/FORNSIC_20251006/hashes]
set -euo pipefail
IFS=$'\n\t'

OUTDIR="/mnt/FORNSIC_20251006"
CONF_DIR="${OUTDIR}/conf"
SCREEN_DIR="${OUTDIR}/screenshots"
LOG_DIR="${OUTDIR}/logs"
PCAP_DIR="${OUTDIR}/pcap"
HASH_DIR="${OUTDIR}/hashes"

FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --outdir) HASH_DIR="$2"; shift 2 ;;
    -h|--help) echo "Usage: $(basename $0) [--force] [--outdir /path]"; exit 0;;
    *) echo "Unknown arg $1"; exit 1;;
  esac
done

mkdir -p "$HASH_DIR"

now() { date -u +%Y%m%dT%H%M%SZ; }
iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
MANIFEST="${HASH_DIR}/evidence_manifest_${now()}.sha256"
COC="${HASH_DIR}/chain_of_custody_manifest.txt"

echo "$(iso_now) | GENERATE_MANIFEST_START user=$(id -un) host=$(hostname -f)" >> "$COC"

# find files in the evidence directories
# ensure stable order with sort -z
find "$CONF_DIR" "$SCREEN_DIR" "$LOG_DIR" "$PCAP_DIR" -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum > "$MANIFEST"

# also create a compact human-readable summary
SUMMARY="${HASH_DIR}/evidence_manifest_summary_${now()}.txt"
echo "Evidence manifest generated: $MANIFEST" > "$SUMMARY"
echo "Generated: $(iso_now)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Top 200 lines of manifest:" >> "$SUMMARY"
head -n 200 "$MANIFEST" >> "$SUMMARY" || true

echo "$(iso_now) | MANIFEST_CREATED file=$(basename "$MANIFEST") entries=$(wc -l < "$MANIFEST")" >> "$COC"
ls -lh "$MANIFEST" >> "$COC" 2>/dev/null || true

cat <<EOF

MANIFEST CREATED: $MANIFEST
SUMMARY: $SUMMARY
Chain of Custody log: $COC

EOF
exit 0
