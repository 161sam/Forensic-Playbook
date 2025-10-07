#!/usr/bin/env bash
# find potential backup/restore/config artifacts in conf dir and nearby
set -euo pipefail
CONF_DIR="${1:-/mnt/FORNSIC_20251006/conf}"
OUT_DIR="${2:-/mnt/FORNSIC_20251006/logs}/backups_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT_DIR"

# search strings that indicate backup/restore or config upload/download
grep -iR --line-number --binary-files=without-match -E "backup|restore|config|export|import|fw|firmware|cfg|cfg_backup|.bin|.cfg|.xml" "$CONF_DIR" > "$OUT_DIR/backup_hits.txt" 2>/dev/null || true

# list likely backup files (extensions) in top-level dirs (don't descend outside)
find "$CONF_DIR" -maxdepth 2 -type f \( -iname '*.bin' -o -iname '*.cfg' -o -iname '*.xml' -o -iname '*backup*' \) -print > "$OUT_DIR/backup_files_list.txt" || true

echo "Backup/restore hits and file list saved in: $OUT_DIR"
