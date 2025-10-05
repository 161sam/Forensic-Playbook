#!/usr/bin/env bash
# identify_disks.sh - idempotent: writes only to stdout, no device writes
set -euo pipefail

OUTDIR="${PWD}/forensic_meta_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTDIR"

echo "[*] Ausgabeverzeichnis: $OUTDIR"

# List block devices with model, serial, size
lsblk -o NAME,TRAN,MODEL,SERIAL,SIZE,FSTYPE,MOUNTPOINT > "$OUTDIR/lsblk.txt"
echo "[*] lsblk -> $OUTDIR/lsblk.txt"

# Print fdisk for each sdX
for dev in /dev/sd[a-z]; do
  [[ -b $dev ]] || continue
  echo "======== $dev ========" >> "$OUTDIR/fdisk_all.txt"
  sudo fdisk -l "$dev" >> "$OUTDIR/fdisk_all.txt" 2>/dev/null || true
  # smartctl info if available
  if command -v smartctl >/dev/null 2>&1; then
    sudo smartctl -i "$dev" > "$OUTDIR/$(basename $dev)_smartctl.txt" 2>/dev/null || true
  fi
  # udev info
  udevadm info --query=all --name="$dev" > "$OUTDIR/$(basename $dev)_udev.txt" 2>/dev/null || true
done

echo "[*] Fertig. Prüfe $OUTDIR. Tipp: aktive Linux-Installation erkennt man an ext4/ btrfs Partitionen und /boot LVs."
