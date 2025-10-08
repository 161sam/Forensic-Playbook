#!/usr/bin/env bash
set -euo pipefail
PART="${1:-/dev/sdb1}"                          # ggf. anpassen
TS="$(date -u +%Y%m%dT%H%M%SZ)"
MNT="/mnt/usb_ro_${TS}"
OUT="/mnt/forensic_evidence/usb_audit_${TS}"

# helper: sudo_tee <file>
sudo_tee() { sudo tee "$1" >/dev/null; }

# Mount RO
sudo mkdir -p "$MNT" "$OUT"
echo "[*] Mounting $PART read-only at $MNT"
sudo mount -o ro,nodev,noexec,nosuid "$PART" "$MNT"

# 1) df
echo "[*] Filesystem usage"
sudo df -h "$MNT" | sudo_tee "$OUT/df.txt"

# 2) Top-Level Größen
echo "[*] Top-Level Größenübersicht"
sudo du -x -h --max-depth=1 "$MNT" | sort -h | sudo_tee "$OUT/size_top_level.txt"

# 3) Forensik-Kandidaten
echo "[*] Vermutliche Forensik-Artefakte"
sudo grep -RIl --binary-files=text -E \
'(?i)(autopsy|sleuthkit|evidence|case|hash(es)?|sha256sum|md5sum|ddrescue|timeline|ioc|forensic|report|dump|router|tr[-_]?069|pcap|zeek|suricata|sbom|manifest|readme\.md|summary_report\.md|\.(E01|img|dd|raw|gz|xz|zip|7z|pcap|json|csv|log)$)' \
"$MNT" 2>/dev/null | sed "s|$MNT||" | sudo_tee "$OUT/forensic_candidates.txt" || true

# 4) Linux-Root-ähnliche Struktur?
echo "[*] Linux-root-like Prüfliste"
( ls -1 "$MNT" | grep -E '^(bin|sbin|lib|lib64|usr|etc|var|root|opt)$' || true ) | sudo_tee "$OUT/linux_root_like.txt"

# 5) Größte 200 Dateien
echo "[*] Größte 200 Dateien"
sudo find "$MNT" -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM:%TS\t%p\n' \
  | sort -nr | head -n 200 | sed "s|$MNT||" | sudo_tee "$OUT/largest_200.tsv"

# 6) Neueste 200 Dateien
echo "[*] Neueste 200 Dateien"
sudo find "$MNT" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%s\t%p\n' \
  | sort -r | head -n 200 | sed "s|$MNT||" | sudo_tee "$OUT/newest_200.tsv"

# 7) Hash der Top-Level-Dateien
echo "[*] Hash-Liste (Top-Level-Dateien)"
sudo find "$MNT" -maxdepth 1 -type f -print0 | xargs -0 -r sha256sum | sed "s|$MNT||" | sudo_tee "$OUT/top_sha256.txt"

# 8) Mountpoint & Log festhalten
echo "$MNT" | sudo_tee "$OUT/mountpoint.txt"
{
  echo "PART=$PART"
  echo "MNT=$MNT"
  echo "OUT=$OUT"
  date -u +"UTC %Y-%m-%dT%H:%M:%SZ"
} | sudo_tee "$OUT/audit_log.txt"

echo "[*] Fertig. Ergebnisse unter: $OUT"
echo "[*] (Stick bleibt gemountet)"
