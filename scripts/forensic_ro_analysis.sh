#!/usr/bin/env bash
# Forensic Read-Only System Sweep (offline)
# - Mountet Zieldisk/Partition read-only
# - Sammelt Artefakte in LOGDIR/analysis_YYYYmmddTHHMMSSZ
# - Kein Schreiben ins untersuchte Dateisystem
# - Idempotent: erzeugt neuen analysis_* Ordner pro Lauf

set -Eeuo pipefail
export LC_ALL=C
IFS=$'\n\t'

DEVICE="${1:-/dev/nvme0n1}"          # Standard: geklonte Zieldisk
LOGDIR="${2:-/mnt/forensic_workdir}"  # wie beim Clone
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${LOGDIR}/analysis_${TS}"
MNT="${OUT}/mnt"

note(){ echo "[*] $*" >&2; }
ok(){ echo "[+] $*" >&2; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[x] $*" >&2; exit 1; }

mkdir -p "$OUT" "$MNT"

# ---------- Hilfsfunktionen ----------
is_block(){ [[ -b "$1" ]]; }
fs_type_of(){
  local dev="$1"
  blkid -o value -s TYPE "$dev" 2>/dev/null || true
}
mount_ro_fs(){
  # mount_ro_fs <device-part> <mountpoint>
  local part="$1" mp="$2"
  local fstype; fstype="$(fs_type_of "$part")"
  mkdir -p "$mp"
  case "$fstype" in
    ext2|ext3|ext4)   mount -o ro,noload              "$part" "$mp" ;;
    xfs)              mount -o ro,norecovery          "$part" "$mp" ;;
    btrfs)            mount -o ro                      "$part" "$mp" ;;
    vfat|fat|fat32)   mount -o ro,uid=0,gid=0,umask=077 "$part" "$mp" ;;
    ntfs)             mount -o ro                      "$part" "$mp" ;;
    *)                mount -o ro                      "$part" "$mp" ;;
  esac
}

# Umount auf Exit sicherstellen
cleanup(){
  set +e
  if mountpoint -q "$MNT"; then
    umount -R "$MNT" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------- Gerätekontext erfassen ----------
note "Gerätekontext erfassen…"
{
  echo "RUN_UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "DEVICE: $(readlink -f "$DEVICE")"
  echo "LOGDIR: $LOGDIR"
} > "${OUT}/context.txt"

# Basis-Geräteübersicht speichern
lsblk -O > "${OUT}/lsblk_full.txt" 2>/dev/null || true
blkid > "${OUT}/blkid.txt" 2>/dev/null || true
udevadm info --query=all --name="$(readlink -f "$DEVICE")" > "${OUT}/udev_device.txt" 2>/dev/null || true

is_block "$DEVICE" || die "DEVICE ist kein Blockgerät: $DEVICE"

# ---------- Root-FS-Partition bestimmen ----------
note "Bestimme Root-Filesystem-Partition…"

# Kandidaten: alle Partitionen unter DEVICE mit Linux-FS
mapfile -t parts < <(lsblk -ln -o PATH,FSTYPE,SIZE "$DEVICE" | awk '
  $2 ~ /(ext[234]|xfs|btrfs|vfat|fat|fat32|ntfs)/ {print $0}
')

ROOT_PART=""
ROOT_MP=""

# 1) Heuristik: Partition, die /etc/os-release enthält
for line in "${parts[@]}"; do
  p="$(echo "$line" | awk "{print \$1}")"
  tmp="${MNT}/probe"
  mkdir -p "$tmp"
  if mount_ro_fs "$p" "$tmp" 2>/dev/null; then
    if [[ -f "${tmp}/etc/os-release" ]]; then
      ROOT_PART="$p"
      umount "$tmp" 2>/dev/null || true
      rmdir "$tmp" 2>/dev/null || true
      break
    fi
    umount "$tmp" 2>/dev/null || true
    rmdir "$tmp" 2>/dev/null || true
  fi
done

# 2) Fallback: größte Linux-FS-Partition (ext*/xfs/btrfs)
if [[ -z "$ROOT_PART" && ${#parts[@]} -gt 0 ]]; then
  ROOT_PART="$(printf '%s\n' "${parts[@]}" | awk '{print $1, $3}' | sort -k2,2hr | head -n1 | awk '{print $1}')"
fi

[[ -n "$ROOT_PART" ]] || die "Konnte Root-Partition nicht bestimmen. Prüfe manuell mit lsblk -o PATH,FSTYPE,SIZE $DEVICE"

# ---------- Root-FS mounten (RO) ----------
ROOT_MP="${MNT}/rootfs"
note "Mount RO: $ROOT_PART -> $ROOT_MP"
mount_ro_fs "$ROOT_PART" "$ROOT_MP"

# Kontext aktualisieren
{
  echo "ROOT_PART: $ROOT_PART"
  echo "ROOT_MP: $ROOT_MP"
} >> "${OUT}/context.txt"

# Boot/EFI ggf. mounten (RO)
for p in $(lsblk -ln -o PATH,FSTYPE "$DEVICE" | awk '$2 ~ /(vfat|fat|fat32)/ {print $1}'); do
  # typischerweise EFI
  mp="${MNT}/efi_$(basename "$p")"
  note "Mount RO EFI: $p -> $mp"
  mount_ro_fs "$p" "$mp" || true
done

# Zusätzlich: LUKS-Erkennung nur als Hinweis
lsblk -o NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}' > "${OUT}/luks_partitions.txt" 2>/dev/null || true

# ---------- Artefaktsammlung ----------
note "Sammle Artefakte (nur Lesen)…"

# 0) Kurzer Überblick über /etc und /var/log
mkdir -p "${OUT}/etc" "${OUT}/logs"
cp -a "${ROOT_MP}/etc/passwd" "${OUT}/etc/passwd" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/shadow" "${OUT}/etc/shadow" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/group"  "${OUT}/etc/group"  2>/dev/null || true
cp -a "${ROOT_MP}/etc/sudoers" "${OUT}/etc/sudoers" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/sudoers.d" "${OUT}/etc/sudoers.d" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/os-release" "${OUT}/etc/os-release" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/issue" "${OUT}/etc/issue" 2>/dev/null || true

# 1) systemd Units und Enabled-Links
note "Systemd-Units/Timer sammeln…"
mkdir -p "${OUT}/systemd"
cp -a "${ROOT_MP}/etc/systemd" "${OUT}/systemd/etc_systemd" 2>/dev/null || true
cp -a "${ROOT_MP}/lib/systemd" "${OUT}/systemd/lib_systemd" 2>/dev/null || true
cp -a "${ROOT_MP}/usr/lib/systemd" "${OUT}/systemd/usr_lib_systemd" 2>/dev/null || true
# Enabled-Zustände über Verzeichnisstruktur
find "${OUT}/systemd" -type l -lname '*/*.service' -o -lname '*/*.timer' > "${OUT}/systemd/enabled_links.txt" 2>/dev/null || true
# Rohsuche nach ExecStart
grep -R --line-number -I -E '^\s*ExecStart=' "${OUT}/systemd" > "${OUT}/systemd/execstart_lines.txt" 2>/dev/null || true

# 2) Cron/At
note "Cron/At Jobs sammeln…"
mkdir -p "${OUT}/schedules"
cp -a "${ROOT_MP}/etc/crontab" "${OUT}/schedules/etc_crontab" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/cron.*" "${OUT}/schedules/" 2>/dev/null || true
cp -a "${ROOT_MP}/var/spool/cron" "${OUT}/schedules/spool_cron" 2>/dev/null || true
cp -a "${ROOT_MP}/var/spool/at"   "${OUT}/schedules/spool_at"   2>/dev/null || true

# 3) SSH
note "SSH-Konfiguration & Keys sammeln…"
mkdir -p "${OUT}/ssh"
cp -a "${ROOT_MP}/etc/ssh/sshd_config" "${OUT}/ssh/sshd_config" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/ssh/ssh_config"  "${OUT}/ssh/ssh_config"  2>/dev/null || true
# User-Autorized Keys (nur Inhalte)
find "${ROOT_MP}/home" -maxdepth 3 -type f -name "authorized_keys" -print -exec bash -c 'echo "----- $0 -----"; cat "$0"' {} \; \
  > "${OUT}/ssh/authorized_keys_dump.txt" 2>/dev/null || true
# Private Keys erkennen und Dump placeholder (keine Inhalte!)
find "${ROOT_MP}/home" -type f -regex '.*\.ssh/.*_rsa\|.*\.ssh/id_ed25519\|.*\.ssh/id_rsa' -print > "${OUT}/ssh/private_keys_paths.txt" 2>/dev/null || true

# 4) SUID/SGID & Capabilities
note "SUID/SGID & Capabilities…"
mkdir -p "${OUT}/priv"
# Nur lokales Root-FS (keine anderen Mounts)
find "${ROOT_MP}" -xdev -type f -perm -4000 -ls > "${OUT}/priv/suid_files.txt" 2>/dev/null || true
find "${ROOT_MP}" -xdev -type f -perm -2000 -ls > "${OUT}/priv/sgid_files.txt" 2>/dev/null || true
if command -v getcap >/dev/null 2>&1; then
  getcap -r "${ROOT_MP}" 2>/dev/null > "${OUT}/priv/file_capabilities.txt" || true
fi

# 5) Paketquellen / Package-History (Debian/Ubuntu + rpm-Fallback)
note "Paketquellen & History…"
mkdir -p "${OUT}/packages"
cp -a "${ROOT_MP}/etc/apt" "${OUT}/packages/apt" 2>/dev/null || true
cp -a "${ROOT_MP}/var/log/apt" "${OUT}/packages/apt_logs" 2>/dev/null || true
cp -a "${ROOT_MP}/var/lib/dpkg/status" "${OUT}/packages/dpkg_status" 2>/dev/null || true
# rpm-basierte Systeme
cp -a "${ROOT_MP}/var/log/dnf"* "${OUT}/packages/" 2>/dev/null || true
cp -a "${ROOT_MP}/var/log/yum"* "${OUT}/packages/" 2>/dev/null || true
cp -a "${ROOT_MP}/var/lib/rpm"  "${OUT}/packages/rpmdb" 2>/dev/null || true

# 6) Kernel/Boot
note "Kernel-/Boot-Artefakte…"
mkdir -p "${OUT}/boot"
cp -a "${ROOT_MP}/boot" "${OUT}/boot/boot_tree" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/default/grub" "${OUT}/boot/grub_default" 2>/dev/null || true

# 7) Logs
note "Logs (klassisch & journald)…"
# Klassische /var/log Verzeichnisse (nur Kopie, kein Schreiben ins Original)
rsync -a --chmod=Du=rwx,Dg=,Do=,Fu=rw,Fg=,Fo= "${ROOT_MP}/var/log/" "${OUT}/logs/var_log/" 2>/dev/null || true
# Journald offline lesen
if command -v journalctl >/dev/null 2>&1; then
  journalctl --root="$ROOT_MP" --no-pager -o short-iso > "${OUT}/logs/journalctl_all.txt" 2>/dev/null || true
fi

# 8) Netzspuren (Konfiguration)
note "Netzwerk-/Firewall-Konfigs…"
mkdir -p "${OUT}/network"
cp -a "${ROOT_MP}/etc/ufw" "${OUT}/network/ufw" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/iptables" "${OUT}/network/iptables" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/network" "${OUT}/network/etc_network" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/netplan" "${OUT}/network/netplan" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/resolv.conf" "${OUT}/network/resolv.conf" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/hosts" "${OUT}/network/hosts" 2>/dev/null || true

# 9) Jüngste Dateien (Heuristik) – nur Liste
note "Jüngste Dateien (<= 15 Tage, > 1MiB) listen…"
find "${ROOT_MP}" -xdev -type f -mtime -15 -size +1M -printf "%TY-%Tm-%Td %TH:%TM:%TS %p (%s bytes)\n" \
  | sort -r > "${OUT}/recent_files_15d_over1MiB.txt" 2>/dev/null || true

# 10) Partitions-/Mount-Übersicht am Ende noch einmal
lsblk -f > "${OUT}/lsblk_summary.txt" 2>/dev/null || true
mount | grep -- " ${MNT}" > "${OUT}/active_mounts.txt" 2>/dev/null || true

ok "Sammlung abgeschlossen: ${OUT}"
echo "Hinweis: Mounts werden beim Exit sauber gelöst."
