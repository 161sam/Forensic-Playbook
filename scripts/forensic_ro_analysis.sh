#!/usr/bin/env bash
# Forensic Read-Only System Sweep (offline)
# - Mountet Ziel-Disk RO
# - Sammelt Artefakte in LOGDIR/analysis_YYYYmmddTHHMMSSZ
# - Kein Schreiben ins untersuchte Dateisystem

export LC_ALL=C
set -Eeuo pipefail

DEVICE="${1:-/dev/nvme0n1}"         # geklonte Zieldisk
LOGDIR="${2:-/mnt/forensic_workdir}" # wie beim Clone
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${LOGDIR}/analysis_${TS}"
MNT="${OUT}/mnt"
mkdir -p "$OUT" "$MNT"

note(){ echo "[*] $*"; }
ok(){ echo "[✓] $*"; }
err(){ echo "ERROR: $*" >&2; exit 1; }

[[ -b "$DEVICE" ]] || err "Kein Blockdevice: $DEVICE"
[[ -w "$LOGDIR" ]] || err "LOGDIR nicht schreibbar: $LOGDIR"

# ---------- Helper ----------
_ro_mount() {
  local dev="$1" mpt="$2" fstype
  mkdir -p "$mpt"
  fstype="$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)"
  case "$fstype" in
    ext2|ext3|ext4)  mount -o ro,noload "$dev" "$mpt" ;;
    xfs)             mount -o ro,norecovery "$dev" "$mpt" ;;
    btrfs|ntfs|vfat|exfat) mount -o ro "$dev" "$mpt" ;;
    "") note "Kein FS auf $dev — überspringe"; return 0 ;;
    *)  mount -o ro "$dev" "$mpt" || note "Generic ro-Mount auf $dev fehlgeschlagen" ;;
  esac
}

_umount_all() {
  # in umgekehrter Tiefe aushängen (nur unterhalb $MNT)
  awk '{print length($2), $2}' /proc/self/mounts | sort -nr | awk '{print $2}' \
    | grep -E "^${MNT}(/|$)" || true
  awk '{print length($2), $2}' /proc/self/mounts | sort -nr | awk '{print $2}' \
    | grep -E "^${MNT}(/|$)" | while read -r p; do umount "$p" 2>/dev/null || true; done
}
trap _umount_all EXIT

# ---------- Inventar ----------
note "Inventarisierung der Partitionen…"
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT "$DEVICE" > "${OUT}/lsblk_target.txt"

# Partitionsliste ermitteln
mapfile -t PARTS < <(lsblk -ln -o NAME,TYPE "$DEVICE" | awk '$2=="part"{print $1}')
[[ "${#PARTS[@]}" -gt 0 ]] || err "Keine Partitionen erkannt auf ${DEVICE}"

# LUKS-Erkennung (nur Listing, kein Unlock)
if command -v cryptsetup >/dev/null 2>&1; then
  lsblk -ln -o NAME,FSTYPE "$DEVICE" | awk '$2=="crypto_LUKS"{print "/dev/"$1}' \
    > "${OUT}/luks_partitions.txt" || true
fi

# ---------- Mount aller Partitionen (read-only) ----------
for pn in "${PARTS[@]}"; do
  dev="/dev/${pn}"
  mp="${MNT}/${pn}"
  _ro_mount "$dev" "$mp" && ok "Mounted $dev -> $mp (ro)" || note "Mount skipped: $dev"
done

# ---------- Root-FS ermitteln ----------
ROOT_MP=""
for pn in "${PARTS[@]}"; do
  mp="${MNT}/${pn}"
  if [[ -r "${mp}/etc/os-release" ]]; then ROOT_MP="$mp"; break; fi
done

# Fallback: größte Linux-FS-Partition (ext[2-4], xfs, btrfs)
if [[ -z "$ROOT_MP" ]]; then
  ROOT_CAND="$(lsblk -b -ln -o NAME,SIZE,FSTYPE "$DEVICE" \
    | awk '$3 ~ /(ext[234]|xfs|btrfs)$/ {print $1, $2}' \
    | sort -k2,2nr | head -n1 | awk '{print $1}')"
  [[ -n "$ROOT_CAND" ]] && ROOT_MP="${MNT}/${ROOT_CAND}"
fi
[[ -n "$ROOT_MP" ]] || err "Root-FS nicht eindeutig ermittelbar."

ok "Root-FS: $ROOT_MP"

# ---------- Kontext schreiben (für Reports) ----------
{
  echo "DEVICE: $DEVICE"
  echo "ROOT_MP: $ROOT_MP"
  echo "ANALYSIS_DIR: $OUT"
  date -u +"RUN_UTC: %Y-%m-%dT%H:%M:%SZ"
} > "${OUT}/context.txt"

# ---------- Sammlung ----------
note "Sammle Basis-Metadaten…"
cp -a "${ROOT_MP}/etc/os-release" "${OUT}/os-release" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/hostname"    "${OUT}/hostname"  2>/dev/null || true
cp -a "${ROOT_MP}/etc/hosts"       "${OUT}/hosts"     2>/dev/null || true
cp -a "${ROOT_MP}/etc/resolv.conf" "${OUT}/resolv.conf" 2>/dev/null || true

note "Systemd-Units & Autostarts…"
mkdir -p "${OUT}/systemd"
find "${ROOT_MP}/etc/systemd" -maxdepth 3 -type f -name "*.service" -print0 2>/dev/null \
  | xargs -0 -I{} bash -lc 'rel="${1#'"${ROOT_MP}"'/}"; echo "$rel";' _ {} \
  > "${OUT}/systemd/etc_services.txt" || true
find "${ROOT_MP}/usr/lib/systemd" -maxdepth 3 -type f -name "*.service" -print0 2>/dev/null \
  | xargs -0 -I{} bash -lc 'rel="${1#'"${ROOT_MP}"'/}"; echo "$rel";' _ {} \
  > "${OUT}/systemd/usrlib_services.txt" || true
find "${ROOT_MP}/etc/systemd/system" -type d -name "*.wants" -print -o -type l -print 2>/dev/null \
  > "${OUT}/systemd/enabled_wants.txt" || true
find "${ROOT_MP}" -type f -name "*.timer" -print 2>/dev/null \
  | sed "s#^${ROOT_MP}/##" > "${OUT}/systemd/timers.txt" || true

note "Cron & At-Jobs…"
mkdir -p "${OUT}/cron"
for d in cron.d cron.daily cron.hourly cron.weekly cron.monthly; do
  [[ -d "${ROOT_MP}/etc/$d" ]] && (cd "${ROOT_MP}/etc" && tar -cf - "$d") > "${OUT}/cron/${d}.tar" 2>/dev/null || true
done
cp -a "${ROOT_MP}/etc/crontab"         "${OUT}/cron/crontab"     2>/dev/null || true
cp -a "${ROOT_MP}/var/spool/cron"      "${OUT}/cron/spool_cron"  2>/dev/null || true
cp -a "${ROOT_MP}/var/spool/at"        "${OUT}/cron/spool_at"    2>/dev/null || true

note "SSH & sudoers…"
mkdir -p "${OUT}/ssh" "${OUT}/sudo"
cp -a "${ROOT_MP}/etc/ssh" "${OUT}/ssh/etc_ssh" 2>/dev/null || true
cp -a "${ROOT_MP}/home"    "${OUT}/ssh/home_keys" 2>/dev/null || true  # nur Verzeichnisstruktur/Dateinamen
# Private Keys im Export verstecken
find "${OUT}/ssh/home_keys" -type f -name "id_*" -exec chmod 000 {} + 2>/dev/null || true
cp -a "${ROOT_MP}/etc/sudoers"   "${OUT}/sudo/sudoers"   2>/dev/null || true
cp -a "${ROOT_MP}/etc/sudoers.d" "${OUT}/sudo/sudoers.d" 2>/dev/null || true

note "Benutzer & Gruppen (Kopien)…"
mkdir -p "${OUT}/etc"
for f in passwd group shadow gshadow subuid subgid login.defs securetty shells; do
  cp -a "${ROOT_MP}/etc/${f}" "${OUT}/etc/${f}" 2>/dev/null || true
done
chmod 600 "${OUT}/etc/shadow" "${OUT}/etc/gshadow" 2>/dev/null || true

note "Persistenz-Verdachtsorte…"
mkdir -p "${OUT}/persistence"
cp -a "${ROOT_MP}/etc/rc.local"     "${OUT}/persistence/rc.local"    2>/dev/null || true
cp -a "${ROOT_MP}/etc/profile.d"    "${OUT}/persistence/profile.d"   2>/dev/null || true
find "${ROOT_MP}/etc/systemd" -type f \( -name "*.path" -o -name "*.timer" \) -print 2>/dev/null \
  | sed "s#^${ROOT_MP}/##" > "${OUT}/persistence/systemd_paths_timers.txt" || true
find "${ROOT_MP}/home" -maxdepth 2 -type f \
  \( -name ".bashrc" -o -name ".zshrc" -o -name ".profile" -o -name ".bash_profile" \) -print 2>/dev/null \
  | sed "s#^${ROOT_MP}/##" > "${OUT}/persistence/user_shell_autoruns.txt" || true

note "Logs (Dateien)…"
mkdir -p "${OUT}/var_log"
# Journald offline extrahieren (falls vorhanden)
if command -v journalctl >/dev/null 2>&1 && [[ -d "${ROOT_MP}/var/log/journal" ]]; then
  journalctl --root="${ROOT_MP}" --no-pager -xb > "${OUT}/var_log/boot_journal.txt" 2>/dev/null || true
fi
# klassische Logs kopieren (tar, um Meta zu behalten)
( cd "${ROOT_MP}/var" && tar --warning=no-file-changed -cf - log ) > "${OUT}/var_log/var_log.tar" 2>/dev/null || true

note "SUID/SGID & Linux Capabilities…"
mkdir -p "${OUT}/binaries"
find "${ROOT_MP}" -xdev -type f -perm -4000 -print 2>/dev/null | sed "s#^${ROOT_MP}/##" > "${OUT}/binaries/suid.txt" || true
find "${ROOT_MP}" -xdev -type f -perm -2000 -print 2>/dev/null | sed "s#^${ROOT_MP}/##" > "${OUT}/binaries/sgid.txt" || true
# Hashes für SUID-Dateien
if [[ -s "${OUT}/binaries/suid.txt" ]]; then
  while read -r rel; do
    sha256sum "${ROOT_MP}/${rel}" || true
  done < "${OUT}/binaries/suid.txt" > "${OUT}/binaries/suid.sha256" 2>/dev/null || true
fi
# Capabilities (falls Tool vorhanden)
if command -v getcap >/dev/null 2>&1; then
  getcap -r "${ROOT_MP}" 2>/dev/null | sed "s#^${ROOT_MP}/##" > "${OUT}/binaries/capabilities.txt" || true
fi

note "Netzwerk-Profile…"
mkdir -p "${OUT}/network"
cp -a "${ROOT_MP}/etc/NetworkManager/system-connections" "${OUT}/network/nm-connections" 2>/dev/null || true
cp -a "${ROOT_MP}/etc/netplan"                           "${OUT}/network/netplan"        2>/dev/null || true
cp -a "${ROOT_MP}/etc/hosts.allow"                       "${OUT}/network/hosts.allow"    2>/dev/null || true
cp -a "${ROOT_MP}/etc/hosts.deny"                        "${OUT}/network/hosts.deny"     2>/dev/null || true

note "Paketquellen & Install-Historien…"
mkdir -p "${OUT}/packages"
cp -a "${ROOT_MP}/etc/apt"        "${OUT}/packages/apt"       2>/dev/null || true
cp -a "${ROOT_MP}/var/log/apt"    "${OUT}/packages/apt_logs"  2>/dev/null || true
cp -a "${ROOT_MP}/var/lib/dpkg/status" "${OUT}/packages/dpkg_status" 2>/dev/null || true
# rpm-basierte Fallbacks
cp -a "${ROOT_MP}/var/log/dnf"*   "${OUT}/packages/"          2>/dev/null || true
cp -a "${ROOT_MP}/var/log/yum"*   "${OUT}/packages/"          2>/dev/null || true
cp -a "${ROOT_MP}/var/lib/rpm"    "${OUT}/packages/rpmdb"     2>/dev/null || true

note "Kernel-/Boot-Artefakte…"
mkdir -p "${OUT}/boot"
cp -a "${ROOT_MP}/boot"                "${OUT}/boot/boot_tree"   2>/dev/null || true
cp -a "${ROOT_MP}/etc/default/grub"    "${OUT}/boot/grub_default" 2>/dev/null || true

ok "Sammlung abgeschlossen: ${OUT}"
echo "Hinweis: Mounts werden beim Exit sauber gelöst."
