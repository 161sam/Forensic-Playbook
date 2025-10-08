#!/usr/bin/env bash
# triage_offline.sh – Offline-Forensik für gemountetes Linux-Root
# Voraussetzung:
#   - kompromittiertes Root-FS: /mnt/korrupt_root (ro,norecovery)
#   - Ziel (rw): /mnt/usb_rw
#   - Ausführung als root, NICHT chrooten
# Nutzung:
# chmod +x /root/triage_offline.sh
# SRC=/mnt/korrupt_root OUTBASE=/mnt/usb_rw /root/triage_offline.sh

set -Eeuo pipefail
IFS=$'\n\t'
TZ=UTC
export TZ

SRC=${SRC:-/mnt/korrupt_root}
OUTBASE=${OUTBASE:-/mnt/usb_rw}
CASE=${CASE:-case_$(date -u +%Y%m%dT%H%MZ)}
OUT="$OUTBASE/$CASE"

# --- Sanity-Checks ---
echo "[*] Quelle: $SRC  → Ziel: $OUT"
if ! mountpoint -q "$OUTBASE"; then echo "[!] $OUTBASE nicht gemountet"; exit 1; fi
if ! findmnt -no OPTIONS "$SRC" | grep -qw ro; then
  echo "[!] $SRC ist nicht read-only gemountet. Abbruch."; exit 1
fi

# --- Struktur & Metadaten ---
mkdir -p "$OUT"/{meta,logs,hashes,artifacts,findings}
{
  date -u +"%F %T%Z"
  echo "Kali Host uname: $(uname -a)"
  echo "Quelle mount: $(findmnt -no FSTYPE,OPTIONS $SRC)"
  echo "Ziel mount:   $(findmnt -no FSTYPE,OPTIONS $OUTBASE)"
  echo "Quell-OS (os-release falls vorhanden):"
  sed -n '1,200p' "$SRC/etc/os-release" 2>/dev/null || true
} > "$OUT/meta/_env.txt"

lsblk -f > "$OUT/meta/lsblk_host.txt" 2>&1 || true
findmnt -R "$SRC" > "$OUT/meta/findmnt_src.txt" 2>&1 || true
df -hT "$SRC" "$OUTBASE" > "$OUT/meta/df.txt" 2>&1 || true

# --- Relevante Artefakte konservieren (nur Kopien) ---
echo "[*] Kopiere Log-/Key-/Config-Artefakte…"
# Logs (klassisch + journal)
mkdir -p "$OUT/artifacts"/{var_log,var_log_journal,etc_ssh,etc_cron,boot,accounts}
rsync -a --info=stats0 \
  --include='/auth.log*' --include='/secure*' --include='/syslog*' \
  --include='/messages*' --include='/dmesg*' --include='/kern.log*' \
  --include='/wtmp*' --include='/btmp*' --include='/lastlog*' \
  --include='*/' --exclude='*' \
  "$SRC/var/log/" "$OUT/artifacts/var_log/" 2>/dev/null || true

if [ -d "$SRC/var/log/journal" ]; then
  rsync -a "$SRC/var/log/journal/" "$OUT/artifacts/var_log_journal/" || true
fi

# SSH/Accounts/Boot
rsync -a --info=stats0 "$SRC/etc/ssh/" "$OUT/artifacts/etc_ssh/" 2>/dev/null || true
rsync -a --info=stats0 "$SRC/boot/"    "$OUT/artifacts/boot/"     2>/dev/null || true
rsync -a --info=stats0 "$SRC/etc/passwd" "$SRC/etc/shadow" "$SRC/etc/group" "$OUT/artifacts/accounts/" 2>/dev/null || true

# Cron & systemd
rsync -a --info=stats0 "$SRC/etc/cron.d" "$SRC/etc/cron.daily" "$SRC/etc/cron.hourly" \
  "$SRC/etc/cron.weekly" "$SRC/etc/cron.monthly" "$SRC/etc/crontab" \
  "$SRC/var/spool/cron" "$SRC/var/spool/cron/crontabs" \
  "$OUT/artifacts/etc_cron/" 2>/dev/null || true
rsync -a --info=stats0 \
  "$SRC/etc/systemd/system" "$SRC/usr/lib/systemd/system" "$SRC/lib/systemd/system" \
  "$OUT/artifacts/" 2>/dev/null || true

# LD-Persistence & Profile-Hooks
for f in /etc/ld.so.preload /etc/ld.so.conf /etc/profile /etc/bash.bashrc; do
  [ -e "$SRC$f" ] && rsync -a "$SRC$f" "$OUT/artifacts/$(echo "$f" | tr '/' '_')" || true
done
rsync -a "$SRC/etc/ld.so.conf.d/" "$OUT/artifacts/ld.so.conf.d/" 2>/dev/null || true
rsync -a "$SRC/etc/profile.d/"    "$OUT/artifacts/profile.d/"    2>/dev/null || true

# Home-SSH & Shell-Historien (nur Metadaten + Kopie falls vorhanden)
find "$SRC/home" "$SRC/root" -maxdepth 3 -type f \( -name "authorized_keys" -o -name "id_*" -o -name ".bash_history" -o -name ".zsh_history" \) -print \
  | tee "$OUT/findings/home_keys_and_histories.list" \
  | while read -r p; do
      d="$OUT/artifacts/home$(dirname "${p#$SRC}")"; mkdir -p "$d"; rsync -a "$p" "$d/" 2>/dev/null || true
    done

# --- SSH/Log-Auswertung (auth.log/secure, wtmp/btmp) ---
echo "[*] SSH/Anmeldeereignisse aggregieren…"
shopt -s nullglob
AUTHFILES=( "$SRC/var/log/auth.log" "$SRC/var/log/auth.log".* "$SRC/var/log/secure" "$SRC/var/log/secure".* )
# zcat -f behandelt plain & .gz
zcat -f -- "${AUTHFILES[@]}" 2>/dev/null \
  | tee "$OUT/logs/auth_all.txt" \
  | awk '
    /Failed password/      {print "FAIL\t"$0}
    /Invalid user/         {print "INVALID\t"$0}
    /Accepted (password|publickey)/ {print "OK\t"$0}
    /sudo:.*authentication failure/ {print "SUDOFAIL\t"$0}
  ' > "$OUT/logs/auth_events_tagged.tsv" || true

# Top-IPs & -User
grep -E "FAIL|INVALID|OK" "$OUT/logs/auth_events_tagged.tsv" \
 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
 | sort | uniq -c | sort -nr > "$OUT/findings/ssh_top_ips.txt" || true

grep -E "FAIL|INVALID" "$OUT/logs/auth_events_tagged.tsv" \
 | grep -Eo 'user [^ ]+' | awk '{print $2}' \
 | sort | uniq -c | sort -nr > "$OUT/findings/ssh_top_usernames.txt" || true

grep -E "^OK" "$OUT/logs/auth_events_tagged.tsv" > "$OUT/findings/ssh_accepts.txt" || true

# wtmp/btmp
LASTBIN=$(command -v last || true)
if [ -n "$LASTBIN" ]; then
  [ -f "$SRC/var/log/wtmp" ] && last  -f "$SRC/var/log/wtmp"  > "$OUT/logs/last_wtmp.txt"  || true
  [ -f "$SRC/var/log/btmp" ] && lastb -f "$SRC/var/log/btmp" > "$OUT/logs/lastb_btmp.txt" || true
fi

# --- Persistence & verdächtige Einträge suchen ---
echo "[*] Suche nach Persistence (systemd/cron/ld.so/profile/sudoers)…"
# systemd Services mit verdächtigen ExecStart-Inhalten
grep -RInE 'ExecStart=.*(curl|wget|bash -c|sh -c|/tmp|/dev/shm|/var/tmp|python -c|perl -e|nc |socat|nohup)' \
  "$SRC/etc/systemd" "$SRC/usr/lib/systemd" "$SRC/lib/systemd" 2>/dev/null \
  | tee "$OUT/findings/systemd_suspicious.txt" || true

# Cron-Jobs mit ähnlichen Mustern
grep -RInE '(curl|wget|/tmp|/dev/shm|/var/tmp|base64 -d|bash -c|python -c|perl -e|nc |socat)' \
  "$SRC/etc/cron"* "$SRC/var/spool/cron" 2>/dev/null \
  | tee "$OUT/findings/cron_suspicious.txt" || true

# /etc/ld.so.preload (Rootkits)
[ -f "$SRC/etc/ld.so.preload" ] && cat "$SRC/etc/ld.so.preload" > "$OUT/findings/ld.so.preload.txt" || true

# sudoers (NOPASSWD / ALL)
grep -RInE '(^[^#].*ALL=\(ALL\).*NOPASSWD|^%?sudo|!authenticate)' "$SRC/etc/sudoers" "$SRC/etc/sudoers.d" 2>/dev/null \
  | tee "$OUT/findings/sudoers_review.txt" || true

# --- SUID/SGID & Capabilities ---
echo "[*] SUID/SGID & file capabilities…"
find "$SRC" -xdev -type f \( -perm -4000 -o -perm -2000 \) \
  -exec stat -c "%U:%G %A %s %y %n" {} + \
  | sort > "$OUT/findings/suid_sgid_files.txt" || true

if command -v getcap >/dev/null 2>&1; then
  getcap -r "$SRC" 2>/dev/null | sort > "$OUT/findings/file_capabilities.txt" || true
fi

# Welt-schreibbare Verzeichnisse außerhalb der üblichen Orte
find "$SRC" -xdev -type d -perm -0002 ! -path "$SRC/tmp/*" ! -path "$SRC/var/tmp/*" ! -path "$SRC/dev/shm/*" \
  > "$OUT/findings/world_writable_dirs.txt" || true

# --- ELF-Binaries an komischen Orten ---
echo "[*] Suche ELF-Binaries in tmp/dev.shm/var.tmp/home…"
for d in "$SRC/tmp" "$SRC/var/tmp" "$SRC/dev/shm" "$SRC/run" "$SRC/home"; do
  [ -d "$d" ] || continue
  find "$d" -type f -size +0 -maxdepth 5 -print0 \
    | xargs -0 file -n -E 2>/dev/null \
    | grep -F 'ELF' \
    > "$OUT/findings/elf_in_user_areas.txt" || true
done

# --- String-Heuristiken (Miner, dreckige Tricks) ---
grep -RInE '(xmrig|minerd|cpuminer|stratum|wallet|/dev/tcp/|curl .*http|wget .*http|base64 -d|eval |LD_PRELOAD|chattr -i|nohup|cron\.d/\.|systemd.*\.service.*After=network\.target.*ExecStart=.*(curl|wget))' \
  "$SRC" 2>/dev/null > "$OUT/findings/strings_suspicious_grep.txt" || true

# --- Paket-/Integritätschecks (falls verfügbar, offline) ---
echo "[*] Integrität prüfen (debsums/dpkg) – wenn vorhanden…"
if command -v debsums >/dev/null 2>&1; then
  debsums --root="$SRC" -s > "$OUT/findings/debsums_mismatches.txt" 2>&1 || true
fi
if command -v dpkg >/dev/null 2>&1; then
  # dpkg -V ohne chroot (liest DB), kann laut Systemzustand Rauschen erzeugen, ist aber hilfreich
  dpkg --admindir="$SRC/var/lib/dpkg" -V > "$OUT/findings/dpkg_V.txt" 2>&1 || true
fi

# --- Hashes der Systembinaries & libs ---
echo "[*] Hashes erzeugen (sha256) für Kernpfade…"
HASHLIST="$OUT/hashes/core_sha256.txt"
find "$SRC/bin" "$SRC/sbin" "$SRC/usr/bin" "$SRC/usr/sbin" "$SRC/lib" "$SRC/lib64" "$SRC/usr/lib" -xdev -type f -print0 2>/dev/null \
 | xargs -0 sha256sum > "$HASHLIST" 2>/dev/null || true

# --- ClamAV/YARA/Lynis (nur wenn installiert) ---
if command -v clamscan >/dev/null 2>&1; then
  echo "[*] ClamAV-Scan… (kann dauern)"
  clamscan -ri --max-filesize=200M --max-scansize=1500M --cross-fs=no "$SRC" \
    -l "$OUT/logs/clamav.log" || true
fi

# YARA (nur falls Regeln vorhanden)
if command -v yara >/dev/null 2>&1; then
  for RULEDIR in /usr/share/yara* /usr/share/yara/rules; do
    [ -d "$RULEDIR" ] || continue
    echo "[*] YARA mit Regeln aus $RULEDIR …"
    yara -r -f "$RULEDIR" "$SRC" > "$OUT/logs/yara_matches.txt" 2>/dev/null || true
    break
  done
fi

# Lynis (unterstützt --rootdir)
if command -v lynis >/dev/null 2>&1; then
  echo "[*] Lynis Offline-Audit…"
  lynis audit system --rootdir "$SRC" --quick --logfile "$OUT/logs/lynis.log" --no-colors || true
fi

# journal offline lesen (falls möglich)
if command -v journalctl >/dev/null 2>&1 && [ -d "$SRC/var/log/journal" ]; then
  echo "[*] Exportiere Journal…"
  journalctl -D "$SRC/var/log/journal" --no-pager -o short-iso > "$OUT/logs/journal_export.txt" 2>/dev/null || true
fi

# --- Zusammenfassung ---
{
  echo "=== QUICK SUMMARY (UTC) ==="
  date -u +"%F %T%Z"
  echo
  echo "[Top SSH-IPs]"; head -n 20 "$OUT/findings/ssh_top_ips.txt" 2>/dev/null || true
  echo
  echo "[Top Usernames]"; head -n 20 "$OUT/findings/ssh_top_usernames.txt" 2>/dev/null || true
  echo
  echo "[Akzeptierte SSH-Logins - letzte 50]"; tail -n 50 "$OUT/findings/ssh_accepts.txt" 2>/dev/null || true
  echo
  echo "[SUID/SGID count] $(wc -l < "$OUT/findings/suid_sgid_files.txt" 2>/dev/null || echo 0)"
  echo "[ELF in tmp/dev/shm/home count] $(wc -l < "$OUT/findings/elf_in_user_areas.txt" 2>/dev/null || echo 0)"
} > "$OUT/README_FIRST.txt"

echo "[+] Fertig. Ergebnisse: $OUT"
