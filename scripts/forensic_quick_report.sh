#!/usr/bin/env bash
set -Eeuo pipefail

LOGDIR="${2:-/mnt/forensic_workdir}"
BASE="${1:-}"
if [[ -z "$BASE" ]]; then
  # neuestes analysis_* in LOGDIR wählen
  BASE="$(ls -d "$LOGDIR"/analysis_* 2>/dev/null | tail -n1 || true)"
fi
[[ -n "${BASE:-}" && -d "$BASE" ]] || { echo "Kein analysis_*-Ordner gefunden. Usage: $0 /pfad/zu/analysis_YYYYmmddTHHMMSSZ [LOGDIR]"; exit 1; }

OUT="$BASE/REPORT.txt"
ROOT_MP="$(awk -F': ' '/ROOT_MP:/{print $2}' "$BASE/context.txt" 2>/dev/null || true)"
[[ -n "${ROOT_MP:-}" && -d "$ROOT_MP" ]] || ROOT_MP="$BASE/mnt"

say(){ printf "%s\n" "$*" | tee -a "$OUT" >/dev/null; }
sep(){ printf -- "--------------------------------------------------------------------------------\n" | tee -a "$OUT" >/dev/null; }
hdr(){ printf "\n## %s\n" "$1" | tee -a "$OUT" >/dev/null; }

: > "$OUT"
say "# Forensic Quick Report"
say "Pfad: $BASE"
say "Root-FS (ro gemountet): ${ROOT_MP:-?}"
say "Zeitpunkt (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sep

# 1) OS & Host
hdr "System-Basis"
[[ -f "$BASE/os-release" ]] && sed -n '1,5p' "$BASE/os-release" | tee -a "$OUT" >/dev/null
[[ -f "$BASE/hostname"   ]] && { printf "Hostname: "; cat "$BASE/hostname"; } | tee -a "$OUT" >/dev/null
[[ -f "$BASE/lsblk_target.txt" ]] && { echo; tail -n +1 "$BASE/lsblk_target.txt" | tee -a "$OUT" >/dev/null; }
sep

# 2) Systemd Autostarts (enabled)
hdr "Systemd: Enabled/Autostarts"
if [[ -f "$BASE/systemd/enabled_wants.txt" ]]; then
  awk '{print}' "$BASE/systemd/enabled_wants.txt" | sort -u | tee -a "$OUT" >/dev/null
else
  say "Keine Daten (enabled_wants.txt fehlt)."
fi

# Kandidaten mit ExecStart aus /tmp, /home, /var/tmp
if compgen -G "$ROOT_MP/etc/systemd/system/*.service" >/dev/null; then
  hdr "Systemd: Verdächtige ExecStart-Pfade (/tmp, /home, /var/tmp)"
  while IFS= read -r svc; do
    if grep -qiE '^\s*ExecStart=.*\s(/tmp|/var/tmp|/home)/' "$svc"; then
      rel="${svc#"$ROOT_MP"/}"
      echo "$rel: $(grep -i 'ExecStart=' "$svc" | sed 's/^[[:space:]]*//')" | tee -a "$OUT" >/dev/null
    fi
  done < <(find "$ROOT_MP/etc/systemd/system" -type f -name '*.service' 2>/dev/null)
fi
sep

# 3) Cron/Timer
hdr "Zeitgesteuert: Cron & Timer"
[[ -f "$BASE/cron/crontab" ]] && { echo "[/etc/crontab]"; sed -n '1,200p' "$BASE/cron/crontab"; } | tee -a "$OUT" >/dev/null
[[ -d "$BASE/cron/spool_cron" ]] && { echo; echo "[/var/spool/cron vorhanden]"; find "$BASE/cron/spool_cron" -type f -maxdepth 2; } | tee -a "$OUT" >/dev/null
[[ -f "$BASE/systemd/timers.txt" ]] && { echo; echo "[Systemd Timer]"; sed -n '1,200p' "$BASE/systemd/timers.txt"; } | tee -a "$OUT" >/dev/null
sep

# 4) SSH-Härten
hdr "SSH-Konfiguration (Hardening-Check)"
SSH_DIR="$BASE/ssh"
if [[ -d "$SSH_DIR" ]]; then
  CFG="$SSH_DIR/etc_ssh/sshd_config"
  if [[ -f "$CFG" ]]; then
    awk 'BEGIN{print "Datei: etc/ssh/sshd_config"} /^(#|$)/{next} {print}' "$CFG" | sed -n '1,200p' | tee -a "$OUT" >/dev/null
    echo >> "$OUT"
    say "SSH-Flags (auffällig = JA):"
    for k in PermitRootLogin PasswordAuthentication PermitEmptyPasswords PermitTunnel AllowTcpForwarding GatewayPorts X11Forwarding; do
      v="$(grep -iE "^\s*$k\s+" "$CFG" | tail -n1 | awk '{print tolower($2)}')"
      [[ -z "$v" ]] && v="(unset)"
      bad="NEIN"
      case "$k:$v" in
        PermitRootLogin:yes|PermitRootLogin:prohibit-password) bad="JA";;
        PasswordAuthentication:yes|PermitEmptyPasswords:yes|PermitTunnel:yes|AllowTcpForwarding:yes|GatewayPorts:yes|X11Forwarding:yes) bad="JA";;
      esac
      printf "  %-24s -> %-8s  [%s]\n" "$k" "$v" "$bad" | tee -a "$OUT" >/dev/null
    done
  else
    say "Keine etc/ssh/sshd_config gesichert."
  fi
else
  say "SSH-Daten nicht vorhanden."
fi
sep

# 5) Benutzer, Gruppen, sudoers
hdr "Accounts & Privilegien"
for f in passwd group sudo/sudoers; do
  [[ -f "$BASE/etc/$f" ]] && { echo "[$f]"; sed -n '1,60p' "$BASE/etc/$f"; echo; } | tee -a "$OUT" >/dev/null
done
if [[ -d "$BASE/sudo/sudoers.d" ]]; then
  echo "[sudoers.d/]" | tee -a "$OUT" >/dev/null
  find "$BASE/sudo/sudoers.d" -type f -maxdepth 1 -print | sed "s#^$BASE/##" | tee -a "$OUT" >/dev/null
fi
sep

# 6) SUID/SGID & Capabilities
hdr "Binaries: SUID/SGID & Capabilities"
[[ -f "$BASE/binaries/suid.txt" ]] && { echo "[SUID]"; sed -n '1,120p' "$BASE/binaries/suid.txt"; } | tee -a "$OUT" >/dev/null
[[ -f "$BASE/binaries/sgid.txt" ]] && { echo; echo "[SGID]"; sed -n '1,80p' "$BASE/binaries/sgid.txt"; } | tee -a "$OUT" >/dev/null
if [[ -f "$BASE/binaries/capabilities.txt" ]]; then
  echo; echo "[Capabilities (gefährlich markiert)]" | tee -a "$OUT" >/dev/null
  awk '
    /cap_(sys_admin|sys_module|sys_time|sys_ptrace|dac_read_search|dac_override|setfcap|setuid|setgid|net_admin|net_raw|mknod|audit_control)/{
      print "!! " $0
      next
    }
    {print}
  ' "$BASE/binaries/capabilities.txt" | sed -n '1,200p' | tee -a "$OUT" >/dev/null
fi
sep

# 7) Netzwerkprofile
hdr "Netzwerkprofile"
[[ -d "$BASE/network/nm-connections" ]] && { echo "[NetworkManager/system-connections]"; find "$BASE/network/nm-connections" -type f -maxdepth 2; } | tee -a "$OUT" >/dev/null
[[ -d "$BASE/network/netplan" ]] && { echo; echo "[/etc/netplan]"; find "$BASE/network/netplan" -type f -maxdepth 2; } | tee -a "$OUT" >/dev/null
sep

# 8) Paketquellen & Historie
hdr "Paketquellen / Install-Historie"
[[ -d "$BASE/packages/apt" ]] && { echo "[/etc/apt]"; find "$BASE/packages/apt" -type f | sed "s#^$BASE/##"; } | tee -a "$OUT" >/dev/null
if [[ -d "$BASE/packages/apt_logs" ]]; then
  echo; echo "[APT History (letzte 200 Zeilen)]" | tee -a "$OUT" >/dev/null
  zgrep -hE '' "$BASE"/packages/apt_logs/history.log* 2>/dev/null | tail -n 200 | tee -a "$OUT" >/dev/null
fi
[[ -f "$BASE/packages/dpkg_status" ]] && { echo; echo "[dpkg Status: Paketanzahl] $(grep -cE '^Package:' "$BASE/packages/dpkg_status") Pakete"; } | tee -a "$OUT" >/dev/null
sep

# 9) Boot/Journald & klassische Logs
hdr "Logs"
[[ -f "$BASE/var_log/boot_journal.txt" ]] && { echo "[Journald (Boot)]"; sed -n '1,160p' "$BASE/var_log/boot_journal.txt"; } | tee -a "$OUT" >/dev/null
if [[ -f "$BASE/var_log/var_log.tar" ]]; then
  echo; echo "[/var/log – Archiv vorhanden]" | tee -a "$OUT" >/dev/null
  tar -tf "$BASE/var_log/var_log.tar" 2>/dev/null | head -n 120 | tee -a "$OUT" >/dev/null
fi
sep

# 10) Potenziell jüngste Änderungen (Heuristik: mtime der letzten 15 Tage)
hdr "Jüngste Dateien (≤ 15 Tage) — Heuristik"
# Achtung: mtime kann je nach Clock-Drift ungenau sein
if [[ -d "$ROOT_MP" ]]; then
  find "$ROOT_MP" -xdev -type f -mtime -15 -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
    | sort -r | head -n 60 | sed "s#^$ROOT_MP/##" | tee -a "$OUT" >/dev/null || true
else
  say "Root-Mount unbekannt; Abschnitt übersprungen."
fi
sep

say "Fertig. Report: $OUT"
