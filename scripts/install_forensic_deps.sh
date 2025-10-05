#!/usr/bin/env bash
# install_forensic_deps.sh
# Prüft & installiert forensische Tools/Abhängigkeiten (multi-distro),
# inkl. Freiplatz-Check, SMART-/NVMe-Kurzcheck, ddrescue-Version.
# Idempotent; interaktiv, oder mit --yes non-interaktiv.
set -Eeuo pipefail

PROGNAME="$(basename "$0")"
YES="false"
LOGDIR_DEFAULT="/mnt/forensic_workdir"
NEEDED_CMDS=(
  ddrescue
  lsblk blkid wipefs
  partprobe
  smartctl
  nvme
  sha256sum b2sum
  tar
  git
)

usage() {
  cat <<EOF
$PROGNAME — Prüft & installiert benötigte Tools für forensisches Cloning/Analyse.

Usage:
  sudo $PROGNAME [--yes] [--logdir PATH] [--min-free-mb N] [--no-smart]

Options:
  --yes           non-interaktiv installieren (keine Rückfragen)
  --logdir PATH   Verzeichnis für Logs/Artefakte (Default: $LOGDIR_DEFAULT)
  --min-free-mb N Mindestfreier Speicher auf dem Root-Dateisystem (Default: 512)
  --no-smart      SMART-/NVMe-Checks überspringen
  --help          diese Hilfe

Unterstützte Paketmanager: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL),
                           pacman (Arch), zypper (openSUSE).
EOF
}

# -------- Argumente --------
LOGDIR="$LOGDIR_DEFAULT"
MIN_FREE_MB=512
DO_SMART="true"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES="true"; shift ;;
    --logdir) LOGDIR="${2:-}"; shift 2 ;;
    --min-free-mb) MIN_FREE_MB="${2:-}"; shift 2 ;;
    --no-smart) DO_SMART="false"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unbekannte Option: $1"; usage; exit 1 ;;
  esac
done

# -------- Helpers --------
note() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }
err()  { echo "ERROR: $*" >&2; exit 1; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Bitte als root / mit sudo ausführen."
  fi
}

# -------- Distro / Package Manager erkennen --------
PKG_MGR=""
detect_pkgmgr() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
  else
    PKG_MGR=""
  fi
}

detect_distro() {
  local id="unknown" like=""
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    id="${ID:-unknown}"
    like="${ID_LIKE:-}"
  fi
  note "Detected distro: $id (ID_LIKE=${like:-n/a})"
}

# -------- Mapping: Binaries -> Pakete je Paketmanager --------
# Für jeden Paketmanager eine Liste (unique) aufbauen
declare -A MAP_APT=(
  [ddrescue]="gddrescue"
  [lsblk]="util-linux"   [blkid]="util-linux"  [wipefs]="util-linux"
  [partprobe]="parted"
  [smartctl]="smartmontools"
  [nvme]="nvme-cli"
  [sha256sum]="coreutils" [b2sum]="coreutils"
  [tar]="tar"
  [git]="git"
)
declare -A MAP_DNF=(
  [ddrescue]="ddrescue"
  [lsblk]="util-linux"   [blkid]="util-linux"  [wipefs]="util-linux"
  [partprobe]="parted"
  [smartctl]="smartmontools"
  [nvme]="nvme-cli"
  [sha256sum]="coreutils" [b2sum]="coreutils"
  [tar]="tar"
  [git]="git"
)
declare -A MAP_PACMAN=(
  [ddrescue]="gnu-ddrescue"
  [lsblk]="util-linux"   [blkid]="util-linux"  [wipefs]="util-linux"
  [partprobe]="parted"
  [smartctl]="smartmontools"
  [nvme]="nvme-cli"
  [sha256sum]="coreutils" [b2sum]="coreutils"
  [tar]="tar"
  [git]="git"
)
declare -A MAP_ZYPPER=(
  [ddrescue]="gnu_ddrescue"
  [lsblk]="util-linux"   [blkid]="util-linux"  [wipefs]="util-linux"
  [partprobe]="parted"
  [smartctl]="smartmontools"
  [nvme]="nvme-cli"
  [sha256sum]="coreutils" [b2sum]="coreutils"
  [tar]="tar"
  [git]="git"
)

# -------- Check fehlende Kommandos (ohne ungewollte Prints) --------
missing_cmds=()
present_cmds=()
check_cmds() {
  missing_cmds=()
  present_cmds=()
  for item in "${NEEDED_CMDS[@]}"; do
    # Gruppe zulassen (z. B. "lsblk blkid wipefs")
    for cmd in $item; do
      if command -v "$cmd" >/dev/null 2>&1; then
        present_cmds+=("$cmd")
        ok "Gefunden: $cmd -> $(command -v "$cmd")"
      else
        missing_cmds+=("$cmd")
      fi
    done
  done
  if [[ ${#missing_cmds[@]} -eq 0 ]]; then
    ok "Alle benötigten Befehle sind vorhanden."
  else
    warn "Fehlende Befehle: ${missing_cmds[*]}"
  fi
}

# -------- Aus fehlenden Kommandos Paketliste bauen --------
pkgs_to_install=()
build_pkg_list() {
  pkgs_to_install=()
  local -A seen=()
  local pkg=""
  for cmd in "${missing_cmds[@]}"; do
    case "$PKG_MGR" in
      apt)    pkg="${MAP_APT[$cmd]:-}";;
      dnf)    pkg="${MAP_DNF[$cmd]:-}";;
      pacman) pkg="${MAP_PACMAN[$cmd]:-}";;
      zypper) pkg="${MAP_ZYPPER[$cmd]:-}";;
      *) pkg="";;
    esac
    if [[ -n "$pkg" && -z "${seen[$pkg]:-}" ]]; then
      seen[$pkg]=1
      pkgs_to_install+=("$pkg")
    elif [[ -z "$pkg" ]]; then
      warn "Kein Paket-Mapping für Befehl: $cmd — bitte manuell installieren."
    fi
  done
}

# -------- Installation für verschiedene Paketmanager --------
install_pkgs() {
  [[ ${#pkgs_to_install[@]} -gt 0 ]] || { ok "Keine Pakete zu installieren."; return; }

  note "Zu installierende Pakete: ${pkgs_to_install[*]}"
  if [[ "$YES" != "true" ]]; then
    read -r -p "Fortfahren und diese Pakete installieren? (YES/NO): " ANS
    [[ "$ANS" == "YES" ]] || err "Abgebrochen."
  fi

  case "$PKG_MGR" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs_to_install[@]}"
      ;;
    dnf)
      dnf -y install "${pkgs_to_install[@]}"
      ;;
    pacman)
      pacman -Sy --noconfirm "${pkgs_to_install[@]}"
      ;;
    zypper)
      zypper --non-interactive refresh
      zypper --non-interactive install "${pkgs_to_install[@]}"
      ;;
    *)
      err "Kein unterstützter Paketmanager gefunden. Bitte manuell installieren: ${pkgs_to_install[*]}"
      ;;
  esac
}

# -------- Freier Speicher prüfen --------
check_free_space() {
  local mountpoint="/"
  local free_kb
  free_kb="$(df -Pk "$mountpoint" | awk 'NR==2 {print $4}')"
  local free_mb=$(( free_kb / 1024 ))
  if (( free_mb < MIN_FREE_MB )); then
    warn "Wenig freier Speicher auf $mountpoint: ${free_mb}MB (benötigt: >= ${MIN_FREE_MB}MB)."
    warn "Weiter ist möglich, aber Logs/Hashes könnten fehlschlagen. Setze --min-free-mb zum Anpassen."
    if [[ "$YES" != "true" ]]; then
      read -r -p "Trotzdem fortfahren? (YES/NO): " ANS
      [[ "$ANS" == "YES" ]] || err "Abgebrochen."
    fi
  else
    ok "Freier Speicher OK auf $mountpoint: ${free_mb}MB (>= ${MIN_FREE_MB}MB)."
  fi
}

# -------- Logdir vorbereiten --------
prepare_logdir() {
  mkdir -p "$LOGDIR"
  if [[ ! -w "$LOGDIR" ]]; then
    err "Kann nicht in LOGDIR schreiben: $LOGDIR"
  fi
  ok "Logverzeichnis bereit: $LOGDIR"
}

# -------- SMART-/NVMe-Kurzcheck --------
smart_summary() {
  [[ "$DO_SMART" == "true" ]] || { note "SMART-/NVMe-Checks übersprungen (--no-smart)."; return; }

  if command -v smartctl >/dev/null 2>&1; then
    note "SMART: kurze Zusammenfassung (falls verfügbar)…"
    for dev in /dev/nvme[0-9]n[0-9] /dev/sd[a-z]; do
      [[ -b "$dev" ]] || continue
      echo "---- smartctl -H $dev ----"
      smartctl -H "$dev" 2>/dev/null | sed 's/^/  /'
    done
  else
    warn "smartctl nicht gefunden — SMART-Check übersprungen."
  fi

  if command -v nvme >/dev/null 2>&1; then
    note "NVMe: Liste / Gesundheitsinfo (falls verfügbar)…"
    nvme list 2>/dev/null | sed 's/^/  /' || true
    # Für jedes NVMe-Device ein kurzer health check
    for ctrl in /dev/nvme[0-9]; do
      [[ -e "$ctrl" ]] || continue
      echo "---- nvme smart-log $ctrl ----"
      nvme smart-log "$ctrl" 2>/dev/null | head -n 12 | sed 's/^/  /' || true
    done
  else
    warn "nvme-cli nicht gefunden — NVMe-Check übersprungen."
  fi
}

# -------- ddrescue-Version --------
check_ddrescue_version() {
  if command -v ddrescue >/dev/null 2>&1; then
    local ver
    ver="$(ddrescue --version 2>/dev/null | head -n1)"
    ok "ddrescue Version: $ver"
  else
    warn "ddrescue noch nicht installiert."
  fi
}

# -------- MAIN --------
main() {
  require_root
  detect_distro
  detect_pkgmgr
  [[ -n "$PKG_MGR" ]] || warn "Kein bekannter Paketmanager entdeckt — Installation wird ggf. manuell nötig."

  check_free_space
  prepare_logdir

  note "Prüfe erforderliche Befehle…"
  check_cmds

  if [[ ${#missing_cmds[@]} -gt 0 ]]; then
    build_pkg_list
    install_pkgs
    note "Re-Check nach Installation…"
    check_cmds
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
      err "Folgende Befehle fehlen weiterhin: ${missing_cmds[*]} — bitte manuell installieren."
    fi
  fi

  check_ddrescue_version
  smart_summary

  ok "System ist bereit. Du kannst jetzt dein forensisches Clone-/Analyse-Skript nutzen."
  echo
  echo "Nützliche nächste Schritte:"
  echo "  mkdir -p $LOGDIR && ls -al $LOGDIR"
  echo "  ddrescue --help | head -n 5"
}

main "$@"
