#!/usr/bin/env bash
# install_forensic_deps.sh
# Prüft & installiert forensische Tools/Abhängigkeiten (Debian/Ubuntu/Kali)
# Idempotent, fragt nach Bestätigung, unterstützt --yes
#
# Benötigt (mind.): sudo-Rechte
# Empfohlen für: Kali / Debian / Ubuntu (andere Distros: manuelle Installation nötig)
set -Eeuo pipefail

PROGNAME="$(basename "$0")"
YES="false"

usage() {
  cat <<EOF
$PROGNAME — Prüft und installiert benötigte Tools für das Forensic-Workflow-Setup.

Usage:
  sudo $PROGNAME [--yes] [--help]

Options:
  --yes    nicht interaktiv installieren (keine Bestätigungsfragen)
  --help   diese Hilfe

Getestete Distributionen: Debian/Ubuntu/Kali.
EOF
}

# ---------- Argumente ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unbekannte Option: $1"; usage; exit 1 ;;
  esac
done

# ---------- Helpers ----------
note()  { echo "[*] $*"; }
ok()    { echo "[✓] $*"; }
warn()  { echo "[!] $*"; }
err()   { echo "ERROR: $*" >&2; exit 1; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Bitte als root / mit sudo ausführen."
  fi
}

# ---------- Detect distro (debian-family) ----------
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    DISTRO_ID="unknown"
    DISTRO_LIKE=""
  fi
  note "Detected distro: $DISTRO_ID (ID_LIKE=$DISTRO_LIKE)"
}

# ---------- Required commands & package mapping ----------
# Commands we check for
declare -a CMD_CHECKS=(
  ddrescue
  lsblk
  blkid
  wipefs
  partprobe
  smartctl
  nvme
  sha256sum
  b2sum
  tar
  git
)

# Debian/Ubuntu package mapping (package -> provides commands)
# (We keep names conservative for Debian family)
declare -A PKG_MAP=(
  [gddrescue]="gddrescue"            # provides ddrescue
  [util-linux]="util-linux"          # provides lsblk, blkid, wipefs
  [parted]="parted"                  # provides partprobe (some systems have partprobe in parted)
  [smartmontools]="smartmontools"    # provides smartctl
  [nvme-cli]="nvme-cli"              # provides nvme
  [coreutils]="coreutils"            # provides sha256sum, b2sum, etc.
  [tar]="tar"                        # tar
  [git]="git"                        # git
)

# Some systems may already have partprobe via parted or parted-bin; keep parted entry.
# On Kali/Ubuntu apt package names are as above.

# ---------- Check commands ----------
check_commands() {
  local missing=()
  for cmd in "${CMD_CHECKS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    else
      ok "Found: $cmd -> $(command -v "$cmd")"
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "Alle benötigten Befehle sind vorhanden."
  else
    warn "Fehlende Befehle: ${missing[*]}"
  fi
  echo "${missing[@]:-}"
}

# ---------- Build package install list from missing commands ----------
build_pkg_list() {
  local missing_cmds=("$@")
  local pkgs_needed=()
  # For each missing command, map to package(s)
  for cmd in "${missing_cmds[@]}"; do
    case "$cmd" in
      ddrescue) pkgs_needed+=("gddrescue");;
      lsblk|blkid|wipefs) pkgs_needed+=("util-linux");;
      partprobe) pkgs_needed+=("parted");;
      smartctl) pkgs_needed+=("smartmontools");;
      nvme) pkgs_needed+=("nvme-cli");;
      sha256sum|b2sum) pkgs_needed+=("coreutils");;
      tar) pkgs_needed+=("tar");;
      git) pkgs_needed+=("git");;
      *) warn "Kein Paket-Mapping für $cmd vorhanden — bitte manuell installieren";;
    esac
  done
  # deduplicate
  local uniq=()
  for p in "${pkgs_needed[@]}"; do
    [[ " ${uniq[*]} " == *" $p "* ]] || uniq+=("$p")
  done
  echo "${uniq[@]:-}"
}

# ---------- Install via apt (Debian family) ----------
apt_install() {
  local pkgs=("$@")
  if [[ ${#pkgs[@]} -eq 0 ]]; then
    ok "Keine Pakete zu installieren."
    return 0
  fi

  note "Installiere Pakete: ${pkgs[*]}"
  if [[ "$YES" != "true" ]]; then
    read -r -p "Fortfahren und diese Pakete mit apt installieren? (YES/NO): " ANS
    [[ "$ANS" == "YES" ]] || err "Abgebrochen."
  fi

  # Update once
  apt-get update -y

  # Install packages in one go
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

# ---------- Main ----------
main() {
  require_root
  detect_distro

  # If not Debian-family, warn and exit (we can still try, but user must handle)
  if [[ "$DISTRO_ID" != "debian" && "$DISTRO_ID" != "ubuntu" && "$DISTRO_ID" != "kali" && "$DISTRO_LIKE" != *"debian"* ]]; then
    warn "Diese automatische Installation ist primär für Debian/Ubuntu/Kali-Systeme vorgesehen."
    warn "Auf Nicht-Debian-Systemen bitte die Pakete manuell installieren."
    if [[ "$YES" != "true" ]]; then
      read -r -p "Trotzdem weitermachen? (YES/NO): " ANS
      [[ "$ANS" == "YES" ]] || err "Abgebrochen."
    fi
  fi

  local -a missing_cmds
  IFS=$'\n' read -r -d '' -a missing_cmds < <(printf '%s\n' $(check_commands) && printf '\0')

  # If nothing missing, exit
  if [[ ${#missing_cmds[@]} -eq 0 ]]; then
    ok "System ist bereit."
    exit 0
  fi

  local -a pkgs_to_install
  IFS=' ' read -r -a pkgs_to_install <<< "$(build_pkg_list "${missing_cmds[@]}")"

  if [[ ${#pkgs_to_install[@]} -eq 0 ]]; then
    warn "Keine passenden Pakete aus den fehlenden Kommandos abgeleitet. Bitte manuell prüfen."
    exit 1
  fi

  apt_install "${pkgs_to_install[@]}"

  note "Prüfe nach Installation erneut..."
  IFS=$'\n' read -r -d '' -a missing_cmds < <(printf '%s\n' $(check_commands) && printf '\0')
  if [[ ${#missing_cmds[@]} -eq 0 ]]; then
    ok "Alle Tools installiert und verfügbar."
  else
    warn "Folgende Befehle fehlen weiterhin: ${missing_cmds[*]}"
    warn "Bitte prüfe manuell oder installiere zusätzliche Pakete."
    exit 2
  fi

  ok "Fertig. Du kannst jetzt das forensische Skript ausführen."
}

main "$@"
