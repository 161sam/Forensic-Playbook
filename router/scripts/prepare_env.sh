#!/usr/bin/env bash
# prepare_env.sh — idempotent forensic environment preparation
# - creates router.env template (if missing)
# - creates python venv at /mnt/FORNSIC_20251006/venv
# - installs selenium + python-dotenv (base)
# - optional: installs selenium-wire + mitmproxy + blinker (heavy) if --with-wire
# - handles geckodriver (system PATH or forensic bin fallback)
# - logs actions to /mnt/FORNSIC_20251006/logs and chain-of-custody in /mnt/FORNSIC_20251006/hashes
#
# Usage:
#   /mnt/FORNSIC_20251006/conf/prepare_env.sh [--no-apt] [--with-wire] [--gecko-ver vX.Y.Z] [--gecko-dest /usr/local/bin]
#
set -euo pipefail
IFS=$'\n\t'

OUTDIR="/mnt/FORNSIC_20251006"
CONF_DIR="${OUTDIR}/conf"
VENV_DIR="${OUTDIR}/venv"
BIN_DIR="${OUTDIR}/bin"
LOG_DIR="${OUTDIR}/logs"
HASH_DIR="${OUTDIR}/hashes"
ENV_FILE="${CONF_DIR}/router.env"

GECKO_DEST="/usr/local/bin"
GECKO_VER=""
DO_APT=1
INSTALL_WIRE=0    # set to 1 with --with-wire
CURL_OPTS="-sS"

mkdir -p "$CONF_DIR" "$BIN_DIR" "$LOG_DIR" "$HASH_DIR"

log(){ printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
append_coc(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | PREPARE | user=$(id -un) | host=$(hostname -f) | $*" >> "${HASH_DIR}/chain_of_custody_prepare.txt"; }

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-apt) DO_APT=0; shift ;;
    --with-wire) INSTALL_WIRE=1; shift ;;
    --gecko-ver) GECKO_VER="$2"; shift 2 ;;
    --gecko-dest) GECKO_DEST="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [--no-apt] [--with-wire] [--gecko-ver vX.Y.Z] [--gecko-dest /path]
  --no-apt    : skip apt installs (use when offline or restricted)
  --with-wire : install selenium-wire + mitmproxy + heavy deps
  --gecko-ver : force geckodriver tag (e.g. v0.33.0)
  --gecko-dest: where to place geckodriver (default /usr/local/bin)
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log "START prepare_env.sh"
append_coc "$0 $*"

# 1) router.env template
if [[ -f "$ENV_FILE" ]]; then
  log "router.env exists -> skipping"
else
  cat > "$ENV_FILE" <<'EOF'
# router.env - fill or leave blank (script will prompt)
ROUTER_URL="https://192.168.0.1/"
ROUTER_USER="admin"
ROUTER_PASS=""
EOF
  chmod 600 "$ENV_FILE"
  log "Created $ENV_FILE (600)"
  append_coc "created router.env"
fi

# 2) optional system packages for heavy builds
need_pkgs=()
# only ask for these if --with-wire requested (heavy deps)
if [[ $INSTALL_WIRE -eq 1 ]]; then
  # packages required for building cryptography/mitmproxy on Debian/Kali
  need_pkgs+=(build-essential python3-dev libffi-dev libssl-dev cargo rustc \
              libxml2-dev libxslt1-dev zlib1g-dev)
fi

# base helpful packages (if missing)
base_pkgs=()
command -v curl >/dev/null 2>&1 || base_pkgs+=("curl")
command -v tar >/dev/null 2>&1 || base_pkgs+=("tar")
if ! command -v firefox >/dev/null 2>&1 && ! command -v firefox-esr >/dev/null 2>&1; then
  base_pkgs+=("firefox-esr")
fi

all_pkgs=("${base_pkgs[@]}" "${need_pkgs[@]}")
if [[ ${#all_pkgs[@]} -gt 0 ]]; then
  log "Detected candidate apt packages: ${all_pkgs[*]}"
  if [[ $DO_APT -eq 1 ]]; then
    read -p "Install apt packages needed (${#all_pkgs[@]})? [y/N] " yn
    if [[ "${yn,,}" =~ ^y ]]; then
      log "Installing apt packages..."
      sudo apt update
      sudo apt install -y "${all_pkgs[@]}"
      append_coc "apt install ${all_pkgs[*]}"
    else
      log "User declined apt install"
    fi
  else
    log "APT disabled by --no-apt (skipping system package install)"
  fi
else
  log "No missing system packages detected"
fi

# 3) create virtualenv idempotent
if [[ -d "$VENV_DIR" ]]; then
  log "venv exists at $VENV_DIR"
else
  log "Creating venv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
  append_coc "created venv $VENV_DIR"
fi

VENV_PIP="${VENV_DIR}/bin/pip"
VENV_PY="${VENV_DIR}/bin/python"

if [[ ! -x "$VENV_PIP" ]]; then
  log "ERROR: pip missing in venv ($VENV_PIP)"; exit 2
fi

log "Upgrading pip/setuptools/wheel in venv"
"$VENV_PIP" install --upgrade pip setuptools wheel >/dev/null

log "Install base python packages (selenium, python-dotenv)"
"$VENV_PIP" install selenium python-dotenv >/dev/null
append_coc "pip install selenium python-dotenv"

# Always ensure blinker present because mitmproxy/selenium-wire sometimes require it
log "Ensuring blinker in venv"
"$VENV_PIP" install blinker >/dev/null || log "blinker install may have failed (network?)"
append_coc "pip ensure blinker"

# optional heavy install: selenium-wire + mitmproxy
if [[ $INSTALL_WIRE -eq 1 ]]; then
  log "Installing selenium-wire and mitmproxy (heavy). This may take a while."
  # prefer prebuilt wheels when possible
  if "$VENV_PIP" install --prefer-binary selenium-wire mitmproxy >/dev/null 2>&1; then
    log "selenium-wire + mitmproxy installed in venv"
    append_coc "pip install selenium-wire mitmproxy"
  else
    log "Initial pip install failed; retrying verbose to capture errors"
    if "$VENV_PIP" install selenium-wire mitmproxy; then
      log "Installed on retry"
      append_coc "pip install selenium-wire mitmproxy (retry success)"
    else
      log "Failed to install selenium-wire/mitmproxy into venv. Check network and system build tools (rust/cargo, libssl-dev)."
      append_coc "pip install selenium-wire mitmproxy FAILED"
    fi
  fi
else
  log "selenium-wire/mitmproxy not requested (skipped)"
fi

# 4) geckodriver handling (idempotent)
if command -v geckodriver >/dev/null 2>&1; then
  GD_PATH="$(command -v geckodriver)"
  log "geckodriver found: $GD_PATH"
  echo "GECKO_PATH=${GD_PATH}" > "${CONF_DIR}/gecko_path.env"
  append_coc "geckodriver exists $GD_PATH"
else
  # attempt download if network available
  if command -v curl >/dev/null 2>&1; then
    log "Attempting geckodriver download"
    if [[ -z "$GECKO_VER" ]]; then
      GECKO_VER="$(curl $CURL_OPTS https://api.github.com/repos/mozilla/geckodriver/releases/latest 2>/dev/null | grep -m1 '\"tag_name\":' | sed -E 's/.*\"([^"]+)\".*/\1/' || true)"
      log "Resolved GECKO_VER=${GECKO_VER}"
    fi
    if [[ -n "$GECKO_VER" ]]; then
      ARCH="linux64"
      TAR="geckodriver-${GECKO_VER}-${ARCH}.tar.gz"
      URL="https://github.com/mozilla/geckodriver/releases/download/${GECKO_VER}/${TAR}"
      tmpd="$(mktemp -d)"
      pushd "$tmpd" >/dev/null
      if curl -fL $CURL_OPTS -O "$URL"; then
        tar xzf "$TAR"
        if [[ -f geckodriver ]]; then
          if [[ -w "$GECKO_DEST" || $(id -u) -eq 0 ]]; then
            if [[ $(id -u) -ne 0 ]]; then sudo mv geckodriver "$GECKO_DEST/"; sudo chmod 755 "$GECKO_DEST/geckodriver"; else mv geckodriver "$GECKO_DEST/"; chmod 755 "$GECKO_DEST/geckodriver"; fi
            echo "GECKO_PATH=${GECKO_DEST}/geckodriver" > "${CONF_DIR}/gecko_path.env"
            append_coc "installed geckodriver to $GECKO_DEST"
            log "Installed geckodriver to $GECKO_DEST"
          else
            mv geckodriver "$BIN_DIR/"
            chmod 755 "$BIN_DIR/geckodriver"
            echo "GECKO_PATH=${BIN_DIR}/geckodriver" > "${CONF_DIR}/gecko_path.env"
            append_coc "installed geckodriver to $BIN_DIR"
            log "Installed geckodriver to $BIN_DIR (forensic bin)"
          fi
        fi
      else
        log "geckodriver download failed or network not available"
      fi
      popd >/dev/null
      rm -rf "$tmpd"
    else
      log "Could not determine geckodriver tag; skipping download"
    fi
  else
    log "curl missing — cannot download geckodriver"
  fi
fi

# 5) manifest and final log
MANIFEST="${LOG_DIR}/prepare_manifest_$(date -u +%Y%m%dT%H%M%SZ).txt"
cat > "$MANIFEST" <<EOF
prepare_env manifest
timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
user: $(id -un)
host: $(hostname -f)
outdir: $OUTDIR
venv: $VENV_DIR
gecko_path_file: ${CONF_DIR}/gecko_path.env
env_template: $ENV_FILE
install_wire: $INSTALL_WIRE
EOF
chmod 600 "$MANIFEST"
append_coc "wrote manifest $MANIFEST"

log "PREPARATION COMPLETE"
log "To use venv: source ${VENV_DIR}/bin/activate"
log "To run collector: python ${CONF_DIR}/collect_router_ui.py"
exit 0
