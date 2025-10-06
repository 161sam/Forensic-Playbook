#!/usr/bin/env bash
# prepare_env.sh — idempotent preparation for router UI forensic collection
# - creates /mnt/FORNSIC_20251006/conf/router.env template (if missing)
# - creates python venv at /mnt/FORNSIC_20251006/venv and installs deps there
# - ensures geckodriver available (system PATH or forensic bin fallback)
# - creates logs and chain-of-custody entries
#
# Usage:
#   /mnt/FORNSIC_20251006/conf/prepare_env.sh [--no-apt] [--gecko-ver v0.33.0] [--gecko-dest /usr/local/bin]
# Notes:
#   - Idempotent: mehrfach ausführbar, ändert nur was fehlt.
#   - By default will prompt before apt installs.
set -euo pipefail
IFS=$'\n\t'

OUTDIR="/mnt/FORNSIC_20251006"
CONF="${OUTDIR}/conf"
VENV="${OUTDIR}/venv"
BIN_DIR="${OUTDIR}/bin"
LOGDIR="${OUTDIR}/logs"
ENVFILE="${CONF}/router.env"
GECKO_DEST="/usr/local/bin"
GECKO_VER=""
DO_APT=1
CURL_OPTS="-sS"

# simple logger
log(){ printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-apt) DO_APT=0; shift ;;
    --gecko-ver) GECKO_VER="$2"; shift 2 ;;
    --gecko-dest) GECKO_DEST="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [--no-apt] [--gecko-ver v0.33.0] [--gecko-dest /path]
  --no-apt       : skip apt installs
  --gecko-ver    : force geckodriver tag (e.g. v0.33.0)
  --gecko-dest   : install geckodriver here (default /usr/local/bin)
EOF
      exit 0
      ;;
    *) log "Unknown option: $1"; exit 1 ;;
  esac
done

mkdir -p "$CONF" "$BIN_DIR" "$LOGDIR"

# chain-of-custody record helper
coc_file="${OUTDIR}/hashes/chain_of_custody_preparation.txt"
mkdir -p "$(dirname "$coc_file")"
append_coc(){
  cat >> "$coc_file" <<EOF
$(date -u +%Y-%m-%dT%H:%M:%SZ) | PREPARE_ENV | user=$(id -un) | host=$(hostname -f) | cmd="$*"
EOF
}

log "START prepare_env.sh"
append_coc "$0 $*"

### 1) create router.env template if missing
if [[ -f "$ENVFILE" ]]; then
  log "router.env exists -> skipping creation: $ENVFILE"
else
  cat > "$ENVFILE" <<'EOF'
# router.env - fill or leave empty to be prompted at runtime
# ROUTER_URL should include scheme and trailing slash, e.g. https://192.168.0.1/
ROUTER_URL="https://192.168.0.1/"
ROUTER_USER="admin"
ROUTER_PASS=""
EOF
  chmod 600 "$ENVFILE"
  log "Created template $ENVFILE (chmod 600). Edit to add credentials or leave empty."
  append_coc "created $ENVFILE"
fi

### 2) optional apt installs (idempotent)
need=()
# minimal checks
command -v python3 >/dev/null 2>&1 || need+=("python3")
python3 -c 'import venv' >/dev/null 2>&1 || need+=("python3-venv")
command -v curl >/dev/null 2>&1 || need+=("curl")
command -v tar >/dev/null 2>&1 || need+=("tar")
# prefer firefox-esr if firefox missing
if ! command -v firefox >/dev/null 2>&1 && ! command -v firefox-esr >/dev/null 2>&1; then
  need+=("firefox-esr")
fi

if [[ ${#need[@]} -gt 0 ]]; then
  log "Missing system packages: ${need[*]}"
  if [[ $DO_APT -eq 1 ]]; then
    read -p "Install missing packages with sudo apt? [y/N] " yn
    if [[ "${yn,,}" =~ ^y ]]; then
      log "Running apt update/install"
      sudo apt update
      sudo apt install -y "${need[@]}"
      append_coc "apt install ${need[*]}"
    else
      log "Skipping apt install per user choice"
    fi
  else
    log "APT disabled (--no-apt); ensure packages are present manually"
  fi
else
  log "Required system packages present"
fi

### 3) create python venv and install python packages (idempotent)
if [[ -d "$VENV" ]]; then
  log "venv exists at $VENV -> skipping creation"
else
  log "Creating python venv at $VENV"
  python3 -m venv "$VENV"
  append_coc "created venv $VENV"
fi

# ensure pip inside venv and install pkgs
V_PIP="${VENV}/bin/pip"
if [[ ! -x "$V_PIP" ]]; then
  log "ERROR: pip not found in venv ($V_PIP)"
  exit 2
fi
log "Upgrading pip inside venv"
"$V_PIP" install --upgrade pip setuptools >/dev/null
log "Installing python packages into venv: selenium selenium-wire python-dotenv"
"$V_PIP" install selenium selenium-wire python-dotenv >/dev/null
append_coc "pip install selenium selenium-wire python-dotenv"

### 4) geckodriver handling (idempotent)
if command -v geckodriver >/dev/null 2>&1; then
  GD_PATH="$(command -v geckodriver)"
  log "geckodriver found in PATH: $GD_PATH"
  echo "GECKO_PATH=${GD_PATH}" > "${CONF}/gecko_path.env"
  append_coc "geckodriver found $GD_PATH"
else
  # attempt download
  log "geckodriver not found in PATH -> will download"
  # fetch tag if not provided
  if [[ -z "$GECKO_VER" ]]; then
    log "Querying GitHub for latest geckodriver release tag"
    GECKO_VER="$(curl $CURL_OPTS https://api.github.com/repos/mozilla/geckodriver/releases/latest \
      | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"
    log "Resolved GECKO_VER=${GECKO_VER}"
  fi
  ARCH="linux64"
  TB="geckodriver-${GECKO_VER}-${ARCH}.tar.gz"
  URL="https://github.com/mozilla/geckodriver/releases/download/${GECKO_VER}/${TB}"
  tmpd="$(mktemp -d)"
  pushd "$tmpd" >/dev/null
  log "Downloading $URL"
  if ! curl -fL $CURL_OPTS -O "$URL"; then
    log "ERROR: geckodriver download failed"
    popd >/dev/null
    rm -rf "$tmpd"
  else
    tar xzf "$TB"
    # try to move to GECKO_DEST if writable, else to forensic bin
    if [[ -w "$GECKO_DEST" || $(id -u) -eq 0 ]]; then
      log "Installing geckodriver to $GECKO_DEST"
      if [[ $(id -u) -ne 0 ]]; then
        sudo mv geckodriver "$GECKO_DEST/"
        sudo chmod 755 "$GECKO_DEST/geckodriver"
      else
        mv geckodriver "$GECKO_DEST/"
        chmod 755 "$GECKO_DEST/geckodriver"
      fi
      echo "GECKO_PATH=${GECKO_DEST}/geckodriver" > "${CONF}/gecko_path.env"
      append_coc "installed geckodriver to $GECKO_DEST"
    else
      mv geckodriver "$BIN_DIR/"
      chmod 755 "$BIN_DIR/geckodriver"
      echo "GECKO_PATH=${BIN_DIR}/geckodriver" > "${CONF}/gecko_path.env"
      append_coc "installed geckodriver to $BIN_DIR"
      log "Note: add $BIN_DIR to PATH for convenience or set GECKO_PATH"
    fi
    popd >/dev/null
    rm -rf "$tmpd"
  fi
fi

### 5) finalization — manifest + permissions
manifest="${OUTDIR}/logs/prepare_manifest_$(date -u +%Y%m%dT%H%M%SZ).txt"
cat > "$manifest" <<EOF
prepare_env manifest
timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
user: $(id -un)
host: $(hostname -f)
outdir: $OUTDIR
venv: $VENV
gecko_path_file: ${CONF}/gecko_path.env
env_template: $ENVFILE
EOF
chmod 600 "$manifest"
append_coc "wrote manifest $manifest"

log "PREPARATION COMPLETE. See $manifest"
log "To use venv: source \"$VENV/bin/activate\""
log "To run collector: python ${CONF}/collect_router_ui.py"
exit 0
