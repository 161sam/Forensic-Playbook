#!/usr/bin/env bash
# install_forensic_codex.sh
# Idempotent installer & configurator for a forensic Codex + MCP Kali Server environment.
# Places everything on a writable USB workspace (default /mnt/usb_rw).
# - mounts removable media (best-effort) and names them /mnt/usb_rw, /mnt/usb2, /mnt/usb_ro_*
# - creates codex_home and codex_logs on writable USB
# - clones MCP-Kali-Server repo (if missing), creates venv and installs deps
# - installs nodejs/npm (if missing, via apt) and installs @openai/codex locally (optional)
# - writes Codex config pointing at local MCP server (loopback)
# - tries not to modify original suspect disks; uses read-only mounts for additional devices
# Usage: sudo /mnt/usb_rw/install_forensic_codex.sh
set -euo pipefail
IFS=$'\n\t'

USB_DEFAULT="/mnt/usb_rw"
USB="$USB_DEFAULT"
LOGDIR="$USB/codex_logs"
CODEx_HOME="$USB/codex_home"
MCP_DIR="$USB/MCP-Kali-Server"
VENV_DIR="$MCP_DIR/.venv"
MCP_REPO="https://github.com/Wh0am123/MCP-Kali-Server.git"
NODE_LOCAL_DIR="$USB/codex_npm"
MINIMAL_PIP_PACKAGES=(flask flask-cors requests)

# Helpers
log(){ printf "%s %s\n" "$(date --iso-8601=seconds)" "$*" | tee -a "$LOGDIR/install.log"; }
ensure_dir(){ mkdir -p "$1"; chmod 700 "$1" || true; }
require_root(){ if [ "$(id -u)" -ne 0 ]; then echo "ERROR: Script must be run as root (sudo)"; exit 1; fi }

require_root
ensure_dir "$USB"
ensure_dir "$LOGDIR"
ensure_dir "$CODEx_HOME"

log "Starting installer: USB workspace = $USB"

# 1) Detect removable partitions (best-effort)
log "Detecting removable partitions via lsblk"
mapfile -t REM_PARTS < <(lsblk -nr -o NAME,RM,TYPE,SIZE,MOUNTPOINT | awk '$2==1 && $3=="part" {print "/dev/"$1" "$4" "$5}') || true

# Helper to mount a device at a target mountpoint
mount_dev(){ dev="$1" mp="$2" roflag="$3"
  ensure_dir "$mp"
  if mountpoint -q "$mp"; then
    log "$mp already mounted -> skipping"
    return 0
  fi
  if [ "$roflag" = "ro" ]; then
    log "Mounting $dev -> $mp (read-only)"
    mount -o ro "$dev" "$mp"
  else
    log "Mounting $dev -> $mp (read-write)"
    mount "$dev" "$mp"
  fi
}

# If a suitable writable USB is already mounted at /mnt/usb_rw, use it
if mountpoint -q "$USB" && [ -w "$USB" ]; then
  log "$USB ist bereits vorhanden und schreibbar -> Verwende es als Workspace"
else
  # choose the largest removable partition (not mounted) as workspace; if none, skip
  chosen=""
  largest_size=0
  for line in "${REM_PARTS[@]:-}"; do
    dev=$(echo "$line" | awk '{print $1}')
    size_raw=$(echo "$line" | awk '{print $2}')
    mp=$(echo "$line" | awk '{print $3}')
    # skip if already mounted
    if [ -n "$mp" ] && [ "$mp" != "-" ]; then
      continue
    fi
    # parse size like 14G or 512M -> convert to MB approx
    size_mb=0
    if [[ "$size_raw" =~ G$ ]]; then
      size_mb=$(echo "$size_raw" | sed 's/G//' | awk '{print $1*1024}')
    elif [[ "$size_raw" =~ M$ ]]; then
      size_mb=$(echo "$size_raw" | sed 's/M//' | awk '{print $1}')
    else
      size_mb=0
    fi
    if [ "$size_mb" -gt "$largest_size" ]; then
      largest_size=$size_mb
      chosen="$dev"
    fi
  done
  if [ -n "$chosen" ]; then
    log "Wähle $chosen als Workspace -> mount to $USB"
    mount_dev "$chosen" "$USB" "rw" || log "WARN: mount of $chosen failed"
  else
    log "Keine ungemounteten entfernten Partitionen gefunden. Falls du einen USB workspace hast, mounte ihn manuell unter $USB"
  fi
fi

# 2) Find or mount a secondary storage /mnt/usb2 (optional)
USB2="$USB/../mnt_usb2"
# prefer existing mounted removable partitions besides the workspace for backup
ensure_dir "$USB2"
if [ "$(mountpoint -q "$USB2"; echo $?)" -eq 0 ]; then
  log "$USB2 bereits mountpoint"
else
  # pick another removable device (not the workspace), mount RW
  for line in "${REM_PARTS[@]:-}"; do
    dev=$(echo "$line" | awk '{print $1}')
    if findmnt -n -S "$dev" >/dev/null 2>&1; then
      continue
    fi
    # skip chosen workspace
    if [ -n "$chosen" ] && [ "$dev" = "$chosen" ]; then
      continue
    fi
    mount_dev "$dev" "$USB2" "rw" && break || continue
  done
fi

# 3) If any leftover removable devices exist, mount them read-only under /mnt/usb_ro_* (best-effort)
idx=1
for line in "${REM_PARTS[@]:-}"; do
  dev=$(echo "$line" | awk '{print $1}')
  # skip ones already mounted
  if findmnt -n -S "$dev" >/dev/null 2>&1; then
    continue
  fi
  target="$USB/usb_ro_$idx"
  mount_dev "$dev" "$target" "ro" || log "WARN: could not mount $dev as ro"
  idx=$((idx+1))
done

# 4) Clone MCP repo if missing
if [ ! -d "$MCP_DIR" ]; then
  log "Cloning MCP repo into $MCP_DIR"
  git clone "$MCP_REPO" "$MCP_DIR" 2>> "$LOGDIR/git_clone.err" || { log "ERROR: git clone failed (see git_clone.err)"; }
else
  log "MCP repo already exists at $MCP_DIR -> pulling latest"
  (cd "$MCP_DIR" && git pull --ff-only) 2>> "$LOGDIR/git_pull.err" || log "WARN: git pull failed"
fi

# 5) Create venv and install python deps (idempotent)
if [ -f "$MCP_DIR/kali_server.py" ]; then
  if [ ! -d "$VENV_DIR" ]; then
    log "Creating venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  # activate and install
  # shellcheck disable=SC1090
  source "$VENV_DIR/bin/activate"
  log "Upgrading pip/setuptools/wheel inside venv"
  python -m pip install --upgrade pip setuptools wheel 2>> "$LOGDIR/pip_install.err" || true
  if [ -f "$MCP_DIR/requirements.txt" ] && [ -s "$MCP_DIR/requirements.txt" ]; then
    log "Installing requirements.txt"
    python -m pip install -r "$MCP_DIR/requirements.txt" 2>> "$LOGDIR/pip_install.err" || log "WARN: pip install -r failed"
  else
    log "Installing minimal pip packages: ${MINIMAL_PIP_PACKAGES[*]}"
    python -m pip install "${MINIMAL_PIP_PACKAGES[@]}" 2>> "$LOGDIR/pip_install.err" || log "WARN: pip minimal install failed"
  fi
  deactivate || true
else
  log "WARN: $MCP_DIR/kali_server.py not found -> cannot setup venv / install MCP server dependencies"
fi

# 6) Node/npm and Codex CLI (install locally under $NODE_LOCAL_DIR)
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  log "node & npm detected"
else
  if command -v apt >/dev/null 2>&1; then
    log "node/npm not found -> installing via apt"
    apt update -y >/dev/null 2>> "$LOGDIR/apt.err" || true
    apt install -y nodejs npm >/dev/null 2>> "$LOGDIR/apt.err" || log "WARN: apt install nodejs/npm failed"
  else
    log "WARN: Paketmanager apt nicht gefunden; bitte node/npm manuell installieren wenn du Codex CLI nutzen willst"
  fi
fi

# Install codex CLI locally (idempotent)
ensure_dir "$NODE_LOCAL_DIR"
if [ ! -d "$NODE_LOCAL_DIR/node_modules/@openai/codex" ]; then
  log "Installing @openai/codex locally into $NODE_LOCAL_DIR"
  npm --prefix "$NODE_LOCAL_DIR" install @openai/codex --no-audit --no-fund > "$LOGDIR/npm_install.out" 2> "$LOGDIR/npm_install.err" || log "WARN: npm install produced warnings (see npm_install.err)"
else
  log "@openai/codex already installed in $NODE_LOCAL_DIR"
fi

# 7) Create Codex config (forensic HOME)
CODEx_CONF_DIR="$CODEx_HOME/.codex"
ensure_dir "$CODEx_CONF_DIR"
CFG_FILE="$CODEx_CONF_DIR/config.toml"
log "Writing Codex config to $CFG_FILE"
cat > "$CFG_FILE" <<'EOF'
[core]
# default_model = "gpt-5-codex"

[mcp_servers.kali_mcp]
command = "python3"
args = ["/mnt/usb_rw/MCP-Kali-Server/mcp_server.py", "http://127.0.0.1:5000"]
env = { MCP_ALLOW_EXEC = "true" }
EOF
sha256sum "$CFG_FILE" > "$LOGDIR/config.sha256" || true

# 8) Create convenience symlinks for local npm binary
if [ -x "$NODE_LOCAL_DIR/node_modules/.bin/codex" ]; then
  ln -sf "$NODE_LOCAL_DIR/node_modules/.bin/codex" "$USB/codex_cmd" || true
  log "Created symlink $USB/codex_cmd -> local codex binary"
else
  log "Local codex binary not found; 'npx' can still be used to run codex commands"
fi

# 9) Final report
log "Installation finished. Summary:"
log "Workspace (USB): $USB"
log "Codex home: $CODEx_HOME"
log "Logs: $LOGDIR/install.log"
if mountpoint -q "$USB"; then log "$USB mounted: $(df -h "$USB" | tail -n1)"; fi
if mountpoint -q "$USB2"; then log "$USB2 mounted: $(df -h "$USB2" | tail -n1)"; fi
ss -ltnp | rg 5000 || true | tee -a "$LOGDIR/install.log"

log "Next recommended steps:"
log " - Run /mnt/usb_rw/start_all_forensic.sh to start the MCP server and create Codex config (it will re-use what we set up)."
log " - Use HOME=$CODEx_HOME npx -y @openai/codex mcp list  to verify Codex MCP config (or $USB/codex_cmd if created)."

exit 0
