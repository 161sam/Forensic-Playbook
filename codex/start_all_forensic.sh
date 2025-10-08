#!/usr/bin/env bash
# start_all_forensic.sh
# Idempotent starter and verifier for the forensic MCP + Codex environment.
# - Starts MCP Kali Server (kali_server.py) in a venv with nohup
# - Ensures basic "bind" / local resolution safety (/etc/hosts check and backup)
# - Writes/updates Codex config under the forensic CODEx_HOME
# - Performs health checks and prints a short report
# - Designed to be safe for live forensic work (minimal, reversible changes)

set -euo pipefail
IFS=$'\n\t'

USB_DEFAULT="/mnt/usb_rw"
USB="${USB:-$USB_DEFAULT}"
MCP_DIR="$USB/MCP-Kali-Server"
VENV_DIR="$MCP_DIR/.venv"
CODEx_HOME="${CODEx_HOME:-$USB/codex_home}"
LOGDIR="${LOGDIR:-$USB/codex_logs}"
PIDFILE="$LOGDIR/mcp.pid"
STDOUT="$LOGDIR/mcp_stdout.log"
STDERR="$LOGDIR/mcp_stderr.log"
CONTROL_LOG="$LOGDIR/kali_server_control.log"
PORT="5000"
HOST_ADDR="127.0.0.1"
MCP_SCRIPT="kali_server.py"

mkdir -p "$LOGDIR" "$CODEx_HOME"
chmod 700 "$CODEx_HOME"

log(){ echo "$(date --iso-8601=seconds) $*" | tee -a "$CONTROL_LOG"; }
require_root(){ if [ "$(id -u)" -ne 0 ]; then echo "ERROR: please run as root"; exit 1; fi }

require_root
log "=== start_all_forensic.sh starting ==="
log "Workspace: $USB"

# 1) Basic sanity checks
if [ ! -d "$MCP_DIR" ]; then
  log "ERROR: MCP directory $MCP_DIR not found. Run install script first or clone repo."
  exit 2
fi
if [ ! -f "$MCP_DIR/$MCP_SCRIPT" ]; then
  log "ERROR: MCP server script $MCP_DIR/$MCP_SCRIPT missing"
  exit 3
fi

# 2) Patch Bind (non-destructive minimal step): ensure /etc/hosts has loopback entries
patch_bind(){
  local hostsfile="/etc/hosts"
  local bak="$LOGDIR/hosts.orig.$(date +%Y%m%dT%H%M%S)"
  if grep -E "^127\.(0\.0\.1|0)\s+localhost" "$hostsfile" >/dev/null 2>&1; then
    log "/etc/hosts contains localhost mapping -> OK"
    return 0
  fi
  log "Backing up /etc/hosts -> $bak and adding loopback localhost entry (best-effort)"
  cp "$hostsfile" "$bak"
  echo "127.0.0.1 localhost" >> "$hostsfile"
  log "WROTE: 127.0.0.1 localhost to /etc/hosts"
}

patch_bind

# 3) Ensure venv exists and dependencies installed (idempotent)
if [ -d "$VENV_DIR" ]; then
  log "Activating existing venv: $VENV_DIR"
else
  log "Creating venv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel >/dev/null 2>>"$LOGDIR/pip.err" || true
if python -c "import importlib,sys
try:
 importlib.import_module('flask')
except Exception:
 sys.exit(2)
" >/dev/null 2>&1; then
  log "flask available in venv -> OK"
else
  log "Installing minimal MCP deps (flask, flask-cors, requests)"
  python -m pip install flask flask-cors requests >/dev/null 2>>"$LOGDIR/pip.err" || log "WARN: pip install issues (see $LOGDIR/pip.err)"
fi

# 4) Start MCP server (kali_server.py) idempotent
start_mcp(){
  # if pid exists and process alive -> keep
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      log "MCP server already running with PID $pid (leaving as-is)"
      return 0
    else
      log "Found stale PID file -> removing"
      rm -f "$PIDFILE"
    fi
  fi

  log "Starting MCP server: $MCP_DIR/$MCP_SCRIPT"
  cd "$MCP_DIR"
  nohup python3 "$MCP_SCRIPT" --host "$HOST_ADDR" --port "$PORT" >"$STDOUT" 2>"$STDERR" &
  newpid=$!
  sleep 0.8
  # if it died quickly, retry without args
  if ! kill -0 "$newpid" 2>/dev/null; then
    log "First start attempt failed, retrying without flags"
    nohup python3 "$MCP_SCRIPT" >"$STDOUT" 2>"$STDERR" &
    newpid=$!
    sleep 0.8
  fi
  echo "$newpid" > "$PIDFILE"
  log "Started $MCP_SCRIPT with PID $newpid"
}

start_mcp

# 5) Wait and check listening socket
sleep 0.8
LISTENING=$(ss -ltnp 2>/dev/null | rg "${PORT}" || true)
if [ -n "$LISTENING" ]; then
  log "MCP appears to be listening on port $PORT"
else
  log "WARN: MCP not listening on port $PORT (see logs $STDERR / $STDOUT)"
fi

# 6) Write Codex config into CODEx_HOME (idempotent)
CODEx_CONF_DIR="$CODEx_HOME/.codex"
CFG_FILE="$CODEx_CONF_DIR/config.toml"
mkdir -p "$CODEx_CONF_DIR"
if [ -f "$CFG_FILE" ]; then
  log "Codex config already exists at $CFG_FILE -> backing up"
  cp -a "$CFG_FILE" "$CFG_FILE.bak.$(date +%Y%m%dT%H%M%S)"
fi
cat > "$CFG_FILE" <<EOF
[core]
# default_model = "gpt-5-codex"

[mcp_servers.kali_mcp]
command = "python3"
args = ["$MCP_DIR/mcp_server.py", "http://$HOST_ADDR:$PORT"]
env = { MCP_ALLOW_EXEC = "true" }
EOF
log "Wrote Codex config -> $CFG_FILE"
sha256sum "$CFG_FILE" > "$LOGDIR/codex_config.sha256"

# 7) Health check against http endpoint
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$HOST_ADDR:$PORT/" || true)
if [ -n "$HTTP_STATUS" ]; then
  log "HTTP probe returned status: $HTTP_STATUS"
else
  log "HTTP probe failed (no response)"
fi

# 8) Small report
log "=== REPORT ==="
if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" || true)
  log "MCP PID: $pid"
fi
log "PORT check:"
ss -ltnp | rg ":$PORT" || true
log "HTTP status: $HTTP_STATUS"
log "Codex config: $CFG_FILE"
log "Codex home: $CODEx_HOME"
log "MCP dir: $MCP_DIR"
log "Logs: $LOGDIR"
log "Disk usage for workspace: $(df -h "$USB" | tail -n1)"

# show last 20 lines of stdout/stderr
log "--- tailing MCP stdout ---"
tail -n 20 "$STDOUT" 2>/dev/null || true
log "--- tailing MCP stderr ---"
tail -n 20 "$STDERR" 2>/dev/null || true

log "=== start_all_forensic.sh finished ==="

deactivate 2>/dev/null || true
exit 0
