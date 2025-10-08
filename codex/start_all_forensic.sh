#!/usr/bin/env bash
# start_all_forensic.sh
# Idempotenter Forensic Starter: MCP-Server (kali_server.py) + Codex (MCP-Config)
# Ziel: /mnt/usb_rw als forensischer Workspace (alle writes bleiben dort)
#
# Usage:
#   sudo /mnt/usb_rw/start_all_forensic.sh
#
set -euo pipefail
IFS=$'\n\t'

# -----------------------
# Konfiguration (ein Ort ändern genügt)
# -----------------------
USB="/mnt/usb_rw"
MCP_DIR="$USB/MCP-Kali-Server"
CODEx_HOME="$USB/codex_home"
LOGDIR="$USB/codex_logs"
VENV_DIR="$MCP_DIR/.venv"

KALI_PY="$MCP_DIR/kali_server.py"
MCP_CLIENT_PY="$MCP_DIR/mcp_server.py"

PIDFILE="$LOGDIR/kali_server.pid"
STDOUT="$LOGDIR/kali_stdout.log"
STDERR="$LOGDIR/kali_stderr.log"

REPORT="$LOGDIR/start_report.txt"

# Minimale Paketliste (wird in venv installiert nur falls requirements.txt fehlt)
MINIMAL_PIP_PACKAGES=(flask flask-cors requests)

# -----------------------
# Hilfsfunktionen
# -----------------------
log() { printf "%s %s\n" "$(date --iso-8601=seconds)" "$*" | tee -a "$REPORT"; }
ensure_dir() { mkdir -p "$1"; chmod 700 "$1" || true; }

# -----------------------
# Vorbereitungen
# -----------------------
ensure_dir "$USB"
ensure_dir "$CODEx_HOME"
ensure_dir "$LOGDIR"
ensure_dir "$MCP_DIR"

log "=== START start_all_forensic.sh ==="
log "USB: $USB"
log "MCP_DIR: $MCP_DIR"
log "CODEx_HOME: $CODEx_HOME"
log "LOGDIR: $LOGDIR"

# -----------------------
# 1) Gültigkeit Repo prüfen
# -----------------------
if [ ! -f "$KALI_PY" ]; then
  log "ERROR: $KALI_PY nicht gefunden. Stelle sicher, dass das Repo in $MCP_DIR geklont ist."
  exit 1
fi
if [ ! -f "$MCP_CLIENT_PY" ]; then
  log "WARN: $MCP_CLIENT_PY nicht gefunden. Client wird evtl. nicht verfügbar sein."
fi

# -----------------------
# 2) Venv erstellen / aktivieren + Pip-Upgrade + deps
# -----------------------
cd "$MCP_DIR"
if [ ! -d "$VENV_DIR" ]; then
  log "Erstelle venv in $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

log "Upgraden von pip/setuptools/wheel (innerhalb venv)"
python -m pip install --upgrade pip setuptools wheel 2>> "$LOGDIR/pip_install.err" || true

if [ -f requirements.txt ] && [ -s requirements.txt ]; then
  log "requirements.txt gefunden -> pip install -r requirements.txt"
  python -m pip install -r requirements.txt 2>> "$LOGDIR/pip_install.err" || {
    log "WARN: pip install -r requirements.txt hat Fehler geloggt (siehe pip_install.err)"
  }
else
  log "Keine requirements.txt -> installiere minimale Pakete: ${MINIMAL_PIP_PACKAGES[*]}"
  python -m pip install "${MINIMAL_PIP_PACKAGES[@]}" 2>> "$LOGDIR/pip_install.err" || {
    log "WARN: pip install (minimal) hat Fehler geloggt (siehe pip_install.err)"
  }
fi

# quick import-check
python - <<'PY' 2>> "$LOGDIR/pip_install.err" || true
try:
    import flask, requests
    print("IMPORT-OK")
except Exception as e:
    print("IMPORT-ERROR", e)
    raise SystemExit(1)
PY

# -----------------------
# 3) Patch: bind auf 127.0.0.1 erzwingen (idempotent, Backup)
# -----------------------
PATCH_BACKUP="$MCP_DIR/kali_server.py.bak.$(date +%Y%m%dT%H%M%S)"
if ! grep -q "127.0.0.1" "$KALI_PY"; then
  log "Patch: Ersetze 0.0.0.0 -> 127.0.0.1 falls vorhanden (Backup: $PATCH_BACKUP)"
  cp -a "$KALI_PY" "$PATCH_BACKUP"
  # Ersetze wörtliche "0.0.0.0" Vorkommen
  sed -i "s/'0.0.0.0'/'127.0.0.1'/g; s/\"0.0.0.0\"/\"127.0.0.1\"/g" "$KALI_PY" || true
  # Falls app.run vorkommt ohne host=..., füge host=127.0.0.1 ein (rudimentär)
  awk '
    /app.run/ && $0 !~ /host[[:space:]]*=/ {
      sub(/app.run[[:space:]]*\(/, "app.run(host=\\047127.0.0.1\\047, ")
    }
    { print }
  ' "$KALI_PY" > "$KALI_PY.tmp" && mv "$KALI_PY.tmp" "$KALI_PY" || true
else
  log "Patch: $KALI_PY enthält bereits 127.0.0.1 (keine Änderung)."
fi

# -----------------------
# 4) Stoppe vorherigen Prozess falls aktiv
# -----------------------
if [ -f "$PIDFILE" ]; then
  oldpid=$(cat "$PIDFILE" 2>/dev/null || echo "")
  if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    log "Stoppe alten Kali-Server PID $oldpid"
    kill "$oldpid" || true
    sleep 1
  fi
fi

# -----------------------
# 5) Starte den Server (nohup; venv aktiv)
# -----------------------
log "Starte Kali MCP Server (venv aktiv) — stdout: $STDOUT stderr: $STDERR"
nohup python3 "$KALI_PY" --host 127.0.0.1 --port 5000 >"$STDOUT" 2>"$STDERR" &
sleep 1
newpid=$!
# falls Prozess sofort abgestürzt ist, versuche ohne flags
if ! kill -0 "$newpid" 2>/dev/null; then
  log "Start mit Flags schlug fehl, versuche Start ohne Flags"
  nohup python3 "$KALI_PY" >"$STDOUT" 2>"$STDERR" &
  sleep 1
  newpid=$!
fi
echo "$newpid" > "$PIDFILE"
log "Kali-Server gestartet mit PID $newpid"

# -----------------------
# 6) Codex forensische Config schreiben (auf USB HOME)
# -----------------------
CODEx_CONF_DIR="$CODEx_HOME/.codex"
ensure_dir "$CODEx_CONF_DIR"
CFG_FILE="$CODEx_CONF_DIR/config.toml"

log "Erstelle/überschreibe Codex config: $CFG_FILE"
cat > "$CFG_FILE" <<'EOF'
[core]
# optional: default_model = "gpt-5-codex"

[mcp_servers.kali_mcp]
command = "python3"
args = ["/mnt/usb_rw/MCP-Kali-Server/mcp_server.py", "http://127.0.0.1:5000"]
env = { MCP_ALLOW_EXEC = "true" }
EOF

sha256sum "$CFG_FILE" > "$LOGDIR/config.sha256" || true
ls -l "$CFG_FILE" > "$LOGDIR/config.info" || true

# -----------------------
# 7) Test (listen, logs, optional npx test)
# -----------------------
log "Health-Check: Listening sockets (Port 5000):"
ss -ltnp | rg 5000 || true | tee -a "$REPORT"

log "Tail server stdout/stderr (last 60 lines):"
tail -n 60 "$STDOUT" 2>/dev/null | sed 's/^/STDOUT: /' | tee -a "$REPORT"
tail -n 60 "$STDERR" 2>/dev/null | sed 's/^/STDERR: /' | tee -a "$REPORT"

# optional: npx test (nur wenn npx vorhanden). Wir setzen HOME auf forensisches HOME, damit codex-config dort gelesen wird.
if command -v npx >/dev/null 2>&1; then
  log "npx vorhanden -> versuche 'npx -y @openai/codex mcp list' (HOME=$CODEx_HOME)"
  HOME="$CODEx_HOME" XDG_CONFIG_HOME="$CODEx_HOME" npx -y @openai/codex mcp list > "$LOGDIR/codex_mcp_list.out" 2>&1 || true
  log "npx output (erste 200 Zeilen):"
  sed -n '1,200p' "$LOGDIR/codex_mcp_list.out" | sed 's/^/NPX: /' | tee -a "$REPORT"
else
  log "npx nicht gefunden -> überspringe npx-Test. (Wenn du Codex testen willst, installiere npm & npx oder nutze 'npm install --prefix /mnt/usb_rw/codex_npm @openai/codex')"
fi

# -----------------------
# 8) Extra-Security: erzwinge loopback-only via iptables (optional, reversibel)
#    Nur wenn Server noch an 0.0.0.0 gebunden wäre (defensive)
# -----------------------
LISTEN_ADDR=$(ss -ltnp | rg 5000 || true | awk '{print $4}' | head -n1 || true)
if [ -n "$LISTEN_ADDR" ]; then
  if echo "$LISTEN_ADDR" | grep -q "^0.0.0.0:5000"; then
    log "Server lauscht auf 0.0.0.0:5000. Setze vorsichtige iptables-Regel, um externen Zugriff zu blocken (Loopback erlauben)."
    # Backup rules
    iptables-save > "$LOGDIR/iptables-before-5000.rules" 2>/dev/null || true
    # Einfügen: allow loopback src 127.0.0.1, then reject other incoming to 5000
    iptables -C INPUT -p tcp -s 127.0.0.1 --dport 5000 -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 1 -p tcp -s 127.0.0.1 --dport 5000 -j ACCEPT
    iptables -C INPUT -p tcp --dport 5000 -j REJECT --reject-with tcp-reset 2>/dev/null || \
      iptables -I INPUT 2 -p tcp --dport 5000 -j REJECT --reject-with tcp-reset
    log "iptables rule gesetzt (siehe $LOGDIR/iptables-before-5000.rules zum Restore)."
  else
    log "Server lauscht bereits lokal (nicht 0.0.0.0): $LISTEN_ADDR"
  fi
else
  log "Warnung: Kein Listener für Port 5000 gefunden (Start evtl. fehlgeschlagen)."
fi

# -----------------------
# 9) Kurzer End-Report
# -----------------------
log "=== Kurzer Report ==="
printf "Kali PID: %s\n" "$(cat "$PIDFILE" 2>/dev/null || echo 'n/a')" | tee -a "$REPORT"
ss -ltnp | rg 5000 || true | tee -a "$REPORT"
printf "\nConfig: %s\n" "$CFG_FILE" | tee -a "$REPORT"
sha256sum "$CFG_FILE" | tee -a "$REPORT"
printf "\nLogs: %s (stdout), %s (stderr)\n" "$STDOUT" "$STDERR" | tee -a "$REPORT"
printf "\nFür Debug: less %s\n" "$REPORT" | tee -a "$REPORT"

log "=== ENDE start_all_forensic.sh ==="
deactivate 2>/dev/null || true

exit 0
