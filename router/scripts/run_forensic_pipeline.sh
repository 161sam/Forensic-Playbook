#!/usr/bin/env bash
# idempotent master pipeline to run forensic extraction & create reports
set -euo pipefail
# CONFIG
BASE_DIR="${BASE_DIR:-/mnt/FORNSIC_20251006}"
CONF_DIR="${CONF_DIR:-$BASE_DIR/conf}"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
NOW="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$LOG_DIR/run_$NOW"
mkdir -p "$LOG_DIR" "$CONF_DIR" "$RUN_DIR" "$SCRIPT_DIR" "$BASE_DIR/reports"

# create a 'latest' symlink (idempotent)
ln -snf "$RUN_DIR" "$LOG_DIR/latest"

echo "Starting forensic pipeline: $NOW"
echo "BASE_DIR=$BASE_DIR"
echo "CONF_DIR=$CONF_DIR"
echo "LOG_DIR=$LOG_DIR"
echo "RUN_DIR=$RUN_DIR"

# copy helper scripts into run dir for provenance (idempotent)
for s in extract_ui_artifacts.sh extract_portforwards.sh extract_ddns.sh extract_tr069.sh \
         extract_eventlog.sh extract_session_csrf.sh extract_devices.sh find_backups.sh \
         tcpdump_setup.sh summarize_report.sh; do
  if [ -f "$SCRIPT_DIR/$s" ]; then
    cp -f "$SCRIPT_DIR/$s" "$RUN_DIR/$s"
    chmod +x "$RUN_DIR/$s"
  fi
done

# Execute extraction steps (each script is idempotent)
"$SCRIPT_DIR/extract_ui_artifacts.sh"   "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_portforwards.sh"  "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_ddns.sh"          "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_tr069.sh"         "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_eventlog.sh"      "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_session_csrf.sh"  "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/extract_devices.sh"       "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/find_backups.sh"          "$CONF_DIR" "$RUN_DIR" || true
"$SCRIPT_DIR/tcpdump_setup.sh"         "$CONF_DIR" "$RUN_DIR" || true

# Finally create a consolidated report
"$SCRIPT_DIR/summarize_report.sh" "$CONF_DIR" "$RUN_DIR" "$BASE_DIR/reports" || true

echo "Pipeline finished. Run artifacts and report are in: $RUN_DIR"
echo "Latest report link(s):"
ls -1 "$BASE_DIR/reports" | tail -n 5 || true
