#!/usr/bin/env bash
# forensic_clone.sh — Forensisches 1:1-Cloning mit ddrescue
# Features:
#   - Optionales "Sanitizing" des Zielmediums (zero|random|none)
#   - Sichere Vorab-Checks (Root, Gerätetyp, nicht gemountet, Größenabgleich)
#   - Zweiphasiges ddrescue (fast pass + retries) mit Log
#   - Chain-of-Custody Protokoll + Geräte-Snapshots (lsblk/blkid/smart/nvme)
#   - Hash-Verifikation (sha256/blake2b/none)
#   - Optionales Read-Only Mounting typischer Filesysteme (ext4/btrfs/xfs)
#
# Usage-Beispiele am Ende der Datei.
set -Eeuo pipefail

# ---------- Default-Optionen ----------
SANITIZE="zero"           # zero|random|none
RETRIES="3"               # ddrescue retry count
HASH="sha256"             # sha256|blake2b|none
CHUNK="1M"                # dd/Hash Read-Blockgröße
LABEL=""                  # Freitext zur Dokumentation
LOGDIR="/mnt/forensic_workdir"
MOUNT_RO="false"          # true/false
YES="false"               # Zerstörerische Schritte ohne Rückfrage erlauben
DDRESCUE_BIN="ddrescue"

# ---------- Helpers ----------
err()   { echo "ERROR: $*" >&2; exit 1; }
note()  { echo "[*] $*"; }
ok()    { echo "[✓] $*"; }
ts()    { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# ---------- Usage ----------
usage() {
  cat <<EOF
Forensisches 1:1 Cloning mit ddrescue

Pflichtargumente:
  --source /dev/XXX       Quellgerät (ganze Disk, NICHT Partition)
  --target /dev/YYY       Zielgerät (ganze Disk, wird überschrieben)

Optionen:
  --logdir PATH           Verzeichnis für Logs & Artefakte (Default: $LOGDIR)
  --sanitize MODE         zero|random|none (Default: $SANITIZE)
  --retries N             ddrescue -rN (Default: $RETRIES)
  --hash ALG              sha256|blake2b|none (Default: $HASH)
  --chunk SIZE            Read-Block für Hashes (Default: $CHUNK)
  --label TEXT            Zusatznotiz für Chain-of-Custody
  --mount-ro              Nach dem Clone Ziel-Partition(en) Read-Only mounten
  --yes                   Sicherheitsrückfragen unterdrücken (non-interaktiv)
  --ddrescue PATH         ddrescue Binary (Default: $DDRESCUE_BIN)
  --help                  Diese Hilfe

Beispiele:
  sudo ./forensic_clone.sh --source /dev/nvme1n1 --target /dev/nvme0n1 --logdir /mnt/forensic_workdir --sanitize zero --hash sha256 --retries 3 --yes
  sudo ./forensic_clone.sh --source /dev/sdb      --target /dev/sdc      --sanitize random --hash blake2b --mount-ro --yes

EOF
}

# ---------- Arg-Parsing ----------
SOURCE=""
TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)   SOURCE="${2:-}"; shift 2;;
    --target)   TARGET="${2:-}"; shift 2;;
    --logdir)   LOGDIR="${2:-}"; shift 2;;
    --sanitize) SANITIZE="${2:-}"; shift 2;;
    --retries)  RETRIES="${2:-}"; shift 2;;
    --hash)     HASH="${2:-}"; shift 2;;
    --chunk)    CHUNK="${2:-}"; shift 2;;
    --label)    LABEL="${2:-}"; shift 2;;
    --mount-ro) MOUNT_RO="true"; shift;;
    --yes)      YES="true"; shift;;
    --ddrescue) DDRESCUE_BIN="${2:-}"; shift 2;;
    --help|-h)  usage; exit 0;;
    *) err "Unbekannte Option: $1 (nutze --help)";;
  esac
done

[[ -n "$SOURCE" && -n "$TARGET" ]] || { usage; err "Bitte --source und --target angeben."; }
[[ -b "$SOURCE" ]] || err "SOURCE ist kein Blockdevice: $SOURCE"
[[ -b "$TARGET" ]] || err "TARGET ist kein Blockdevice: $TARGET"
[[ "$SOURCE" != "$TARGET" ]] || err "SOURCE und TARGET dürfen nicht identisch sein."

# Nur ganze Disks erlauben (keine Partitionen wie ...p1, sda1 etc.)
case "$SOURCE" in *[0-9]) err "SOURCE wirkt wie eine Partition ($SOURCE). Bitte ganze Disk angeben.";; esac
case "$TARGET" in *[0-9]) err "TARGET wirkt wie eine Partition ($TARGET). Bitte ganze Disk angeben.";; esac

# Root erforderlich
[[ "$(id -u)" -eq 0 ]] || err "Bitte mit sudo/root ausführen."

# Tools prüfen
command -v "$DDRESCUE_BIN" >/dev/null || err "ddrescue nicht gefunden (gesetzt als: $DDRESCUE_BIN)"
command -v lsblk >/dev/null || err "lsblk fehlt (util-linux)"
command -v blkid >/dev/null || err "blkid fehlt (util-linux)"
command -v wipefs >/dev/null || err "wipefs fehlt (util-linux)"
command -v partprobe >/dev/null || err "partprobe fehlt (parted/pptools)"

# Hash Binaries
case "$HASH" in
  sha256)  HASH_BIN="sha256sum";;
  blake2b) HASH_BIN="b2sum";;   # aus coreutils
  none)    HASH_BIN="";;
  *) err "Unbekannter Hash-Algorithmus: $HASH";;
esac
[[ -z "$HASH_BIN" || -x "$(command -v "$HASH_BIN" || true)" ]] || err "Hash-Tool nicht gefunden: $HASH_BIN"

# Logdir vorbereiten
mkdir -p "$LOGDIR"
[[ -w "$LOGDIR" ]] || err "Kann nicht in LOGDIR schreiben: $LOGDIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COC="$LOGDIR/chain_of_custody.txt"
RUNLOG="$LOGDIR/run_${TS}.log"
DDRESCUE_LOG="$LOGDIR/ddrescue_${TS}.log"
INFO_DIR="$LOGDIR/snapshots_${TS}"
MOUNT_ROOT="$LOGDIR/mount_${TS}"
mkdir -p "$INFO_DIR"

exec > >(tee -a "$RUNLOG") 2>&1
note "Forensic Clone gestartet @ $(ts)"
note "SOURCE: $SOURCE"
note "TARGET: $TARGET"
note "LOGDIR: $LOGDIR"
note "SANITIZE: $SANITIZE | RETRIES: $RETRIES | HASH: $HASH | CHUNK: $CHUNK | MOUNT_RO: $MOUNT_RO"
[[ -n "$LABEL" ]] && note "LABEL: $LABEL"

# ---------- Safety: Mount-Status prüfen ----------
is_mounted() {
  local dev="$1"
  lsblk -no MOUNTPOINT "$dev" | grep -qE '.+'
}
if is_mounted "$SOURCE"; then
  err "SOURCE hat gemountete Partitionen. Bitte alles aushängen (umount) vor dem Start."
fi
if is_mounted "$TARGET"; then
  err "TARGET hat gemountete Partitionen. Bitte alles aushängen (umount) vor dem Start."
fi

# ---------- Größenabgleich ----------
get_size() { blockdev --getsize64 "$1"; }
SIZE_SRC="$(get_size "$SOURCE")"
SIZE_TGT="$(get_size "$TARGET")"
note "Größe SOURCE: $SIZE_SRC Bytes | Ziel: $SIZE_TGT Bytes"

# Ziel muss >= Quelle sein
if (( SIZE_TGT < SIZE_SRC )); then
  err "TARGET ist kleiner als SOURCE. Abbruch."
fi

# ---------- Snapshots/Inventar ----------
note "Erfasse Geräte-Snapshots (lsblk/blkid/smart/nvme)…"
lsblk -o NAME,MODEL,SERIAL,SIZE,ROTA,TYPE,FSTYPE,MOUNTPOINT,WWN,VENDOR > "$INFO_DIR/lsblk_before.txt"
blkid -o full > "$INFO_DIR/blkid_before.txt" || true
( command -v smartctl >/dev/null && smartctl -a "$SOURCE" > "$INFO_DIR/smart_SOURCE.txt" ) || true
( command -v smartctl >/dev/null && smartctl -a "$TARGET" > "$INFO_DIR/smart_TARGET.txt" ) || true
( command -v nvme >/dev/null && nvme list > "$INFO_DIR/nvme_list.txt" ) || true
( command -v nvme >/dev/null && nvme id-ctrl "$SOURCE" > "$INFO_DIR/nvme_id_SOURCE.txt" ) || true
( command -v nvme >/dev/null && nvme id-ctrl "$TARGET" > "$INFO_DIR/nvme_id_TARGET.txt" ) || true

echo "$(ts) - START (label='$LABEL') SOURCE=$SOURCE TARGET=$TARGET SANITIZE=$SANITIZE RETRIES=$RETRIES HASH=$HASH LOGDIR=$LOGDIR" | tee -a "$COC" >/dev/null

# ---------- Sanitizing TARGET (optional) ----------
case "$SANITIZE" in
  zero|random)
    if [[ "$YES" != "true" ]]; then
      echo "WARNUNG: $TARGET wird JETZT vollständig überschrieben ($SANITIZE wipe)."
      read -r -p "Fortfahren? (YES/NO): " ANS
      [[ "$ANS" == "YES" ]] || err "Abgebrochen."
    fi
    note "Wipe TARGET mit $SANITIZE… (das kann dauern)"
    if [[ "$SANITIZE" == "zero" ]]; then
      dd if=/dev/zero of="$TARGET" bs=4M status=progress oflag=direct || err "Zero-Wipe fehlgeschlagen"
    else
      dd if=/dev/urandom of="$TARGET" bs=4M status=progress oflag=direct || err "Random-Wipe fehlgeschlagen"
    fi
    partprobe "$TARGET" || true
    wipefs -a "$TARGET" || true
    ok "TARGET sterilisiert."
    echo "$(ts) - SANITIZE TARGET=$TARGET mode=$SANITIZE" | tee -a "$COC" >/dev/null
    ;;
  none)
    note "Kein Wipe (sanitize=none) – TARGET bleibt unverändert vor Clone."
    ;;
  *)
    err "Ungültiger SANITIZE-Modus: $SANITIZE"
    ;;
esac

# ---------- ddrescue Clone ----------
note "Starte ddrescue Phase 1 (schnelle Kopie, -n)…"
"$DDRESCUE_BIN" -v -n "$SOURCE" "$TARGET" "$DDRESCUE_LOG"
ok "Phase 1 abgeschlossen."

note "Starte ddrescue Phase 2 (Retries -r$RETRIES)…"
"$DDRESCUE_BIN" -v -r"$RETRIES" "$SOURCE" "$TARGET" "$DDRESCUE_LOG"
ok "Phase 2 abgeschlossen."

echo "$(ts) - CLONE SOURCE=$SOURCE -> TARGET=$TARGET ddrescue_log=$(basename "$DDRESCUE_LOG")" | tee -a "$COC" >/dev/null

# ---------- Snapshots nach Clone ----------
lsblk -o NAME,MODEL,SERIAL,SIZE,ROTA,TYPE,FSTYPE,MOUNTPOINT,WWN,VENDOR > "$INFO_DIR/lsblk_after.txt"
blkid -o full > "$INFO_DIR/blkid_after.txt" || true

# ---------- Hash-Verifikation (optional) ----------
SRC_HASH_FILE="$LOGDIR/$(basename "$SOURCE")_${TS}.${HASH}.txt"
TGT_HASH_FILE="$LOGDIR/$(basename "$TARGET")_${TS}.${HASH}.txt"
if [[ -n "$HASH_BIN" ]]; then
  note "Berechne $HASH von SOURCE (kann dauern)…"
  dd if="$SOURCE" bs="$CHUNK" status=progress iflag=direct 2>/dev/null | "$HASH_BIN" | tee "$SRC_HASH_FILE" >/dev/null
  ok "SOURCE Hash gespeichert: $SRC_HASH_FILE"

  note "Berechne $HASH von TARGET (kann dauern)…"
  dd if="$TARGET" bs="$CHUNK" status=progress iflag=direct 2>/dev/null | "$HASH_BIN" | tee "$TGT_HASH_FILE" >/dev/null
  ok "TARGET Hash gespeichert: $TGT_HASH_FILE"

  if diff -q "$SRC_HASH_FILE" "$TGT_HASH_FILE" >/dev/null; then
    ok "Hash-Vergleich OK — 1:1-Abbild verifiziert."
    echo "$(ts) - HASH OK algo=$HASH src=$(basename "$SRC_HASH_FILE") tgt=$(basename "$TGT_HASH_FILE")" | tee -a "$COC" >/dev/null
  else
    err "Hash mismatch! Siehe Dateien: $SRC_HASH_FILE vs $TGT_HASH_FILE"
  fi
else
  note "Hash-Verifikation übersprungen (hash=none)."
  echo "$(ts) - HASH SKIPPED" | tee -a "$COC" >/dev/null
fi

# ---------- Optional: Mount Read-Only ----------
if [[ "$MOUNT_RO" == "true" ]]; then
  note "Versuche Read-Only Mount des ZIEL-Abbilds…"
  mkdir -p "$MOUNT_ROOT"
  # Partitionsliste des TARGET besorgen
  mapfile -t PARTS < <(lsblk -ln -o NAME,TYPE "/dev/$(basename "$TARGET")" | awk '$2=="part"{print $1}')
  if [[ "${#PARTS[@]}" -eq 0 ]]; then
    note "Keine Partitionen am TARGET erkannt (evtl. RAW-Image/Fehler?). Überspringe Mount."
  else
    for pn in "${PARTS[@]}"; do
      dev="/dev/$pn"
      fstype="$(blkid -o value -s TYPE "$dev" || true)"
      mdir="$MOUNT_ROOT/$pn"
      mkdir -p "$mdir"
      case "$fstype" in
        ext2|ext3|ext4)  mount -o ro,noload "$dev" "$mdir" && ok "Mounted $dev (ext*) -> $mdir" || note "Mount fehlgeschlagen: $dev";;
        btrfs)           mount -o ro "$dev" "$mdir" && ok "Mounted $dev (btrfs) -> $mdir" || note "Mount fehlgeschlagen: $dev";;
        xfs)             mount -o ro,norecovery "$dev" "$mdir" && ok "Mounted $dev (xfs) -> $mdir" || note "Mount fehlgeschlagen: $dev";;
        ntfs)            mount -o ro "$dev" "$mdir" && ok "Mounted $dev (ntfs) -> $mdir" || note "Mount fehlgeschlagen: $dev";;
        exfat|vfat)      mount -o ro "$dev" "$mdir" && ok "Mounted $dev ($fstype) -> $mdir" || note "Mount fehlgeschlagen: $dev";;
        "")              note "Kein Filesystem erkennbar auf $dev. Überspringe.";;
        *)               note "Unbekanntes Filesystem '$fstype' auf $dev. Versuche generisches ro-Mount…"; mount -o ro "$dev" "$mdir" && ok "Mounted $dev -> $mdir" || note "Mount fehlgeschlagen: $dev";;
      esac
    done
    echo "$(ts) - MOUNT_RO root=$MOUNT_ROOT" | tee -a "$COC" >/dev/null
  fi
fi

ok "Forensisches Cloning abgeschlossen @ $(ts)"
echo "Artefakte:"
echo "  - Chain-of-Custody: $COC"
echo "  - ddrescue Log:     $DDRESCUE_LOG"
[[ -n "$HASH_BIN" ]] && echo "  - Hashes:           $SRC_HASH_FILE | $TGT_HASH_FILE"
echo "  - Snapshots:        $INFO_DIR"
[[ "$MOUNT_RO" == "true" ]] && echo "  - Mount-Root (ro):  $MOUNT_ROOT"
exit 0

# ------------------ Beispiele ------------------
# 1) Standard-Workflow (Ziel vorher nullen, 3 Retries, SHA256, keine Nachfragen):
# sudo ./forensic_clone.sh --source /dev/nvme1n1 --target /dev/nvme0n1 --logdir /mnt/forensic_workdir --sanitize zero --retries 3 --hash sha256 --yes
#
# 2) Gründlicher Wipe (random), BLAKE2b Hash, anschließend Read-Only mounten:
# sudo ./forensic_clone.sh --source /dev/sdb --target /dev/sdc --sanitize random --hash blake2b --mount-ro --yes
#
# 3) Kein Wipe (z. B. Ziel frisch fabrikneu), Hash überspringen:
# sudo ./forensic_clone.sh --source /dev/nvme1n1 --target /dev/nvme0n1 --sanitize none --hash none --yes
