<!-- AUTODOC:BEGIN -->
---
title: "Extract Router Artefacts"
description: "Entpackt UI-Dumps, Konfigurationsarchive und Logbundles aus Router-Backups."
---

# Überblick

`forensic-cli router extract` arbeitet read-only auf Archiven oder Mountpoints. Der Dry-Run listet alle Dateien und Zielpfade,
inklusive Hash-Plan, bevor Extraktionen freigegeben werden.

## Parameter
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--input` | Ja | — | Tar-/Zip-Archiv oder Verzeichnis mit Router-Dump. |
| `--out` | Ja | — | Zielordner für extrahierte Artefakte. |
| `--profile` | Nein | `ui` | Extraktionsprofil aus `config/modules/router/extract.yaml` (z. B. `logs`, `configs`). |
| `--dry-run` | Nein | `true` | Listet nur geplante Dateien, schreibt nichts. |

## Ausgaben
- Extrahierte Dateien unter `<out>/` mit beibehaltenen Zeitstempeln.
- `extract_manifest.json` inklusive Hashes & Offsets.
- Logs in `<out>/../logs/router_extract-<timestamp>.log`.

## Betriebsnotizen
- Chain-of-Custody wird aktualisiert, sobald Dateien tatsächlich extrahiert werden.
- Tar/Zip werden mit Python-Standardbibliothek geöffnet; fehlende Module erzeugen Guard-Warnungen.
- Verwenden Sie `--profile legacy`, um ursprüngliche Skriptpfade zu validieren.
<!-- AUTODOC:END -->
