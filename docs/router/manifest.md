<!-- AUTODOC:BEGIN -->
---
title: "Router Manifest Generation"
description: "Erstellt Inventarlisten mit Hashes für Router-Artefakte."
---

# Überblick

`forensic-cli router manifest write` generiert Hash-Manifeste aus zuvor extrahierten Dateien und dokumentiert jeden Eintrag im
Provenienzstrom.

## Parameter
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--source` | Ja | — | Ordner mit extrahierten Router-Dateien. |
| `--out` | Ja | — | Zieldatei für Manifest (JSON/CSV). |
| `--format` | Nein | `json` | Ausgabeformat (`json`, `csv`). |
| `--hash` | Nein | `sha256` | Hash-Algorithmus für Artefakte. |
| `--dry-run` | Nein | `true` | Zeigt Dateiliste, schreibt nichts. |

## Ausgaben
- `manifest.json` oder `manifest.csv` mit Hash, Größe, Pfad und Zeitstempel.
- Zusammenfassung in `manifest_summary.json` (Anzahl, Gesamtgröße).

## Betriebsnotizen
- Provenienz enthält Quelle, Hash-Algorithmus und Gesamtanzahl der Artefakte.
- Unterstützt Delta-Vergleiche durch deterministische Sortierung und Hash-Listen.
- Manifest-Dateien sollten zusammen mit PCAPs/Extraktionen archiviert werden.
<!-- AUTODOC:END -->
