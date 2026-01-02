<!-- AUTODOC:BEGIN -->
---
title: "Memory Dump Module"
description: "Erstellt geschützte RAM-Abzüge via AVML (Linux) und protokolliert Metadaten."
---

# Zusammenfassung

- **Kategorie:** Acquisition
- **CLI-Name:** `memory_dump`
- **Guard-Level:** Hard — verlangt --enable-live-capture und prüft Plattform/Tooling.
- **Unterstützte Evidenz:** memory
- **Backends/Extras:** AVML (Linux), manuelle Hinweise für Windows
- **Abhängigkeiten:** avml (Linux)
- **Optionale Extras:** memory extra (optional für spätere Analyse)

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `enable_live_capture` | Yes | false | Bestätigung für Live-Speicherdump. |
| `dry_run` | No | false | Nur Befehle planen, keine Dateien schreiben. |
| `hostname` | No | Systemhostname | Namenspräfix für Ausgabedateien. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run memory_dump --case demo_case --param enable_live_capture=false --dry-run
```

**Ausführung**
```bash
sudo forensic-cli modules run memory_dump --case demo_case --param enable_live_capture=true
```

## Ausgaben & Provenienz
- RAW-Speicherabbild unter `cases/<case>/acq/memdump/`.
- `.meta.json` mit Hostinformationen und Hashes.
- Logs unter `logs/modules/memory_dump-<ts>.log`.

**Chain of Custody:** Hash und Pfade in Chain-of-Custody; Dry-Run vermerkt im Provenienzstrom.

## Guard-Fehlermeldungen
- Status `skipped` wenn --enable-live-capture fehlt.
- Hinweis auf winpmem bei Windows, markiert als `skipped`.
- `avml` fehlt → guidance Install Microsoft's AVML.

## Verwandte Dokumentation
- [Acquisition](/modules/acquisition)
- [Memory](memory.md)

<!-- AUTODOC:END -->
