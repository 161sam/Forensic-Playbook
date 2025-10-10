<!-- AUTODOC:BEGIN -->
---
title: "Timeline Module"
description: "Erstellt korrelierte Forensik-Timelines aus Images, Logs und Netzwerkdaten."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `timeline`
- **Guard-Level:** Medium — nutzt plaso/log2timeline und Sleuthkit, arbeitet auf kopierten Artefakten.
- **Unterstützte Evidenz:** log directories, filesystem exports, network outputs
- **Backends/Extras:** plaso/log2timeline, mactime (sleuthkit)
- **Abhängigkeiten:** log2timeline.py, mactime, fls
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `source` | Yes | — | Ordner, Image oder Sammlung für Timeline. |
| `format` | No | csv | Ausgabeformat (csv, l2tcsv, body, json). |
| `type` | No | auto | Erzwingt Backend (auto / plaso / mactime). |
| `start_date` | No | — | Filter (YYYY-MM-DD). |
| `end_date` | No | — | Filter (YYYY-MM-DD). |
| `include_mft` | No | true | NTFS-$MFT einbeziehen. |
| `include_usnjrnl` | No | false | USN Journal analysieren. |
| `include_browser` | No | true | Browser-Artefakte aufnehmen. |
| `include_logs` | No | true | System-/Anwendungslogs berücksichtigen. |
| `timezone` | No | UTC oder config | Zeitzone für Ausgabe. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run timeline --case demo_case --param source=cases/demo_case/analysis/network --param format=csv --dry-run
```

**Ausführung**
```bash
forensic-cli modules run timeline --case demo_case --param source=cases/demo_case/analysis/network --param include_usnjrnl=true
```

## Ausgaben & Provenienz
- `timeline.<fmt>` im analysis/timeline/ Verzeichnis.
- `timeline_meta.json` mit Parametern, Filterregeln, Tools.

**Chain of Custody:** Timeline-Dateien werden gehasht; plaso/mactime Versionen im Provenienz-Record.

## Guard-Fehlermeldungen
- `Source does not exist` bei falschem Pfad.
- Missing tool result wenn plaso/mactime fehlen.

## Verwandte Dokumentation
- [Analysis](../MODULES/analysis.md)
- [02 Network Timeline Walkthrough](../tutorials/02_network-timeline-walkthrough.md)

<!-- AUTODOC:END -->
