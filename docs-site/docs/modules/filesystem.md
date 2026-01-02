<!-- AUTODOC:BEGIN -->
---
title: "Filesystem Analysis Module"
description: "Analysiert Dateisysteme mit Sleuthkit (Partitionen, gelöschte Dateien, Hashes)."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `filesystem_analysis`
- **Guard-Level:** Medium — benötigt Sleuthkit, operiert read-only auf Images.
- **Unterstützte Evidenz:** disk images, partitions
- **Backends/Extras:** Sleuthkit (fls, fsstat, mmls)
- **Abhängigkeiten:** sleuthkit (fls, fsstat, icat, istat)
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `image` | Yes | — | Pfad zum Disk-Image (E01, RAW, Partition). |
| `partition` | No | auto | Nummer der Partition oder Auto-Erkennung. |
| `include_deleted` | No | true | Einbezug gelöschter Einträge. |
| `extract_strings` | No | false | Strings pro Datei extrahieren. |
| `compute_hashes` | No | false | Dateihashes berechnen. |
| `max_depth` | No | 0 | Maximale Verzeichnistiefe (0 = unlimitiert). |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run filesystem_analysis --case demo_case --param image=cases/demo_case/evidence/disk01.E01 --dry-run
```

**Ausführung**
```bash
forensic-cli modules run filesystem_analysis --case demo_case --param image=cases/demo_case/evidence/disk01.E01 --param compute_hashes=true
```

## Ausgaben & Provenienz
- Analysebericht `filesystem.json`.
- Listen der gefundenen Partitionen und Artefakte unter analysis/filesystem/.
- Protokoll in logs/modules/filesystem_analysis-<ts>.log.

**Chain of Custody:** Alle generierten Artefakte werden gehasht und im Provenienz-Log aufgeführt.

## Guard-Fehlermeldungen
- Missing tool result wenn `fls` fehlt.
- `Image file does not exist` bei falschem Pfad.

## Verwandte Dokumentation
- [Analysis](../MODULES/analysis.md)
- [Timeline](timeline.md)

<!-- AUTODOC:END -->
