<!-- AUTODOC:BEGIN -->
---
title: "Registry Analysis Module"
description: "Untersucht Windows-Registry-Hives auf System-, Benutzer- und Persistenz-Artefakte."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `registry_analysis`
- **Guard-Level:** Medium — read-only, prüft Vorhandensein der Hives.
- **Unterstützte Evidenz:** Windows system images or extracted directories
- **Backends/Extras:** Interner Parser, optional RegRipper
- **Abhängigkeiten:** reglookup, rip.pl (optional)
- **Optionale Extras:** registry extra (optional)

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `target` | Yes | — | Verzeichnis oder Mountpoint mit Registry-Hives. |
| `regripper` | No | false | RegRipper-Integration aktivieren. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run registry_analysis --case demo_case --param target=/mnt/win_mount --dry-run
```

**Ausführung**
```bash
forensic-cli modules run registry_analysis --case demo_case --param target=/mnt/win_mount --param regripper=true
```

## Ausgaben & Provenienz
- `registry.json` mit Hives, Persistence, USB-Historie.
- Unterordner mit extrahierten Reports je Kategorie.

**Chain of Custody:** Hives und Findings werden mit Pfadangaben in meta/provenance.jsonl dokumentiert.

## Guard-Fehlermeldungen
- `Target does not exist` bei falschem Pfad.
- `No registry hives found` falls Pfad leer.

## Verwandte Dokumentation
- [Analysis](/modules/analysis)
- [03 Registry Analysis Windows](../tutorials/03-registry-analysis-windows.md)

<!-- AUTODOC:END -->
