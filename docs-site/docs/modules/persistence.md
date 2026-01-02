<!-- AUTODOC:BEGIN -->
---
title: "Persistence Module"
description: "Inventarisiert übliche Persistenzmechanismen (systemd, Cron, Autostart)."
---

# Zusammenfassung

- **Kategorie:** Triage
- **CLI-Name:** `persistence`
- **Guard-Level:** Soft — Dry-Run standard, durchsucht nur definierte Pfade.
- **Unterstützte Evidenz:** live host
- **Backends/Extras:** Dateisystem-Scans
- **Abhängigkeiten:** Leserechte auf Konfigurationspfade
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `paths` | No | config/triage.persistence | Kategorie→Pfad Mapping. |
| `dry_run` | No | false | Nur Planung, keine Dateizugriffe. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run persistence --case demo_case --dry-run
```

**Ausführung**
```bash
forensic-cli modules run persistence --case demo_case --param paths.systemd_units=/etc/systemd/system
```

## Ausgaben & Provenienz
- CSV-Report `persistence.csv` mit Kategorien, Pfaden, Hashes.
- Markdown/JSON-Zusammenfassung je Kategorie.

**Chain of Custody:** Jede gefundene Datei mit Hash & Zeitstempel im Provenienz-Log.

## Guard-Fehlermeldungen
- Guard `No persistence targets configured` bei leerer Pfadliste.

## Verwandte Dokumentation
- [Triage](../MODULES/triage.md)
- [01 Quick Triage Linux](../tutorials/01_quick-triage-linux.md)

<!-- AUTODOC:END -->
