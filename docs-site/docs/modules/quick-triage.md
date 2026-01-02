<!-- AUTODOC:BEGIN -->
---
title: "Quick Triage Module"
description: "Erstellt einen Schnellbericht zur Systemlage (Prozesse, Benutzer, Netzwerk)."
---

# Zusammenfassung

- **Kategorie:** Triage
- **CLI-Name:** `quick_triage`
- **Guard-Level:** Soft — sammelt nur ungefährliche Systeminformationen.
- **Unterstützte Evidenz:** live host
- **Backends/Extras:** POSIX-Kommandos, Python-Bibliotheken
- **Abhängigkeiten:** coreutils, ps, ss/netstat
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `profile` | No | default | Triage-Profil (default / minimal / extended). |
| `dry_run` | No | false | Nur Planung. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run quick_triage --case demo_case --dry-run
```

**Ausführung**
```bash
forensic-cli modules run quick_triage --case demo_case --param profile=extended
```

## Ausgaben & Provenienz
- Markdown/JSON-Snapshot unter triage/quick/.
- CSV-Listen mit laufenden Prozessen/Verbindungen.

**Chain of Custody:** Snapshots enthalten Hashes, Pfade und Zeitstempel; Provenienz referenziert Profil.

## Guard-Fehlermeldungen
- Guard-Hinweis, falls Tools fehlen (Status `partial`).

## Verwandte Dokumentation
- [Triage](../MODULES/triage.md)
- [01 Quick Triage Linux](../tutorials/01_quick-triage-linux.md)

<!-- AUTODOC:END -->
