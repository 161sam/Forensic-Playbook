<!-- AUTODOC:BEGIN -->
---
title: "System Info Module"
description: "Aggregiert Systeminformationen (Hardware, OS, Benutzer) für den Schnellüberblick."
---

# Zusammenfassung

- **Kategorie:** Triage
- **CLI-Name:** `system_info`
- **Guard-Level:** Soft — read-only Hostinformationen, keine Elevation nötig.
- **Unterstützte Evidenz:** live host
- **Backends/Extras:** Python platform/socket, lsb_release
- **Abhängigkeiten:** lsb_release (optional)
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `sections` | No | all | Auswahl an Informationsblöcken. |
| `dry_run` | No | false | Nur vorbereiten. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run system_info --case demo_case --dry-run
```

**Ausführung**
```bash
forensic-cli modules run system_info --case demo_case --param sections=hardware,users
```

## Ausgaben & Provenienz
- `system_info.json` und Markdown-Snapshot unter triage/system_info/.

**Chain of Custody:** Schreibt Hashes und Parameter in meta/provenance.jsonl.

## Guard-Fehlermeldungen
- Guard-Hinweis wenn bestimmte Utilities fehlen (Status `success` mit Warnung).

## Verwandte Dokumentation
- [Triage](/modules/triage)
- [Minimal E2E](../examples/minimal-e2e.md)

<!-- AUTODOC:END -->
