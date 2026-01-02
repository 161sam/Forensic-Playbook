<!-- AUTODOC:BEGIN -->
---
title: "IoC Scanning Module"
description: "Geplanter Scanner für Indicators of Compromise (Hashes, Domains, IPs)."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `ioc_scanning`
- **Guard-Level:** Planned — Modul befindet sich im Entwurf und ersetzt Legacy-Skripte.
- **Unterstützte Evidenz:** filesystem exports, memory reports, network summaries
- **Backends/Extras:** YARA, custom matchers (in Planung)
- **Abhängigkeiten:** yara (optional), lokale IoC-Feeds
- **Optionale Extras:** ioc

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `input` | Yes | — | Pfad zu Artefakten oder CSV-Datei. |
| `ioc_file` | Yes | config/iocs/default.json | IOC-Definitionen (JSON/YAML). |
| `match_types` | No | hash,domain,ip | Welche IoC-Typen ausgewertet werden. |
| `output` | No | analysis/ioc/matches.json | Speicherort für Ergebnisse. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run ioc_scanning --case demo_case --param input=analysis/timeline/timeline.csv --dry-run
```

**Ausführung**
```bash
forensic-cli modules run ioc_scanning --case demo_case --param input=analysis/timeline/timeline.csv --param ioc_file=config/iocs/high_priority.json
```

## Ausgaben & Provenienz
- Geplanter JSON-Report mit Treffern und Kontext.
- Optionale CSV-Ausgabe für Chain-of-Custody.

**Chain of Custody:** Sobald implementiert, werden Hashes & IoC-Quellen vermerkt.

## Guard-Fehlermeldungen
- Noch keine Fehlermeldungen — Modul markiert als TODO.

## Verwandte Dokumentation
- [Analysis](../modules/analysis.md)
- [Ioc Hunting](../examples/ioc-hunting.md)

<!-- AUTODOC:END -->
