<!-- AUTODOC:BEGIN -->
---
title: "Live Response Module"
description: "Sammelt Host-Metadaten über eine Allowlist an Kommandos (uname, ps, netstat, mount, systemctl)."
---

# Zusammenfassung

- **Kategorie:** Acquisition
- **CLI-Name:** `live_response`
- **Guard-Level:** Medium — dry-run optional, führt nur erlaubte Read-Only-Kommandos aus.
- **Unterstützte Evidenz:** local system
- **Backends/Extras:** POSIX-Utilities (uname, ps, netstat, systemctl)
- **Abhängigkeiten:** uname, ps, netstat/ss, mount, systemctl
- **Optionale Extras:** —

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `commands` | No | Allowlist | Liste erlaubter Kommandos, durch Komma getrennt. |
| `dry_run` | No | false | Nur Ausführung planen und fehlende Tools melden. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run live_response --case demo_case --param commands='uname -a,ps -ef' --dry-run
```

**Ausführung**
```bash
forensic-cli modules run live_response --case demo_case --param commands='uname -a,netstat -tulpen'
```

## Ausgaben & Provenienz
- Textartefakte (*.out/*.err) pro Kommando unter cases/<case>/acq/live_response/.
- `live_response.meta.json` mit Hashwerten pro Ausgabe.

**Chain of Custody:** Jede Kommandoausführung wird in meta/provenance.jsonl plus Chain-of-Custody eingetragen.

## Guard-Fehlermeldungen
- `Unsupported command(s) requested` wenn nicht erlaubte Befehle angegeben.
- Guard-Meldung `Required tooling missing` bei fehlenden Utilities (Status `partial`).

## Verwandte Dokumentation
- [Acquisition](../MODULES/acquisition.md)
- [User Guide](../guides/user-guide.md)

<!-- AUTODOC:END -->
