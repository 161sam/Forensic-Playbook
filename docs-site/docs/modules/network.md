<!-- AUTODOC:BEGIN -->
---
title: "Network Analysis Module"
description: "Extrahiert Flows, DNS und HTTP-Metadaten aus PCAP-Dateien mit optionalen Extras."
---

# Zusammenfassung

- **Kategorie:** Analysis
- **CLI-Name:** `network`
- **Guard-Level:** Soft/Medium — arbeitet read-only auf PCAP, meldet fehlende Extras.
- **Unterstützte Evidenz:** pcap captures
- **Backends/Extras:** Builtin Parser, optional scapy & pyshark
- **Abhängigkeiten:** pcap extra (scapy, pyshark) optional
- **Optionale Extras:** pcap

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `source` | Yes | — | PCAP-Datei oder JSON-Fallback. |
| `output` | No | network.json | Zieldatei für Ergebnisse. |
| `timezone` | No | config/timezone oder UTC | Zeitzone für Timestamps. |
| `http_methods` | No | config | Liste beobachteter HTTP-Methoden. |
| `suspicious_user_agents` | No | config | Benutzeragenten für Alerts. |
| `encoded_uri_regex` | No | Base64-Pattern | Regex für kodierte URI-Erkennung. |
| `dry_run` | No | false | Prüft lediglich Eingabe/Extras. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run network --case demo_case --param source=cases/demo_case/acq/pcap/demo.pcap --dry-run
```

**Ausführung**
```bash
forensic-cli modules run network --case demo_case --param source=cases/demo_case/acq/pcap/demo.pcap
```

## Ausgaben & Provenienz
- `network.json` mit Flows, DNS, HTTP-Events.
- Optional separate CSV/Markdown-Reports abhängig von Konfiguration.

**Chain of Custody:** Alle erzeugten Dateien im analysis/network/ werden gehasht und im Provenienzlog referenziert.

## Guard-Fehlermeldungen
- Guard-Meldung bei fehlender Quelle oder nicht lesbaren Dateien.
- Hinweis, wenn pcap-Extras fehlen (Status `success` mit Warnung).

## Verwandte Dokumentation
- [Analysis](../MODULES/analysis.md)
- [02 Network Timeline Walkthrough](../tutorials/02_network-timeline-walkthrough.md)

<!-- AUTODOC:END -->
