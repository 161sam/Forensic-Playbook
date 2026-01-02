<!-- AUTODOC:BEGIN -->
---
title: "Router Evidence Summaries"
description: "Erzeugt Markdown-Reports aus extrahierten Router-Artefakten."
---

# Überblick

`forensic-cli router summarize` kombiniert Manifest, Capture-Metadaten und Konfigurationsdateien zu einem Markdown-Report.
Templates liegen unter `router/templates/` und lassen sich projektspezifisch erweitern.

## Parameter
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--in` | Ja | — | Ordner mit extrahierten Daten und Manifest. |
| `--out` | Ja | — | Ausgabedatei (Markdown). |
| `--template` | Nein | `default.md.j2` | Jinja2-Vorlage für Berichtsinhalte. |
| `--dry-run` | Nein | `true` | Zeigt geplante Abschnitte und Quellen ohne Datei zu schreiben. |

## Ausgaben
- Markdown-Report mit Hash-Referenzen, Timeline und Konfigurationsanhang.
- Optional JSON-Zusammenfassung für SOC- oder Ticket-Import.

## Betriebsnotizen
- Berichte referenzieren Manifest-Einträge und PCAP-Hashes, um Chain-of-Custody sicherzustellen.
- Zusätzliche Abschnitte (z. B. VPN-Konfiguration) lassen sich über Templates aktivieren.
- PDF-Export erfolgt über das Reporting-Modul (`forensic-cli report generate`).
<!-- AUTODOC:END -->
