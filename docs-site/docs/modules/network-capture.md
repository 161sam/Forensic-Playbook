<!-- AUTODOC:BEGIN -->
---
title: "Network Capture Module"
description: "Plant und führt Live-PCAP-Aufnahmen mit dumpcap oder tcpdump aus."
---

# Zusammenfassung

- **Kategorie:** Acquisition
- **CLI-Name:** `network_capture`
- **Guard-Level:** Hard — Root & --enable-live-capture erforderlich; Dry-Run standardmäßig verfügbar.
- **Unterstützte Evidenz:** network
- **Backends/Extras:** dumpcap (default), tcpdump
- **Abhängigkeiten:** dumpcap oder tcpdump
- **Optionale Extras:** pcap extra (für spätere Analyse)

## Parameterreferenz
| Parameter | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `interface` | No | auto (config/) | Netzwerkschnittstelle für Capture. |
| `duration` | No | 300 | Aufnahmezeit in Sekunden. |
| `bpf` | No | not port 22 | Berkeley Packet Filter. |
| `count` | No | — | Optionales Paketlimit. |
| `tool` | No | dumpcap | Backend für Aufnahme. |
| `enable_live_capture` | Yes | false | Bestätigung für Echtbetrieb. |
| `dry_run` | No | false | Nur Planung ohne Capture. |

> **Konfigurations-Hinweis:** CLI-Werte überschreiben YAML (`config/modules/`), die wiederum die eingebauten Defaults überstimmen.

## CLI-Beispiele
**Dry-Run**
```bash
forensic-cli modules run network_capture --case demo_case --param interface=eth0 --param duration=120 --dry-run
```

**Ausführung**
```bash
sudo forensic-cli modules run network_capture --case demo_case --param interface=eth0 --param duration=120 --enable-live-capture
```

## Ausgaben & Provenienz
- PCAP-Datei unter cases/<case>/acq/pcap/.
- `.json`-Manifest mit Parametern & Hashes.
- Chain-of-Custody-Logeinträge inklusive Parameterquellen.

**Chain of Custody:** Parameterquellen (CLI/YAML/Defaults) werden im Provenienz-Record gespeichert.

## Guard-Fehlermeldungen
- `Live capture disabled` wenn enable_live_capture false.
- Guard-Ergebnis bei fehlendem dumpcap/tcpdump (Status `skipped`).
- Ungültige Dauer -> Guard Fehler `duration`.

## Verwandte Dokumentation
- [Acquisition](../MODULES/acquisition.md)
- [Network](network.md)

<!-- AUTODOC:END -->
