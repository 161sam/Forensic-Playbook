<!-- AUTODOC:BEGIN -->
---
title: "Capture Router Evidence"
description: "Plant und führt Packet Captures oder CLI-Dumps auf Router-Geräten aus."
---

# Überblick

`forensic-cli router capture` ersetzt die Legacy-Skripte. Jeder Einsatz beginnt mit `plan`, damit Live-Aufnahmen erst nach
analystischer Freigabe erfolgen. Alle Schritte aktualisieren Provenienz- und Chain-of-Custody-Logs.

## Unterkommandos
| Subcommand | Zweck | Guard |
| --- | --- | --- |
| `plan` | Erstellt Capture-Plan (`capture_plan.json`) ohne Tools zu starten. | Soft |
| `run` | Startet tcpdump/dumpcap lokal oder via SSH, sobald `--enable-live` gesetzt ist. | Hard |
| `legacy` | Zeigt Status der historischen Bash-Skripte oder führt sie bewusst aus. | Medium |

## Häufige Optionen
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--if` | Ja (für `plan`/`run`) | — | Netzwerkschnittstelle oder SSH-Ziel (z. B. `eth1`). |
| `--bpf` | Nein | `not port 22` | BPF-Filter zur Eingrenzung. |
| `--duration` | Nein | `300` | Aufnahmezeit in Sekunden. |
| `--enable-live` | Ja (für `run`) | `false` | Explizite Bestätigung für Live-Capture. Ohne Flag wird abgebrochen. |
| `--dry-run` | Nein | `true` | Simuliert alle Schritte, erzeugt keine PCAPs. |

## Ausgaben
- PCAP-Dateien unter `<root>/captures/<timestamp>/` (nur nach Live-Ausführung).
- `capture_plan.json` mit Parametern, Hashes und Zielpfaden.
- Logs in `<root>/logs/capture-<timestamp>.log` und `cases/<case>/logs/router/`.

## Betriebsnotizen
- Root-Rechte sind für lokale Captures Pflicht. SSH-Captures nutzen Profile aus `config/modules/router/capture.yaml`.
- Fehlende Tools (tcpdump/dumpcap) erzeugen Guard-Warnungen (`status=skipped`) statt Exceptions.
- Dry-Run-Ergebnisse sollten im Case-Dossier abgelegt werden, bevor Live-Traffic erhoben wird.
<!-- AUTODOC:END -->
