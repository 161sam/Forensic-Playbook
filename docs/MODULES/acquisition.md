<!-- AUTODOC:BEGIN -->
---
title: "Acquisition Modules"
description: "Guarded Datenerfassung für Laufwerke, Speicher und Netzwerk."
---

# Übersicht

Acquisition-Module sorgen für sichere Beweiserhebung mit Root-Schutz, Dry-Run-Planung und Chain-of-Custody-Protokollierung. Alle Befehle folgen dem Grundsatz **dry-run zuerst** und verweisen auf logische Speicherorte im Case-Verzeichnis.

## Modulübersicht
| Modul | Guard | Backends | Anforderungen |
| --- | --- | --- | --- |
| [Disk Imaging](../modules/disk_imaging.md) | Hard | dd / ddrescue / ewfacquire | Root, ddrescue, ewfacquire |
| [Live Response](../modules/live_response.md) | Medium | Allowlisted POSIX-Kommandos | uname, ps, netstat, systemctl |
| [Memory Dump](../modules/memory_dump.md) | Hard | AVML (Linux) | avml, --enable-live-capture |
| [Network Capture](../modules/network_capture.md) | Hard | dumpcap / tcpdump | Root, dumpcap oder tcpdump |

## Betriebsnotizen
- Für jede Live-Aktion ist ein dokumentierter Dry-Run erforderlich.
- Konfigurationen liegen unter `config/modules/acquisition/*.yaml` und können pro Case überschrieben werden.
- Router-spezifische Akquisition wird in [Router Suite](router-suite.md) beschrieben.

## Weiterführende Ressourcen
- [01 Quick Triage Linux](../tutorials/01_quick-triage-linux.md)
- [04 Router Forensics End2End](../tutorials/04_router_forensics_end2end.md)

<!-- AUTODOC:END -->
