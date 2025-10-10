<!-- AUTODOC:BEGIN -->
---
title: "Analysis Modules"
description: "Read-only Analysen für Dateisystem, Registry, Netzwerk, Malware und Timeline."
---

# Übersicht

Analysis-Module arbeiten auf vorhandenen Artefakten oder Synth-Fallbacks. Fehlende Tools führen zu Guard-Hinweisen statt Fehlern.

## Modulübersicht
| Modul | Guard | Backends | Anforderungen |
| --- | --- | --- | --- |
| [Filesystem](../modules/filesystem.md) | Medium | Sleuthkit | fls, mmls, icat |
| [Memory](../modules/memory.md) | Medium | Volatility 3 / Volatility 2 | volatility3 oder volatility |
| [Network](../modules/network.md) | Soft | Builtin Parser, scapy, pyshark | pcap-Extra optional |
| [Malware](../modules/malware.md) | Medium | Hashing, YARA (optional) | yara optional |
| [Timeline](../modules/timeline.md) | Medium | plaso/log2timeline, mactime | log2timeline.py, mactime |
| [Registry](../modules/registry.md) | Medium | Interner Parser, RegRipper optional | rip.pl optional |
| [Ioc Scanning](../modules/ioc_scanning.md) | Planning | Geplante IoC-Engine | YARA/Feeds (in Arbeit) |

## Betriebsnotizen
- Alle Module akzeptieren `--dry-run`, um Pfade und Tool-Prüfungen zu protokollieren.
- Optional Extras (`pcap`, `memory`, `yara`) werden in `pyproject.toml` gepflegt und melden sich bei `forensic-cli diagnostics`.
- Timeline-Ausgaben können direkt in Reporting-Module gespeist werden.

## Weiterführende Ressourcen
- [02 Network Timeline Walkthrough](../tutorials/02_network-timeline-walkthrough.md)
- [Ioc Hunting](../examples/ioc-hunting.md)

<!-- AUTODOC:END -->
