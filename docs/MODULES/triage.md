<!-- AUTODOC:BEGIN -->
---
title: "Triage Modules"
description: "Schneller Überblick über Systemzustand und Persistenz."
---

# Übersicht

Triage-Module sind für Ersthelfer gedacht und liefern deterministische Snapshots ohne Schreibzugriffe.

## Modulübersicht
| Modul | Guard | Backends | Anforderungen |
| --- | --- | --- | --- |
| [Quick Triage](../modules/quick_triage.md) | Soft | Profiles default / minimal / extended | coreutils, ps, ss |
| [System Info](../modules/system_info.md) | Soft | Python platform APIs | lsb_release (optional) |
| [Persistence](../modules/persistence.md) | Soft | Filesystem-Scans | Leserechte auf Systempfade |

## Betriebsnotizen
- Ergebnisse landen unter `cases/<case>/triage/` und enthalten Hashes je Artefakt.
- Dry-Run zeigt geplante Pfade und verhindert versehentliche Dateizugriffe.
- Empfohlen als Vorbereitung vor tiefgehenden Acquisition-Schritten.

## Weiterführende Ressourcen
- [01 Quick Triage Linux](../tutorials/01_quick-triage-linux.md)
- [Minimal E2E](../examples/minimal-e2e.md)

<!-- AUTODOC:END -->
