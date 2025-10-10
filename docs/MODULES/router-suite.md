<!-- AUTODOC:BEGIN -->
---
title: "Router Suite"
description: "CLI-Gruppe `forensic-cli router` für Router-spezifische Workflows."
---

# Übersicht

Die Router-Suite kapselt Capture, Extraktion, Manifest- und Zusammenfassungsaufgaben. Jeder Befehl respektiert Dry-Run und die Konfigurations-Präzedenz CLI > YAML > Defaults.

## Modulübersicht
| Modul | Guard | Backends | Anforderungen |
| --- | --- | --- | --- |
| [Router Environment](../router/env.md) | Guarded Setup | config/modules/router/env.yaml | Initialisiert Arbeitsverzeichnis |
| [Router Capture](../router/capture.md) | Hard | tcpdump/dumpcap (remote/SSH) | Root, Netzwerkzugriff |
| [Router Extract](../router/extract.md) | Medium | Python Archiv-Parser | Leserechte auf Router-Dumps |
| [Router Manifest](../router/manifest.md) | Medium | Hashing & Inventarisierung | python hashlib |
| [Router Pipeline](../router/pipeline.md) | Medium | YAML-Workflows | config/router/pipeline.yaml |
| [Router Summarize](../router/summarize.md) | Soft | Jinja2 Markdown-Templates | jinja2 |

## Betriebsnotizen
- Dry-Run-Modus ist verpflichtend bevor Live-Captures erlaubt werden.
- Legacy-Bash-Skripte lassen sich mit `--legacy` aufrufen, bleiben aber standardmäßig deaktiviert.
- Router-Logs landen unter `<workspace>/router/logs/` zusätzlich zu `cases/<case>/logs/router/`.

## Weiterführende Ressourcen
- [04 Router Forensics End2End](../tutorials/04_router_forensics_end2end.md)
- [Capture](../router/capture.md)

<!-- AUTODOC:END -->
