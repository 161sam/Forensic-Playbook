<!-- AUTODOC:BEGIN -->
---
title: "Router Pipeline Automation"
description: "Führt deklarative Router-Workflows gemäß YAML-Pipelines aus."
---

# Überblick

`forensic-cli router pipeline run` lädt `router/pipeline.yaml` und führt definierte Schritte (Capture → Extract → Manifest →
Summarize) nacheinander aus. Jeder Schritt wird zuerst geplant und benötigt anschließende Freigabe (`--approve`).

## Parameter
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--pipeline` | Nein | `router/pipeline.yaml` | Pfad zur Pipeline-Definition. |
| `--case` | Ja | — | Case-ID zur Aktualisierung der Chain of Custody. |
| `--steps` | Nein | alle | Kommagetrennte Liste (`capture,extract,manifest,summarize`). |
| `--approve` | Nein | `false` | Führe nach erfolgreicher Planung alle Schritte aus. |

## Ausgaben
- `pipeline_plan.json` mit Schrittfolge, Parametern und Guard-Ergebnissen.
- Bei Ausführung: Artefakte wie in den Einzelkommandos beschrieben.

## Betriebsnotizen
- Fehler stoppen die Pipeline deterministisch; Logs enthalten den blockierenden Schritt.
- Einzelne Schritte können erneut ausgeführt werden, indem sie in `--steps` angegeben werden.
- Dry-Run-Ergebnisse sollten gemeinsam mit Case-Notizen archiviert werden.
<!-- AUTODOC:END -->
