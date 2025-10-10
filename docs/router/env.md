<!-- AUTODOC:BEGIN -->
---
title: "Router Environment Preparation"
description: "Initialisiert einen isolierten Arbeitsbereich für Router-Untersuchungen."
---

# Überblick

Der Befehl `forensic-cli router env init` legt ein deterministisches Verzeichnislayout an, kopiert Template-Konfigurationen und
setzt Guard-Logs auf. Standardmäßig wird nur ein Dry-Run durchgeführt, damit keine Dateien erstellt werden, bevor Analysten den
Plan bestätigen.

## Parameter
| Option | Pflicht | Standard | Beschreibung |
| --- | --- | --- | --- |
| `--root` | Ja | — | Basisverzeichnis für Router-Fälle (z. B. `~/cases/router_demo`). |
| `--profile` | Nein | `default` | Profil aus `config/modules/router/env.yaml`, definiert Ordnerstruktur & Logpfade. |
| `--dry-run` | Nein | `true` | Planung ohne Dateisystemänderung. Muss deaktiviert werden, bevor Verzeichnisse angelegt werden. |

## Ausgaben
- `<root>/manifest/`, `<root>/captures/`, `<root>/logs/` (nur nach deaktiviertem Dry-Run).
- `router_env_plan.json` mit Zeitstempel, Hashes und geplanten Pfaden im Dry-Run.

## Betriebsnotizen
- Schreibt Chain-of-Custody-Einträge nur, wenn `--dry-run` deaktiviert ist.
- Konfigurationspräzedenz: CLI > `config/modules/router/env.yaml` > Defaults.
- Logs liegen unter `<root>/logs/router_env-<timestamp>.log` sowie im aktiven Case (`cases/<case>/logs/router/`).
<!-- AUTODOC:END -->
