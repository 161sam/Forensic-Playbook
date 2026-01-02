<!-- AUTODOC:BEGIN -->
---
title: "CLI Reference"
description: "Reference for forensic-cli commands, parameters, exit codes, and guard behaviour."
---

# Überblick

`forensic-cli` ist der Guarded-Einstiegspunkt für alle Framework-Funktionen. Jeder Aufruf respektiert die Forensic-Mode-Regeln: Dry-Run zuerst, Logs im Workspace, vollständige Provenienz. Aktivieren Sie `--json`, wenn strukturierte Ausgaben benötigt werden.

## Globale Optionen

```text
Usage: forensic-cli [OPTIONS] COMMAND [ARGS]...

  Forensic Framework CLI.

Options:
  --workspace PATH        Workspace directory (default: ./forensic_workspace)
  --config PATH           Optional override for framework config YAML.
  -v, --verbose           Increase verbosity (stack traces bei Fehlern).
  --json                  Emit JSON status objects.
  --quiet                 Suppress human-readable output.
  --legacy / --no-legacy  Enable wrappers for deprecated shell scripts.
  --help                  Show this message and exit.
```

- Logs landen deterministisch in `<workspace>/logs/forensic_<timestamp>.log`.
- Provenienz wird in `cases/<case>/meta/provenance.jsonl` ergänzt.

## Parameter-Konventionen

| Option | Bedeutung | Beispiel |
| --- | --- | --- |
| `--param key=value` | Übergibt modul- oder router-spezifische Parameter. Mehrfach nutzbar. | `--param pcap_json=cases/demo_case/input/flows.json` |
| `--dry-run` | Plant Aktionen ohne Artefakte zu schreiben. Pflichtschritt für sensible Module. | `forensic-cli modules run disk_imaging --dry-run` |
| `--json` | Strukturierte Ausgabe für Automationspipelines. | `forensic-cli modules run network --json --dry-run` |
| Exitcodes | `0` = Erfolg/Guard-Warnung, `1` = Fehler (z. B. Guard verweigert Ausführung). | Guard-Fehler -> Exitcode `0`, Feld `status="warning"`. |
| Output-Pfade | Werden im Resultat (`output_path`, `metadata.artifacts`) und im Provenienz-Log dokumentiert. | `cases/demo_case/analysis/network/network.json` |

## Case Management

```bash
# Case anlegen
forensic-cli --workspace ~/cases case create \
    --name demo_case \
    --description "Router + Timeline Investigation"

# Übersicht vorhandener Cases
a. forensic-cli --workspace ~/cases case list
b. forensic-cli --workspace ~/cases case load --name demo_case --json
```

Alle Case-Befehle sind read-only, außer `create`. Der Workspace wird im Logfile notiert.

## Diagnostics & Guard-Checks

```bash
# Gesamtstatus
forensic-cli --workspace ~/cases diagnostics --summary --dry-run

# Kategorie-spezifischer Guard-Report
forensic-cli --workspace ~/cases diagnostics --modules analysis --json
```

Die Ausgabe listet fehlende Tools, optionale Extras und Guard-Levels. Warnings erzeugen Exitcode `0` (mit `status="warning"`).

## Module ausführen

```bash
# Modulverfügbarkeit
forensic-cli --workspace ~/cases modules list --json

# Dry-Run mit Parametern
forensic-cli --workspace ~/cases modules run network \
    --case demo_case \
    --param pcap_json=cases/demo_case/input/flows.json \
    --dry-run \
    --json

# Live-Lauf (nach Freigabe)
forensic-cli --workspace ~/cases modules run timeline \
    --case demo_case \
    --param source=cases/demo_case/analysis/network \
    --param format=csv
```

- Statusmapping: `success|partial|skipped` → Exitcode `0`, `error` → Exitcode `1`.
- Artefakte werden unter `metadata.artifacts` sowie `output_path` ausgewiesen.
- Parameterquellen (`cli`, `case_config`, `default`) werden im Provenienz-Log vermerkt.

## Reporting

```bash
# HTML-Report planen
forensic-cli --workspace ~/cases report generate \
    --case demo_case \
    --fmt html \
    --out cases/demo_case/reports/demo_case.html \
    --dry-run

# PDF nur mit Extras
forensic-cli --workspace ~/cases report generate \
    --case demo_case \
    --fmt pdf \
    --out cases/demo_case/reports/demo_case.pdf \
    --dry-run
```

Fehlende Renderer führen zu `status="warning"`, Exitcode `0`, inklusive Hinweis im `metadata.errors` Feld.

## Router-Gruppe

```bash
# Umgebung vorbereiten
a. forensic-cli router env init --workspace ~/cases --case demo_case --profile default --dry-run

# Artefakte extrahieren
forensic-cli router extract ui \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/raw_ui \
    --dry-run

# Manifest & Zusammenfassung
forensic-cli router manifest write \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/extract \
    --dry-run
forensic-cli router summarize \
    --workspace ~/cases \
    --case demo_case \
    --param source=cases/demo_case/router/extract \
    --json

# Pipeline-Run (führt env→capture→extract→summarize sequentiell aus)
forensic-cli router pipeline run --workspace ~/cases --case demo_case --dry-run
```

Alle Router-Kommandos protokollieren Ergebnisse nach `cases/<case>/logs/router/` und respektieren `config/modules/router/*.yaml`.

## Codex-Steuerung

```bash
# Installation und Dienststart (Dry-Run Pflicht)
forensic-cli --workspace ~/cases codex install --dry-run
forensic-cli --workspace ~/cases codex install --accept-risk
forensic-cli --workspace ~/cases codex start --foreground --dry-run
forensic-cli --workspace ~/cases codex start --foreground

# Status / Logs
forensic-cli --workspace ~/cases codex status --json
forensic-cli --workspace ~/cases codex status --verbose
```

Logs werden unter `<workspace>/codex_logs/` abgelegt. `status` liefert sowohl Exitcode `0` als auch strukturierte Feldinformationen (`service`, `pid`, `port`). Weitere Schritte siehe [mcp/codex-workflow.md](../mcp/codex-workflow.md).

## MCP-Werkzeuge

```bash
# Tool-Katalog exportieren
forensic-cli --workspace ~/cases mcp expose --json \
    > ~/cases/demo_case/tooling/mcp_catalog.json

# Health-Checks
forensic-cli --workspace ~/cases mcp status --json

# Tool lokal ausführen
forensic-cli --workspace ~/cases mcp run diagnostics.ping \
    --local \
    --json \
    --dry-run
```

- `mcp run` gibt `status`, `logs`, `artifacts` zurück. Exitcode folgt dem Tool-Status (`success/warning` → `0`, `error` → `1`).
- Verwenden Sie `--plan` oder `--dry-run`, um Guard-Anforderungen zu erfüllen, bevor Live-Schritte freigegeben werden.

## Weitere Ressourcen

- [User Guide](../guides/user-guide.md) – Standard-Workflows, Troubleshooting.
- [Module-Katalog](../modules/analysis.md) – Parameterlisten und JSON-Schemata pro Kategorie.
- [Forensic Mode Guardrails](../mcp/forensic-mode.md) – Plan → Confirm → Execute für MCP/Codex.

Alle Beispiele verzichten bewusst auf Binär-Fixtures und verwenden deterministische Pfade. Ergänzen Sie Dry-Run-Protokolle in der Fallakte, bevor Sie Live-Läufe starten.
<!-- AUTODOC:END -->
