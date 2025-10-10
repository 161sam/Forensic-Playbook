<!-- AUTODOC:BEGIN -->
---
title: "CLI Reference"
description: "Snapshot of forensic-cli commands and options."
---

# Überblick

Die Forensic-Playbook-CLI (`forensic-cli`) bietet einen Guarded-Einstieg in alle Framework-Funktionen. Jede Ausführung erstellt
Logdateien im Workspace (`forensic_workspace/logs/`) und schreibt Provenienz-Einträge. Verwenden Sie `--dry-run`, um geplante
Schritte zu validieren, bevor Artefakte geschrieben werden.

## Globale Optionen

```text
Usage: forensic-cli [OPTIONS] COMMAND [ARGS]...

  Forensic Framework CLI.

Options:
  --workspace PATH        Workspace directory
  --config PATH           Config file
  -v, --verbose           Verbose output
  --json                  Emit JSON status objects
  --quiet                 Suppress human-readable output
  --legacy / --no-legacy  Enable wrappers for deprecated shell scripts.
  --help                  Show this message and exit.
```

> Tipp: `--quiet` reduziert die Konsole auf CLI-Ausgaben, Logs werden trotzdem unter `forensic_workspace/logs/forensic_<timestamp>.log` geschrieben.

## Case Management

```text
Usage: forensic-cli case [OPTIONS] COMMAND [ARGS]...

  Case management commands.

Options:
  --help  Show this message and exit.

Commands:
  create  Create a new case.
  init    Scaffold a minimal investigation case for quick demos.
  list    List all cases.
  load    Load an existing case.
```

Guard-Hinweis: Beim Aufruf werden Module automatisch registriert und der aktuelle Workspace protokolliert (`forensic_workspace/logs/...`).

## Module-Befehle

```text
Usage: forensic-cli modules [OPTIONS] COMMAND [ARGS]...

  Module operations.

Options:
  --help  Show this message and exit.

Commands:
  list  List available modules.
  run   Run a module with optional parameters.
```

- `modules list` zeigt Guard-Level, fehlende Tools und Extras.
- `modules run <name> --dry-run` simuliert Ausführung, schreibt aber keine Artefakte.

## Diagnostics

```text
Usage: forensic-cli diagnostics [OPTIONS]

  Display environment diagnostics and guard information.

Options:
  --help  Show this message and exit.
```

Das Kommando validiert Tooling, optionale Extras und meldet Guard-Status für jedes Modul. Logs landen im Workspace.

## Reporting

```text
Usage: forensic-cli report [OPTIONS] COMMAND [ARGS]...

  Reporting commands.

Options:
  --help  Show this message and exit.

Commands:
  generate  Generate a case report using the reporting module.
```

`report generate` akzeptiert Parameter wie `--fmt`, `--out` und `--dry-run`. Fehlt eine PDF-Engine, wird der Lauf als `skipped` markiert und verweist auf den HTML-Report.

## Router-Suite

```text
Usage: forensic-cli router [OPTIONS] COMMAND [ARGS]...

  Router forensic workflow helpers with dry-run safeguards.

Options:
  --help  Show this message and exit.

Commands:
  capture    Passive network capture helpers.
  env        Environment preparation commands.
  extract    Router artifact extraction helpers.
  manifest   Evidence manifest helpers.
  pipeline   Router pipeline orchestration commands.
  summarize  Summarise router analysis findings.
```

Jedes Unterkommando erzwingt einen Dry-Run, bevor Live-Schritte (`capture run`, `env init`) schreibend tätig werden.

## MCP-Adapter

```text
Usage: forensic-cli mcp [OPTIONS] COMMAND [ARGS]...

  Interact with MCP servers and tool adapters.

Options:
  --help  Show this message and exit.

Commands:
  expose  Print the MCP tool catalogue as JSON.
  run     Execute an MCP tool either via HTTP or using the local adapter.
  status  Perform a health check against the configured MCP endpoint.
```

`mcp expose` liefert den Tool-Katalog für Codex. `mcp run` akzeptiert `--tool`, `--local`, `--json` für deterministische Ausgaben.

## Codex-Steuerung

```text
Usage: forensic-cli codex [OPTIONS] COMMAND [ARGS]...

  Guarded helpers for the Codex + MCP workflow.

Options:
  --help  Show this message and exit.

Commands:
  install  Install or update the Codex forensic environment.
  start    Start the guarded MCP server for Codex.
  status   Report the status of the Codex MCP server.
  stop     Stop the Codex MCP server.
```

Alle Kommandos akzeptieren `--dry-run`. Installation und Start protokollieren Logs unter `<workspace>/codex_logs/`.

## Berichts- und Provenienzhinweise

- Jeder CLI-Aufruf erzeugt eine Logdatei unter `forensic_workspace/logs/` mit Zeitstempel.
- Provenienz (`meta/provenance.jsonl`) dokumentiert Parameterquellen (CLI, YAML, Defaults) pro Ausführung.
- Verwenden Sie `--json` für maschinenlesbare Zusammenfassungen in Automationspipelines.

<!-- AUTODOC:END -->
