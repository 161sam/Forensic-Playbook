# Forensic-Playbook – Project Status (January 2025)

## Overview

Das Repository stellt nun eine vollständig gehärtete, deterministische
Forensik-Plattform bereit. Core Features (Case Management, Evidence Handling,
Chain of Custody) bleiben stabil, während Konfiguration, Utilities und alle
Module auf Guarded-Status mit Dry-Run-Pfaden, Provenienz und MCP/Codex-Brücke
gebracht wurden.

## Component summary

| Component | State | Notes |
| --- | --- | --- |
| Core framework | ✅ Stabil | Framework initialisiert Fälle, verwaltet Evidence und Chain-of-Custody deterministisch |
| Configuration loader | ✅ Stabil | `forensic/core/config.py` setzt CLI > YAML > Defaults konsequent um |
| Utilities | ✅ Stabil | `forensic/utils/` bündelt Pfad-, IO- und Hashing-Helfer für deterministische Läufe |
| Acquisition | ✅ Guarded | Disk-, Memory-, Network- und Live-Response-Module mit Dry-Run-Preview & Provenienz-Logging |
| Analysis | ✅ Guarded | Filesystem/Memory/Network/Timeline/Malware liefern deterministische JSON/CSV und skippen fehlende Extras |
| Triage | ✅ Einsatzbereit | Quick Triage, System Info & Persistence decken Guards + Konfigurations-Defaults ab |
| Reporting | ✅ Komplett | HTML immer, PDF optional via Guard-Fallback; CoC & Hashes werden protokolliert |
| CLI | ✅ Stabil | Diagnostics, modules, report, codex/mcp Subcommands inkl. JSON-Ausgabe & Guard-Status |
| Codex / MCP | ✅ Stabil | `forensic-cli codex …` & `mcp …` spiegeln Forensic Mode Prompts und liefern deterministische Kataloge |
| SDK | ✅ Stabil | `forensic/__init__.py` exportiert CLI/Framework-Wrapper für Automatisierung |
| Tests | ✅ Grün | Pytest + Coverage ≥ 70 %, E2E-Minimalflow, Layout- & Matrix-Checks in CI |
| Tooling | ✅ Grün | `tools/generate_module_matrix.py`, Layout-Validator & Artefakt-Uploads laufen deterministisch |

## Recent changes

* Packaging konsolidiert via `pyproject.toml` mit Extras und Entry Point
  `forensic-cli`.
* CI-Pipeline liefert Linting, Tests, Coverage ≥ 70 % sowie HTML/PDF-Artefakte
  und Modulmatrix.
* CLI bietet Diagnostics, Module, Reports plus Codex/MCP Subcommands mit
  Dry-Run-Preview und JSON-Ausgabe.
* Guarded MCP-Adapter (`forensic/mcp/`) und Codex-Runner (`forensic/ops/codex.py`)
  spiegeln den Forensic-Mode-Prompt wider.
* Reporting-Generator unterstützt HTML, Markdown, JSON und optional PDF mit
  Guard-Fallback.
* Modulmatrix-Generator und Layout-Validator sichern Dokumentation & Status-
  Tabellen ab.
* Chain-of-Custody- und Provenienz-Logging deckt sämtliche Module ab und vermeidet
  Duplikate.

## Open work

* Neue Tool-Backends evaluieren und nach Freigabe in Guard-Listen ergänzen.
* Optional extras (Volatility, Plaso, YARA) regelmäßig auf Updates testen und
  Guard-Meldungen anpassen.
* Weitere MCP-Tools und Automations-Playbooks erstellen (Plan → Confirm →
  Execute bleibt Pflicht).
* Internationale Lokalisierung der Report-Templates vorbereiten.
* Beobachtungspunkte für künftige Router-/Network-Hardening-Maßnahmen sammeln.

