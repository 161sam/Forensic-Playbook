<!-- AUTODOC:BEGIN -->
---
title: "Forensic-Playbook Developer Guide"
description: "Engineering handbook for architecture, module development, CI, and MCP integration."
---

# Einleitung

Dieser Developer Guide liefert einen tiefen Einblick in Architektur, Coding-Standards und Betriebsprozesse des Forensic-Playbook Frameworks. Alle Anweisungen folgen dem Forensic-Mode-Mandat: deterministische Abläufe, Guarded-Ausführung, Dry-Run-Validierung und vollständige Provenienz.

## Architekturüberblick

```
┌───────────────────────────┐
│ forensic.core.framework   │  Core orchestriert Cases, Evidence, Provenienz
└────────────┬──────────────┘
             │
┌────────────▼──────────────┐
│ Module Registry           │  Registriert Guarded Module (Acquisition, Analysis, Triage, Reporting, Router)
└───────┬───────────┬───────┘
        │           │
  Tool Wrappers  CLI Layer    SDK / MCP
        │           │               │
┌───────▼───────┐ ┌─▼────────┐ ┌────▼───────────┐
│ subprocess /  │ │ forensic-│ │ Model Context  │
│ python libs   │ │ cli       │ │ Protocol (MCP) │
└───────────────┘ └──────────┘ └────────────────┘
```

- **Core** (`forensic/core/`): Case-Verwaltung, Evidence-Metadaten, Chain-of-Custody (`meta/`), Provenienz-Logger.
- **Module Layer** (`forensic/modules/`): Basisklassen mit Guard-Checks, Parametervalidierung, deterministischen Outputs.
- **Tools & Wrappers** (`forensic/tools/`, `router/`): sichere subprocess-Aufrufe, abstrahierte Third-Party-CLI-Befehle.
- **CLI** (`forensic/cli/`): Click-basierte Befehle, Dry-Run-Default, Logging-Kontext.
- **MCP-Adapter** (`forensic/mcp/`): Stellt CLI/SKD-Funktionen als Werkzeuge für Codex bereit.

Weitere Kontextdiagramme liefert [ARCHITECTURE.md](ARCHITECTURE.md); die physische Struktur ist in [Projektstruktur-v2.0.md](../Projektstruktur-v2.0.md) dokumentiert.

## Guarded-Standard

1. **Tool Detection** – `forensic.tools.checks` liefert `GuardResult`. Module beenden sich sauber mit Hinweis.
2. **Dry-Run Pflichtpfad** – Jede Aktion implementiert `if dry_run: return plan`. Keine Dateischreiboperation außerhalb des Guard-Kontexts.
3. **Deterministische Ausgaben** – Dateinamen mit Zeitstempeln (`YYYYMMDDTHHMMSSZ`), Hashes (`sha256`) im Provenienzlog.
4. **Subprocess-Sandbox** – Nutzung von `run_guarded_command(cmd, allow_write=False)`. Schreibende Aktionen setzen `allow_write=True` erst nach Bestätigung.
5. **Logging** – Module loggen nach `logs/modules/<module>-<timestamp>.log`.

## Projektstruktur v2.0

Die aktuelle Struktur ist in [Projektstruktur-v2.0.md](../Projektstruktur-v2.0.md) erläutert. Kernelemente:

- `forensic/core/` – Framework-Objekte (Framework, Case, Evidence, ProvenanceWriter)
- `forensic/modules/<category>/` – Modul-Pakete mit `__init__.py`, `schemas.py`, `runner.py`
- `config/` – YAML-Defaults (`framework.yaml`, `modules/*.yaml`, Router-Profile)
- `docs/` – Dieser Doc-Hub (Marker beachten!)
- `tests/` – Pytest-Module nach Kategorien (`test_core`, `test_modules_acquisition` ...)
- `tools/` – Hilfs-Skripte (z. B. Layout-Validator)

> **Hinweis:** Die Datei `Projektstruktur-v2.0.md` dient als Referenz. Bei Änderungen immer beide Quellen synchron halten.

## Modulentwicklung

1. **Basisklasse wählen** – `BaseGuardedModule` aus `forensic.modules.base`.
2. **Schema definieren** – Pydantic-Modelle für Parameter/Outputs (`schemas.py`).
3. **Guard-Checks implementieren** – `ensure_tools_available`, `require_root`, `assert_flag_enabled`.
4. **Konfiguration binden** – Defaults liegen in `config/modules/<module>.yaml`. CLI-Parameter werden über `forensic.cli.params` injiziert.
5. **Ausgabeordner** – Verwenden Sie `case.get_module_output_dir(self.name)` und speichern Sie Metadaten (`module.json`, `hashes.json`).
6. **Provenienz** – `framework.provenance.record_run(...)` mit Parametern, Hashes, Artefakten.
7. **Tests** – Pytest-Fälle unter `tests/modules/<module>/test_<feature>.py` mit Fixtures für Synth-Daten.

```python
from forensic.modules.base import BaseGuardedModule
from forensic.tools.checks import require_tools

class ExampleModule(BaseGuardedModule):
    name = "example"
    guard_level = "medium"

    def guard(self, params):
        require_tools(["sleuthkit"])  # Raises GuardError bei Fehlen

    def run(self, params, case, dry_run: bool = False):
        target = case.get_module_output_dir(self.name)
        if dry_run:
            return {"planned_output": str(target / "result.json")}
        # echte Ausführung ...
        self.write_json(target / "result.json", {"status": "ok"})
        return {"artefacts": [target / "result.json"]}
```

## Router-Module

- Python-Pendants zu `router/scripts/` liegen unter `forensic/modules/acquisition/router_*`.
- Mapping-Strategie: CLI-Flags spiegeln Legacy-Argumente (`--if`, `--bpf`, `--duration`).
- Tests: `tests/modules/router/` nutzt synthetische Tar-/JSON-Fallbacks, keine Live-Netzwerkzugriffe.
- Extra-Guards: Router-Kommandos verlangen `--dry-run`, sofern nicht `--ack-live` gesetzt ist.
- Logging: Router-spezifische Logs unter `cases/<case>/logs/router/` plus `router/logs/` für Framework-weite Aktionen.

## Testing & CI

- **Pytest** – `pytest -q` prüft Unit- und Integrationstests. Neue Module benötigen Smoke- und Guard-Tests.
- **Coverage-Gate** – Mindestens 65 % (`pytest --cov=forensic --cov-report=term`).
- **CI-Workflow** – GitHub Actions (`.github/workflows/ci.yml`): lint (`ruff`, `black --check`), tests, optional docs-check.
- **E2E ohne Root/Netz** – Use `tests/e2e/` mit synthetischen Fixtures. Keine Netzwerkeingriffe, stattdessen JSON-Fallbacks.
- **Optional** – `tox -e lint,tests` zur lokalen Reproduktion.

## Dokumentation pflegen

- Alle Markdown-Dateien im `docs/`-Baum enthalten `<!-- AUTODOC:BEGIN/END -->`. Änderungen nur innerhalb dieser Marker.
- Generierte Inhalte (CLI-Hilfen, Modulmatrizen) über Skripte aktualisieren und Commit dokumentieren.
- Reporting über `REPORT.md` synchronisieren (bekannte Lücken, MIGRATION status).
- `_sidebar.md` aktuell halten, falls neue Seiten entstehen.

## Release-Flow

1. `CHANGELOG.md` aktualisieren (Keep a Changelog).
2. Versionsnummer in `pyproject.toml` / `forensic/__init__.py` anheben.
3. `pytest -q` + `forensic-cli diagnostics --summary --dry-run` als Release-Gate.
4. Tag erstellen (`git tag vX.Y.Z`), signieren und pushen.
5. Statusseiten aktualisieren (`PROJECT_STATUS.md`, `REPORT.md`).

> **Hotfixes:** Patch-Branches mit gezielten Commits, Backport-Tests dokumentieren.

## MCP & Codex Integration

- **Expose**: `forensic-cli mcp expose` generiert deterministische Tool-Listen (JSON).
- **Status**: `forensic-cli codex status` prüft Dienst + Port, Logs unter `<workspace>/codex_logs/`.
- **Run**: `forensic-cli mcp run --tool diagnostics.ping --local` für lokale Tools.
- **System Prompt**: `forensic/mcp/prompts/forensic_mode.txt` – beim Ändern stets mit Doku (`docs/mcp/forensic-mode.md`) abstimmen.
- **Tool-Mapping**: Jedes CLI-Modul sollte ein MCP-Äquivalent besitzen (`forensic/mcp/tools/<category>.py`).

## Contribution Guide

- **Code Style** – `ruff check .`, `black`, `isort` (Konfiguration in `pyproject.toml`).
- **Commits** – Conventional Commits (`feat:`, `fix:`, `docs:` …). Branch-Präfixe `feature/`, `bugfix/`, `docs/`.
- **PR-Checkliste**
  - [ ] Dry-Run & Guard-Tests dokumentiert
  - [ ] Provenienz- und Chain-of-Custody-Ausgaben geprüft
  - [ ] Doku aktualisiert (`docs/`, `REPORT.md`, `CHANGELOG.md`)
  - [ ] Tests & Lint grün (`pytest -q`, `ruff check .`, `black --check .`)
  - [ ] MCP-Expose erneut verifiziert (falls Tools betroffen)
- **Review-Kriterien** – deterministische Ergebnisse, nachvollziehbare Artefaktpfade, keine unnötigen Abhängigkeiten.

Weitere Detailfragen beantwortet der [Module Catalogue](MODULES/acquisition.md) sowie die [MCP-Dokumentation](mcp/codex-workflow.md).
<!-- AUTODOC:END -->
