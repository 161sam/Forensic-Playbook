<!-- AUTODOC:BEGIN -->
---
title: "Forensic-Playbook Developer Guide"
description: "Engineering handbook covering architecture, coding standards, testing, and release flow."
---

# Einleitung

Dieser Guide richtet sich an Maintainerinnen und Beitragende. Er bündelt Architekturhinweise, Coding-Standards und Release-Prozesse. **Forensic Mode** bleibt der rote Faden: Dry-Run-first, Guard-Prüfungen und vollständige Chain-of-Custody-Protokolle.

## Architektur & Verantwortlichkeiten

- **Kernarchitektur:** Die komplette Komponentenübersicht ist in [ARCHITECTURE.md](ARCHITECTURE.md) dokumentiert; ergänzend beschreibt [Projektstruktur-v2.0.md](../Projektstruktur-v2.0.md) die Verzeichnisstruktur.
- **Core (`forensic/core/`):** Framework, Case-Objekte, Provenienz-Writer (`meta/provenance.jsonl`), Chain-of-Custody (`meta/chain_of_custody.jsonl`).
- **Module (`forensic/modules/`):** Kategoriepakete (Acquisition, Analysis, Triage, Reporting, Router) mit Guarded-Basisklassen. Die Referenzseiten stehen unter [docs/MODULES/](MODULES/analysis.md).
- **Tools (`forensic/tools/`):** Deterministische Wrapper für externe Binaries (Sleuthkit, Volatility). Logging- und Guard-Vorgaben siehe [forensic/tools/AGENTS.md](../forensic/tools/AGENTS.md).
- **CLI/MCP:** Click-Kommandos in `forensic/cli/`, MCP-Adapter in `forensic/mcp/`. Prompt-Richtlinien: [mcp/forensic-mode.md](mcp/forensic-mode.md).

## Modul-Skelett & Guards

```python
from pathlib import Path
from forensic.modules.base import BaseGuardedModule
from forensic.core.provenance import Artifact

class ExampleModule(BaseGuardedModule):
    name = "example"
    guard_level = "medium"

    def guard(self, params: dict) -> None:
        self.require_tools(["sleuthkit"])
        self.require_case()

    def run(self, params: dict, *, dry_run: bool = False):
        output_dir = self.case.get_module_output_dir(self.name)
        target = output_dir / "result.json"
        if dry_run:
            return self.plan(
                description="Preview example module",
                outputs=[target],
                logs=[self.log_path],
            )
        payload = {"status": "ok"}
        self.write_json(target, payload)
        return self.success(
            artifacts=[Artifact(path=target, kind="json")],
            metadata={"planned_output": str(target)},
        )
```

- **Guards:** Verwenden Sie `require_tools`, `require_root`, `ensure_flag_enabled` und `validate_paths_within_workspace`. Fehlende Voraussetzungen -> `status="skipped"`.
- **Provenienz:** `self.provenance.record_run(...)` wird automatisch durch `success()/plan()` ausgelöst und protokolliert Parameterquellen, Hashes und Artefaktpfade.
- **JSON-Schemas:** Kurze Parameter- und Output-Schemata pro Modul finden Sie in [MODULES/*](MODULES/analysis.md); neue Felder müssen dort dokumentiert werden.

## Coding-Standards

- **Typisierung:** Vollständige Typ-Hints (PEP 484). Verwenden Sie `typing.Protocol`/`TypedDict`, wenn Strukturen mehrfach genutzt werden.
- **Logging:** Nutzen Sie `structlog`/`logging` über `self.logger` oder `forensic.core.logging.get_logger`. Pfade und Hashes explizit erwähnen.
- **Determinismus:** Keine zufälligen Seeds ohne Fixierung (`random.seed`, `uuid.uuid4()` → `uuid.uuid5`). Zeitstempel über `datetime.now(tz=UTC)` oder `framework.clock` abstrahieren.
- **Subprocess:** Nur via `forensic.tools.runner.run_guarded_command` oder spezifische Wrapper aufrufen. Immer Command-Line, Exitcode und Logdatei dokumentieren.
- **Style-Tools:** `ruff check .`, `black`, `isort` (Konfiguration siehe `pyproject.toml`). Imports nicht in `try/except` kapseln.

## Tests & Coverage

- **Unit-Tests:** Pytest unter `tests/` (z. B. `tests/modules/analysis/test_network.py`). Verwenden Sie Fixtures für Synth-Daten; keine Binär-Fixtures einchecken.
- **Mocks:** `pytest-mock`/`unittest.mock` für subprocess und Zeitquellen. Dry-Run-Pfade werden mit `tmp_path` simuliert.
- **Integration/E2E:** Leichtgewichtige Pipelines (siehe [docs/examples/minimal-e2e.md](examples/minimal-e2e.md)) stellen sicher, dass CLI, Module und Reports zusammenspielen.
- **Coverage-Gate:** Mindestwert 70 % (`pytest --cov=forensic --cov-report=term`). Schlägt das Gate fehl, Tests erweitern oder Toleranzen begründen.
- **CI:** GitHub Actions Workflow `ci.yml` führt Linting, Tests und (optional) Docs-Build durch. Vor Merge lokal `tox -e lint,tests` oder `make check` ausführen.

## Release-Flow

1. **Versionierung:** Semantic Versioning (`major.minor.patch`). Version in `pyproject.toml` und `forensic/__init__.py` synchronisieren.
2. **Changelog:** [CHANGELOG.md](../CHANGELOG.md) nach *Keep a Changelog* pflegen, inkl. Guard-/Provenienz-Highlights.
3. **Tests & Diagnostics:** `pytest -q`, `forensic-cli diagnostics --summary --dry-run`, ggf. `forensic-cli mcp expose --json` archivieren.
4. **Tags & Artefakte:** Signierten Git-Tag (`git tag -s vX.Y.Z`) erstellen, Release-Artefakte (Docs, MCP-Katalog, Beispiel-Logs) im Release-Ordner `dist/` oder GitHub Assets ablegen.
5. **Kommunikation:** `PROJECT_STATUS.md`, `REPORT.md` und `SESSION_SUMMARY.md` aktualisieren. Chain-of-Custody-Ereignisse im Ticket-System verlinken.

## Weiterführende Ressourcen

- [CLI-Referenz](api/CLI.md) – Parameternamen, Exitcodes, JSON-Ausgaben.
- [MCP-Dokumentation](mcp/codex-workflow.md) – Plan → Confirm → Execute für Codex.
- [Module-Katalog](MODULES/analysis.md) – Parameter, Inputs/Outputs und Guards pro Kategorie.
- [AGENTS.md](../AGENTS.md) – Forensic-Mode-Grundregeln, inklusive Prompt-Beispielen.

Bleiben Sie innerhalb der Guardrails: Dry-Run dokumentieren, Pfade deterministisch halten und Provenienz vollständig erfassen.
<!-- AUTODOC:END -->
