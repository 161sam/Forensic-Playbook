<!-- AUTODOC:BEGIN -->
---
title: "Python SDK Reference"
description: "Programmatic usage patterns for the Forensic-Playbook Python SDK."
---

# Überblick

Das Python-SDK stellt dieselben Guarded-Funktionen wie die CLI bereit. Kernstück ist `ForensicFramework` aus `forensic.core.framework`,
welches Fälle verwaltet, Module registriert und Provenienz schreibt. Alle Beispiele nutzen Dry-Run-Strategien und arbeiten innerhalb
eines dedizierten Workspace-Verzeichnisses.

## Grundlegendes Setup

```python
from pathlib import Path
from forensic.core.framework import ForensicFramework
from forensic.modules.triage.quick_triage import QuickTriageModule

workspace = Path("~/cases").expanduser()
framework = ForensicFramework(workspace=workspace)
framework.register_module("quick_triage", QuickTriageModule)
case = framework.ensure_case("sdk_demo", description="SDK quickstart", investigator="Analyst")
```

- `ensure_case` lädt einen bestehenden Fall oder legt ihn deterministisch an.
- Beim Konstruktor erstellt das Framework automatisch `workspace/logs/` und `meta/provenance.jsonl`.

## Dry-Run eines Moduls

```python
plan = framework.execute_module(
    "quick_triage",
    params={"profile": "minimal"},
    dry_run=True,
)
print(plan)
```

- `dry_run=True` verhindert Dateischreibungen und liefert eine Plan-Map (geplante Pfade, benötigte Tools).
- Guard-Fehler lösen `ModuleGuardError` aus und enthalten Hinweise auf fehlende Abhängigkeiten.

## Reguläre Ausführung

```python
result = framework.execute_module(
    "quick_triage",
    params={"profile": "extended"},
    dry_run=False,
)
print(result.status)
print(result.metadata["output_directory"])
```

- Rückgabewerte sind `ModuleResult`-Instanzen (Status, Artefakte, Fehlerliste).
- Alle Artefakte erhalten Hashes, die im Chain-of-Custody-Stream (`case/meta/chain_of_custody.jsonl`) aufgezeichnet werden.

## Parameterauflösung

```python
resolved = framework.resolve_module_parameters(
    "filesystem_analysis",
    overrides={"image": "evidence/disk01.E01"},
)
print(resolved.source)
print(resolved.params)
```

- CLI-Logik (`CLI > YAML > Defaults`) ist wiederverwendbar. `resolved.source` enthält die Herkunft jedes Parameters.

## Reports via SDK

```python
report = framework.generate_report(
    case_id="sdk_demo",
    fmt="html",
    output_path=workspace / "cases" / "sdk_demo" / "reports" / "sdk_demo.html",
    dry_run=True,
)
print(report["planned_output"])
```

- `dry_run=True` verifiziert Templates ohne Dateien zu schreiben.
- Nach Freigabe (`dry_run=False`) werden Artefakte und Hashes im Case-Verzeichnis abgelegt.

## Router-Workflows programmatisch

Die Router-Suite wird derzeit primär über die CLI angesprochen. Für automatisierte Abläufe bietet sich ein kontrollierter
`subprocess.run`-Aufruf an, der wie jedes andere Modul zuerst einen Dry-Run durchführt:

```python
import subprocess
subprocess.run(
    [
        "forensic-cli",
        "router",
        "capture",
        "plan",
        "--root", str(workspace / "router_demo"),
        "--if", "eth1",
        "--bpf", "not port 22",
        "--duration", "180",
        "--dry-run",
    ],
    check=True,
)
```

- Der Plan wird als JSON unter `<root>/manifests/capture_plan.json` abgelegt und kann anschliessend im SDK weiterverarbeitet werden.
- Entfernen Sie `--dry-run` nur nach schriftlicher Freigabe und setzen Sie zusätzlich `--enable-live`.

## MCP-Integration

```python
from forensic.mcp.client import MCPClient
client = MCPClient.from_config(workspace)
status = client.status()
print(status)
```

- `MCPClient` kapselt HTTP- und Local-Adapter-Aufrufe.
- Verwenden Sie `client.run_tool("diagnostics.ping", local=True)` für Tests ohne Netzwerkzugriff.

## Best Practices

- **Logs sammeln:** Jeder SDK-Aufruf schreibt nach `workspace/logs/forensic_<timestamp>.log`.
- **Dry-Run dokumentieren:** Bewahren Sie geplante Ergebnisse gemeinsam mit finalen Artefakten auf.
- **Konfiguration versionieren:** Änderungen in `config/framework.yaml` oder `config/modules/*.yaml` sollten in Git dokumentiert werden.
- **Fehlerbehandlung:** Fang `ModuleGuardError` und `ModuleExecutionError`, um Benutzerfreundliche Meldungen an UIs zurückzugeben.

<!-- AUTODOC:END -->
