# Forensic-Playbook

Deterministisches Framework für digitale Forensik mit Fokus auf Guarded-Ausführung, Dry-Run-Strategien und lückenlose
Provenienz. Die Plattform bietet CLI, SDK und MCP-Anbindung (Codex) für reproduzierbare Untersuchungen.

## Schnellüberblick

- 🔒 **Guarded Operations:** Jeder Schritt erzwingt Dry-Run-Planung, Tool-Checks und Chain-of-Custody-Logging.
- 🧰 **Modulare Architektur:** Acquisition, Analysis, Triage, Reporting und Router-Suite lassen sich einzeln oder als Pipeline
  kombinieren.
- 🤖 **MCP/Codex ready:** `forensic-cli codex` und `forensic-cli mcp` stellen geprüfte Tools für Natural-Language-Interfaces bereit.
- 🧪 **Deterministische Tests:** Synth-Fallbacks ersetzen Binärfixtures; fehlende Abhängigkeiten führen zu Guard-Warnungen statt Fehlern.

## Installation (Kurzform)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
forensic-cli diagnostics --summary --dry-run
```

Weitere Details (inklusive Paketlisten für Kali/Ubuntu) finden Sie im [User Guide](docs/User-Guide.md).

## Dokumentations-Hub

| Thema | Beschreibung |
| --- | --- |
| [User Guide](docs/User-Guide.md) | Endnutzerhandbuch mit Installation, Workflows, Troubleshooting und FAQ. |
| [Developer Guide](docs/Developer-Guide.md) | Architektur, Modulentwicklung, Tests/CI, Release-Flow, Contribution. |
| [Getting Started](docs/Getting-Started.md) | Kompakte Einstiegshilfe mit Guard- und Dry-Run-Konzepten. |
| [Architecture](docs/ARCHITECTURE.md) | Komponentenübersicht, Guard-Flows und Erweiterbarkeit. |
| [Module-Katalog](docs/MODULES/analysis.md) | Referenz für Acquisition/Analysis/Triage/Reporting inklusive Parameter-Tabellen. |
| [Tutorials](docs/tutorials/01_quick-triage-linux.md) | Schritt-für-Schritt-Anleitungen (Triage, Netzwerk→Timeline, Registry, Router). |
| [Examples](docs/examples/minimal-e2e.md) | Copy-&-Paste-Workflows für E2E, IoC-Hunting und Reporting. |
| [API Reference](docs/api/CLI.md) | CLI-Befehlsübersicht und Python-SDK-Beispiele. |
| [Codex/MCP Workflow](docs/mcp/codex-workflow.md) | NL→Framework-Integration inklusive Guard-Prinzipien. |

## Projektstatus

| Bereich | Status |
| --- | --- |
| Core Framework (Cases, Evidence, Chain of Custody) | ✅ Stabil |
| Konfiguration & Defaults | ✅ YAML + CLI-Präzedenz |
| Acquisition (disk, memory, network, live response) | 🟡 Guarded, prüfen lokale Toolchain |
| Analysis (filesystem, memory, network, registry, timeline, malware) | 🟡 Optional Extras (`pcap`, `memory`, `yara`) empfohlen |
| Triage (system info, quick triage, persistence) | ✅ Einsatzbereit |
| Reporting | 🟡 HTML stabil, PDF optional (Guarded) |
| MCP/Codex | 🟡 Beta, Dry-Run verpflichtend |
| Tests/CI | ✅ `pytest -q`, `ruff`, `black --check` |

## Schnellstart (CLI)

```bash
# Fall erstellen und Evidenz registrieren
forensic-cli --workspace ~/cases case create --name demo_case --description "Investigation"
forensic-cli --workspace ~/cases evidence add --case demo_case --path /mnt/images/disk01.E01 --type disk

# Module als Dry-Run und Echtlauf
default_cmd="forensic-cli --workspace ~/cases modules run filesystem_analysis --case demo_case --param image=evidence/disk01.E01"
$default_cmd --dry-run
$default_cmd --param compute_hashes=true

# Bericht generieren (Dry-Run prüfen!)
forensic-cli --workspace ~/cases report generate --case demo_case --fmt html --dry-run
```

Weitere Beispiele: [Minimaler E2E-Workflow](docs/examples/minimal-e2e.md), [Network→Timeline Tutorial](docs/tutorials/02_network-timeline-walkthrough.md).

## Codex/MCP in Kürze

```bash
forensic-cli --workspace ~/cases codex install --dry-run
forensic-cli --workspace ~/cases codex start --foreground
forensic-cli --workspace ~/cases mcp expose --json > ~/cases/tooling/mcp_catalog.json
forensic-cli --workspace ~/cases mcp run --tool diagnostics.ping --local --json
```

Detaillierte Abläufe, Prompt-Beispiele und Guardrails stehen in [docs/mcp/codex-workflow.md](docs/mcp/codex-workflow.md) und
[docs/mcp/forensic-mode.md](docs/mcp/forensic-mode.md).

## Mitmachen

1. Lesen Sie den [Developer Guide](docs/Developer-Guide.md) und halten Sie sich an Dry-Run-/Guard-Konventionen.
2. Führen Sie vor PRs `pytest -q` sowie `ruff check .` und `black --check .` aus.
3. Aktualisieren Sie relevante Dokumentation (`docs/`, `REPORT.md`, `CHANGELOG.md`).
4. Nutzen Sie Conventional Commits (`feat:`, `fix:`, `docs:` …).

## Lizenz & Support

- Lizenzinformationen siehe `LICENSE` (falls vorhanden) bzw. Projektrepo.
- Fragen & Issues: GitHub-Issues oder die in der Dokumentation aufgeführten Kontaktkanäle.

