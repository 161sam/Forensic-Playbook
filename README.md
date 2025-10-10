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
| [Codex/MCP Workflow](docs/mcp/codex-workflow.md) | Dualer Pfad zwischen CLI/SDK und Codex-Automatisierung. |
| [Forensic Mode Guardrails](docs/mcp/forensic-mode.md) | Best Practices für Agents, Confirm-Gates und deterministische Exporte. |
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

## Modul-Matrix

Die folgende Tabelle wird automatisiert durch `python tools/generate_module_matrix.py`
gepflegt. Bei Änderungen an Modulen unbedingt den Generator im Dry-Run prüfen,
bevor die finale Tabelle aktualisiert wird.
Die Verfügbarkeit einzelner Tools wird deterministisch über `config/tool_inventory.json`
gesteuert – Änderungen daran nur nach abgesicherter Review und dokumentierter
Guard-Abstimmung vornehmen.

<!-- MODULE_MATRIX:BEGIN -->
| Kategorie | Modul | Status | Backend/Extra | Guard | Notizen |
| --- | --- | --- | --- | --- | --- |
| Acquisition | `disk_imaging` | Guarded | ddrescue / ewfacquire | Root + block device access | Requires ddrescue, ewfacquire (missing locally) |
| Acquisition | `live_response` | Guarded | coreutils (uname, ps, netstat) | — | Requires netstat or ss (missing locally) |
| Acquisition | `memory_dump` | Guarded | avml | --enable-live-capture (Linux) | Requires avml (missing locally) |
| Acquisition | `network_capture` | Guarded | tcpdump / dumpcap | --enable-live-capture + root | — |
| Analysis | `filesystem` | Guarded | sleuthkit (fls, blkcat) | — | Requires fls (missing locally) |
| Analysis | `malware` | Guarded | yara extra | — | Requires yara (missing locally) |
| Analysis | `memory` | Guarded | memory extra (volatility3) | — | Requires vol, vol.py, vol3, volatility (missing locally) |
| Analysis | `network` | Guarded | pcap extra (scapy, pyshark) | — | — |
| Analysis | `registry` | Guarded | reglookup / rip.pl | — | Requires reglookup, rip.pl (missing locally) |
| Analysis | `timeline` | Guarded | log2timeline.py / mactime | — | Requires fls, log2timeline.py, mactime (missing locally) |
| Reporting | `exporter` | Guarded | report_pdf extra (weasyprint) | — | Requires wkhtmltopdf (missing locally) |
| Reporting | `generator` | Guarded | jinja2 templates | — | — |
| Router | `capture` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `common` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `env` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `extract` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `manifest` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `pipeline` | Guarded | router-suite | Dry-run default; tools optional | — |
| Router | `summarize` | Guarded | router-suite | Dry-run default; tools optional | — |
| Triage | `persistence` | Guarded | filesystem inspection | — | — |
| Triage | `quick_triage` | Guarded | POSIX utilities | — | — |
| Triage | `system_info` | Guarded | platform / socket APIs | — | — |
<!-- MODULE_MATRIX:END -->

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

### Router-Suite Quickstart (Guarded)

```bash
forensic-cli router env init --case demo --dry-run
forensic-cli router extract ui --case demo --param input=./evidence/router_exports --dry-run
forensic-cli router manifest write --case demo --param source=./cases/demo/router/20240101T000000Z
forensic-cli router summarize --case demo --param source=./cases/demo/router/20240101T000000Z
```

All router helpers default to dry-run previews. Switch to real execution only
once the plan looks correct and synthetic fixtures are ready—binary captures are
deliberately out of scope for regression tests.

#### Router Skripte → Guarded Module Mapping

| Skript (`router/scripts/*`) | Guarded Modul |
| --- | --- |
| `prepare_env.sh` | `forensic.modules.router.env.RouterEnvModule` |
| `tcpdump_setup.sh`, `tcpdump_passive_capture.sh`, `tcpdump_passive_stop.sh` | `forensic.modules.router.capture.RouterCaptureModule` |
| `extract_*.sh`, `collect_router_ui.py`, `analyze_ui_artifacts.sh` | `forensic.modules.router.extract.RouterExtractModule` |
| `generate_evidence_manifest.sh` | `forensic.modules.router.manifest.RouterManifestModule` |
| `summarize_report.sh` | `forensic.modules.router.summarize.RouterSummarizeModule` |
| `run_forensic_pipeline.sh` | `forensic.modules.router.pipeline.RouterPipelineModule` |

> ℹ️ Tests rely on deterministic text fixtures and archives generated at runtime.
> Avoid binary samples (PCAPs, firmware dumps) to keep the suite portable.

Weitere Beispiele: [Minimaler E2E-Workflow](docs/examples/minimal-e2e.md), [Network→Timeline Tutorial](docs/tutorials/02_network-timeline-walkthrough.md).

## Automatisierung mit Codex/MCP

```bash
forensic-cli --workspace ~/cases codex install --dry-run
forensic-cli --workspace ~/cases codex start --foreground
forensic-cli --workspace ~/cases mcp expose --json > ~/cases/tooling/mcp_catalog.json
forensic-cli --workspace ~/cases mcp run --tool diagnostics.ping --local --json
```

Die Befehle spiegeln den Dual-Workflow wider: zuerst CLI/SDK-Dry-Runs planen, anschließend optional Codex/MCP-Agenten einsetzen. Ausführliche Leitfäden mit Prompt-Beispielen finden sich in [docs/mcp/codex-workflow.md](docs/mcp/codex-workflow.md); die Guardrails stehen in [docs/mcp/forensic-mode.md](docs/mcp/forensic-mode.md).

## Mitmachen

1. Lesen Sie den [Developer Guide](docs/Developer-Guide.md) und halten Sie sich an Dry-Run-/Guard-Konventionen.
2. Führen Sie vor PRs `pytest -q` sowie `ruff check .` und `black --check .` aus.
3. Aktualisieren Sie relevante Dokumentation (`docs/`, `REPORT.md`, `CHANGELOG.md`).
4. Nutzen Sie Conventional Commits (`feat:`, `fix:`, `docs:` …).

## Lizenz & Support

- Lizenzinformationen siehe `LICENSE` (falls vorhanden) bzw. Projektrepo.
- Fragen & Issues: GitHub-Issues oder die in der Dokumentation aufgeführten Kontaktkanäle.

