---
title: Forensic-Playbook Wiki
slug: /
---

Willkommen im **Forensic-Playbook** – einem praxisorientierten Playbook für **Forensik / Incident Response / Triage** mit modularem Aufbau (CLI/SDK), Tutorials, Beispielen und Guardrails für reproduzierbare Analysen.

## Schnellstart

- **Neu hier?** Starte mit dem **[User Guide](guides/user-guide.md)**.
- **Du willst beitragen/entwickeln?** → **[Developer Guide](guides/developer-guide.md)**
- **Du brauchst sofort Triage?** → **[Quick Triage (Linux)](tutorials/01-quick-triage-linux.md)**

---

## Guides

- **[Getting Started](guides/getting-started.md)**  
  Setup und erste Schritte.
- **[User Guide](guides/user-guide.md)**  
  Einstieg, Setup, typische Workflows, Konfiguration und Nutzung im Alltag.
- **[Developer Guide](guides/developer-guide.md)**  
  Architektur, Projektstruktur, Entwicklung, Tests, Releases.
- **[Walkthrough](guides/walkthrough.md)**  
  Schritt-für-Schritt-Durchlauf (End-to-End), wenn du einmal „alles“ sehen willst.

---

## Modules

Der Modul-Katalog ist die „Baukasten“-Ebene: einzelne Analyse-/Extraktions-/Reporting-Module, die du je nach Case kombinierst.

- **[Analysis](modules/analysis.md)** (Startpunkt)  
  Kern-Analysen und Standardchecks.

*(Weitere Module findest du in der Sidebar unter „Modules“.)*

---

## Tutorials

Praxisrezepte für konkrete Aufgaben (z. B. Triage, erste Findings, basale Timeline).

- **[Quick Triage (Linux)](tutorials/01-quick-triage-linux.md)**  
  Minimaler, robuster Ablauf für erste Orientierung.

---

## Examples

Kleine, lauffähige Beispiele – ideal zum Validieren der Toolchain oder für Demos.

- **[Minimal E2E](examples/minimal-e2e.md)**  
  Ein „kleines Ende-zu-Ende“ Beispiel, um den Workflow zu verstehen.

---

## API Reference

Wenn du die CLI/SDK gezielt nutzen willst:

- **[CLI Reference](api/cli.md)**  
  Befehle, Flags, Beispiele.
- **[SDK Reference](api/sdk.md)**  
  Programmatische Nutzung via Python SDK.

---

## MCP & Agents (Codex / Forensic Mode)

Hier stehen die **Guardrails** und das Vorgehen, wenn du mit Agenten/Automatisierung arbeitest:

- **[Codex Workflow](mcp/codex-workflow.md)**  
  Plan → Confirm → Execute, reproduzierbar & sicher.
- **[Forensic Mode](mcp/forensic-mode.md)**  
  Regeln/Prinzipien für read-only, evidenzsicheres Vorgehen.

---

## Labs

- **[Notebooks](labs/notebooks.md)**  
  Jupyter/Experiment-Notebooks und Labor-Workflows.

---

## Project

Projekt- und Meta-Dokumente:

- **[Architecture](project/architecture.md)**
- **[Architecture (Root Snapshot)](project/architecture-root.md)**
- **[Status / Roadmap](project/status.md)**
- **[Changelog](project/changelog.md)**
- **[Migration Guide](project/migration-v1-to-v2.md)**
- **[Migration Progress](project/migration-progress.md)**
- **[Reporting / Output-Konzept](project/reporting.md)**
- **[Development Session Summary](project/development-session-summary.md)**
- **[Session Summary](project/session-summary.md)**
- **[Project Structure v2](project/project-structure-v2.md)**

---

## Guardrails (Forensic Mode, kurz)

- **Dry-Run zuerst:** Wenn verfügbar, nutze `--dry-run` (z. B. `forensic-cli modules run ... --dry-run`).
- **Chain-of-Custody:** Dokumentiere Eingaben/Outputs und Logpfade (z. B. `<workspace>/codex_logs/`).
- **Deterministisch:** Nutze feste Case-IDs wie `demo_case` und reproduzierbare Pfade.
- **CLI vs MCP:** CLI-Workflows findest du im **User Guide**, MCP-Workflows unter **[MCP & Agents](mcp/forensic-mode.md)**.

---

## Leitprinzipien (kurz)

- **Reproduzierbar**: Schritte und Ergebnisse nachvollziehbar dokumentieren.
- **Evidenz-schonend**: read-only wo möglich, klare Trennung von Original und Working Copy.
- **Modular**: Modules kombinieren, statt monolithische „One-Size“-Pipelines.

> Tipp: Nutze die Sidebar links als „Wiki-Navigation“. Alles ist nach Bereichen strukturiert.
