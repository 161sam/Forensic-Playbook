<!-- AUTODOC:BEGIN -->
---
title: "Forensic Mode Principles"
description: "Operational guardrails for MCP agents working with Forensic-Playbook."
---

# Forensic Mode — Grundprinzipien

Forensic Mode stellt sicher, dass jede Aktion nachvollziehbar, read-only by default und dokumentiert bleibt. Die Leitlinien gelten für Menschen, Skripte und MCP-Agents gleichermaßen.

## Kernregeln

1. **Dry-Run zuerst** — Jeder Schritt startet mit `--dry-run`, `--plan` oder einer äquivalenten Vorschau. Live-Ausführung erfolgt nur nach bestätigter Freigabe (`--accept-risk`).
2. **Provenienzpflicht** — Erfassen Sie Eingaben, Ausgaben, Hashes und Entscheidungsgrundlagen in `meta/chain_of_custody.jsonl` sowie `meta/provenance.jsonl`.
3. **Konfigurationspräzedenz** — CLI-Flags > Fallkonfiguration (`cases/<id>/config.yaml`) > globale Defaults (`config/framework.yaml`). MCP-Adapter müssen diese Reihenfolge respektieren.
4. **Determinismus** — Ergebnisse müssen reproduzierbar sein. Zufällige Seeds, Zeitstempel oder UUIDs sind zu fixieren oder in Logs zu dokumentieren.
5. **Read-Only-Standard** — Schreibende Aktionen sind opt-in und transparent dokumentiert (z. B. Live-Capture, Memory-Dumps).

## Do & Don’t

| Do | Don’t |
| --- | --- |
| Plan zuerst, dann bestätigen | Kein Live-Run ohne dokumentierte Freigabe |
| Logs unter `<workspace>/codex_logs/` referenzieren | Unprotokollierte Dateien oder Pfade nutzen |
| Prompttexte mit [`forensic/mcp/prompts/forensic_mode.txt`](https://github.com/161sam/Forensic-Playbook/blob/main/forensic/mcp/prompts/forensic_mode.txt) abgleichen | Eigene Prompts ohne Guard-Abschnitte einsetzen |
| Fehlende Tools als Guard-Warnung (`status=skipped`) melden | Exceptions werfen, die den Prompt-Fluss beenden |

## Bezug zu AGENTS-Anweisungen

- Das Wurzel-Dokument (`/AGENTS.md`) beschreibt allgemeine Guardrails sowie Beispiel-Prompts.
- Bereichsspezifische Dateien wie `docs/AGENTS.md`, `forensic/AGENTS.md` oder `router/AGENTS.md` erweitern diese Regeln für ihr Subsystem.
- Änderungen an Guardtexten müssen synchron in den AGENTS-Dateien und im System-Prompt erfolgen.

## Prompt-Beispiele

**System-Prompt (Auszug):**
```
Du agierst im Forensic Mode. Führe zuerst einen Dry-Run durch, fasse geplante Schritte zusammen und warte auf Freigabe. Dokumentiere Workspace, Logpfade und Chain-of-Custody-Hinweise.
```

**Analysten-Prompt:**
```
Plane eine Timeline-Analyse für den Fall `net_timeline`. Beginne mit einem Dry-Run, liste betroffene Artefakte auf und bestätige, dass alle Pfade innerhalb des Workspaces bleiben.
```

**Plan → Confirm → Execute:**
```
1. Plane `forensic-cli modules run timeline --dry-run ...` und gib Logpfade + Artefaktvorschau zurück.
2. Warte auf "Confirm" mit Ticket-ID. Ohne Freigabe keine Live-Ausführung.
3. Führe erst danach `forensic-cli modules run timeline ...` ohne `--dry-run` aus und protokolliere Ergebnisse.
```

## Confirm-Gates & Exportregeln

- Jede automatisierte Ausführung verlangt eine dokumentierte Freigabe (Prompt-Reply, CLI-Flag oder Ticket-ID).
- Exporte (Berichte, Artefakt-Zips) müssen Hashes berechnen und die Ergebnisse zusammen mit Zeitstempeln im Workspace ablegen.
- Verweise auf externe Systeme (z. B. Ticketing) erfolgen ausschließlich über redigierte IDs.

## Abgleich mit Tests & Dokumentation

- Unit-Tests (`tests/test_cli_codex.py`, `tests/test_cli_mcp.py`, `tests/test_mcp_registry.py`) prüfen die Dry-Run- und JSON-Pfade.
- Dokumentationsupdates (README, Getting-Started, `docs/mcp/*.md`) müssen auf diese Prinzipien verlinken.

<!-- AUTODOC:END -->
