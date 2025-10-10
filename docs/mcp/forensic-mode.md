<!-- AUTODOC:BEGIN -->
---
title: "Forensic Mode Principles"
description: "Operational guardrails for MCP agents working with Forensic-Playbook."
---

# Grundprinzipien

Forensic Mode stellt sicher, dass alle Aktionen nachvollziehbar, read-only und auditierbar bleiben. Die Richtlinien gelten für
Menschen und MCP-Agenten gleichermaßen.

1. **Dry-Run-Pflicht:** Jeder Befehl muss zuerst mit `--dry-run` oder äquivalentem Plan-Flag ausgeführt werden.
2. **Chain of Custody:** Artefakte, Hashes und Parameter sind in `meta/chain_of_custody.jsonl` bzw. `meta/provenance.jsonl`
   festzuhalten.
3. **Konfigurationspräzedenz:** CLI > Fall-spezifische YAML > globale Defaults. MCP-Tools müssen diese Reihenfolge respektieren.
4. **Guarded Execution:** Fehlende Tools führen zu Guard-Warnungen (`status=skipped`/`partial`) statt Exceptions.
5. **Read-Only-Standard:** Schreibende Aktionen setzen explizite Flags (`--enable-live-capture`, `--approve`). Ohne Flag erfolgt
   kein Zugriff.

# Bezug zu AGENTS

- Wurzel-Anweisungen (`AGENTS.md`) definieren globale Leitplanken (Forensic Mode, Dry-Run, Chain-of-Custody).
- Unterordner wie `docs/AGENTS.md` konkretisieren Dokumentationsanforderungen (Dry-Run hervorheben, deterministische Beispiele).
- MCP-Agents sollten diese Anweisungen vor jedem Schritt lesen und in ihren Antworten referenzieren.

# MCP-spezifische Guardrails

- **Tool-Katalog aktualisieren:** Nach Modul- oder CLI-Änderungen `forensic-cli mcp expose` ausführen und Dokumentation
  synchronisieren.
- **Prompts versionieren:** `forensic/mcp/prompts/forensic_mode.txt` enthält den offiziellen System-Prompt. Änderungen müssen in
  `docs/mcp/codex-workflow.md` verlinkt werden.
- **Logging:** Alle MCP-Aufrufe schreiben nach `<workspace>/codex_logs/`. Bewahren Sie die Logdateien bis zur Übergabe an das
  Incident-Response-Team auf.
- **Sicherer Kontext:** Keine Ausführung außerhalb des definierten Workspaces; Pfade werden vor Nutzung normalisiert.

# Best Practices

- Führen Sie regelmäßig `forensic-cli diagnostics` aus, um Guard-Status und fehlende Tools zu erkennen.
- Nutzen Sie `--json`-Ausgaben für automatisierte Auswertung und archivieren Sie die Antworten gemeinsam mit Logdateien.
- Dokumentieren Sie Entscheidungen (Freigaben für Live-Captures, Anpassungen an YAMLs) schriftlich im Case-Dossier.

<!-- AUTODOC:END -->
