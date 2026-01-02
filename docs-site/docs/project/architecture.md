<!-- AUTODOC:BEGIN -->
---
title: "Architecture Overview"
description: "High-level system architecture and guard-flow summary for Forensic-Playbook."
---

# Komponentenübersicht

```
┌─────────────────────────────────────────────┐
│ forensic.core                               │  Cases, Evidence, Provenance
│  ├─ framework.py                             │  Orchestriert Module & Chain-of-Custody
│  ├─ module.py                                │  Guarded Basisklassen, Ergebnisobjekte
│  └─ chain_of_custody.py                      │  Hashing & Audit-Log
├─────────────────────────────────────────────┤
│ forensic.modules                             │  Acquisition / Analysis / Triage / Reporting / Router
├─────────────────────────────────────────────┤
│ forensic.tools                               │  Wrapper für externe Tools (Sleuthkit, Plaso, Volatility …)
├─────────────────────────────────────────────┤
│ forensic.cli                                 │  Click-CLI (`forensic-cli`) mit globalen Guard-Optionen
├─────────────────────────────────────────────┤
│ forensic.mcp                                 │  MCP-Adapter & Codex-Integration
└─────────────────────────────────────────────┘
```

## Guard-Flow

1. **Konfiguration laden:** `config/framework.yaml` + `config/modules/*.yaml` → wird mit CLI-Parametern zusammengeführt.
2. **Diagnose ausführen:** `forensic-cli diagnostics` überprüft Toolverfügbarkeit und Guard-Level (`soft`/`medium`/`hard`).
3. **Dry-Run planen:** `module.run(..., dry_run=True)` oder CLI `--dry-run` erzeugt Plan und stoppt vor Schreibzugriffen.
4. **Ausführung:** Bewusste Bestätigung (z. B. `--enable-live-capture`) löst reale Aktionen aus.
5. **Provenienz & CoC:** Ergebnisse landen in `cases/<id>/meta/provenance.jsonl` und `meta/chain_of_custody.jsonl`.

## Modul-Kategorien

- **Acquisition:** `forensic/modules/acquisition` (Disk, Memory, Network, Live Response).
- **Analysis:** `forensic/modules/analysis` (Filesystem, Memory, Network, Registry, Timeline, Malware).
- **Triage:** `forensic/modules/triage` (System Info, Quick Triage, Persistence).
- **Reporting:** `forensic/modules/reporting` (Exporter & Generator).
- **Router:** Guarded CLI-Gruppe `forensic-cli router`, Konfiguration in `config/modules/router/`.

## Datenfluss (Beispiel)

1. `forensic-cli modules run filesystem_analysis --dry-run` → prüft `sleuthkit`-Wrapper und plant `analysis/filesystem/`.
2. Nach Freigabe erstellt das Modul JSON-/CSV-Artefakte und ruft `chain_of_custody.log_artifact` auf.
3. Reporting-Modul (`report generate`) liest Analysepfade, generiert HTML/PDF und hash't Ausgaben.
4. MCP/Codex kann denselben Ablauf triggern (`mcp run timeline.plan` → `timeline.execute`).

## Erweiterbarkeit

- **Neue Module:** Ableiten von `BaseGuardedModule`, Konfiguration unter `config/modules/<name>.yaml`, Tests in `tests/modules/...`.
- **Neue Tools:** Wrapper in `forensic/tools/` implementieren, CLI/MCP aktualisieren.
- **Pipelines:** YAML-Workflows (z. B. `router/pipeline.yaml`) orchestrieren Module sequenziell mit Dry-Run-Gates.

Weitere Details & Entwicklerhinweise: [Developer Guide](../guides/developer-guide.md) und [Module-Katalog](../modules/analysis.md).

<!-- AUTODOC:END -->
