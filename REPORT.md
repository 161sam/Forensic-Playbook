# REPORT – Phase-3 Abschluss

## Zusammenfassung

Die Phase-3-Härtung hebt alle zuvor als „MVP" geführten Module auf den Guarded-
Standard. Guarded Module liefern jetzt konsistente Dry-Run-Pfade, prüfen externe
Tools mit freundlichen Hinweisen und protokollieren deterministische Exporte in
der Provenienz- und Chain-of-Custody-Logik. Zusätzlich stehen Codex- und MCP-
Workflows bereit (`forensic-cli codex …`, `forensic-cli mcp …`) inklusive SDK-
Exports für Automatisierung. Die Dokumentation (README, Getting-Started,
Walkthrough) und die automatisch generierte Modulmatrix sind synchronisiert.

## Modulstatus (Vorher → Nachher)

| Modul | Bereich | Status Phase-3 Start | Status Phase-3 Abschluss | Guard-Highlights |
| --- | --- | --- | --- | --- |
| `live_response` | Acquisition | MVP, manuelle Checks | Guarded, Dry-Run + Whitelist-Provenienz | Kommandos nur aus Whitelist, Dry-Run zeigt geplante Aufrufe |
| `network_capture` | Acquisition | MVP, rudimentäre Tool-Prüfung | Guarded, privilegienbewusst | Dumpcap/Tcpdump Guards, Dry-Run, Root- und Flag-Prüfung |
| `network` | Analysis | MVP, fixer PCAP-Pfad | Guarded, Runtime-PCAP/JSON-Fallback | Akzeptiert Synth/JSON, deterministische Flow-Aggregation |
| `generator` | Reporting | MVP, HTML-only happy path | Guarded, PDF optional | HTML immer, PDF optional mit Hinweisbox, deterministische Artefakte |
| `persistence` | Triage | MVP, lose Pfadauswahl | Guarded, Konfigurations-Defaults | Liest nur konfigurierte Pfade, Chain-of-Custody aktualisiert |
| `quick_triage` | Triage | MVP, unstrukturierte Ausgabe | Guarded, konsolidierte Funde | Dry-Run, deterministische JSON/CSV, Provenienz-Einträge |
| `system_info` | Triage | MVP, spontane Abfragen | Guarded, OS-sichere APIs | Nur Lesezugriffe, sortierte Ausgaben, Guard-Hinweise |

## Prozess- & QA-Checkliste

- [x] End-to-End-Flow grün mit Runtime-PCAP-Synth oder `--pcap-json -` Fallback.
- [x] PDF-Export optional: HTML immer verfügbar, PDF wird nur bei vorhandenem
      Renderer erzeugt.
- [x] Coverage-Gate ≥ 65 % aktiv in CI.
- [x] Deterministische Exporte (sortierte Keys, ISO-8601-Zeitstempel mit TZ).
- [x] Chain of Custody & Provenienz protokollieren jeden Lauf ohne Duplikate.

## Dokumentation & Werkzeuge

- Modulmatrix über `tools/generate_module_matrix.py` aktualisiert (alle zuvor
  MVP → Guarded, Backend/Guard-Spalten synchron).
- README, Getting-Started und Walkthrough erklären Guard-Level, Dry-Run,
  Konfigurations-Priorität, Runtime-PCAP-Synth/JSON-Fallback sowie die neuen
  Codex/MCP-Workflows.
- CI hält optionale PDF-Erstellung tolerant und dokumentiert fehlende Renderer in
  den Provenienzlogs.
- Abschlussstatus in REPORT.md dokumentiert; Änderungen sind idempotent.
