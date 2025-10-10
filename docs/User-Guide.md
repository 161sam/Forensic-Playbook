<!-- AUTODOC:BEGIN -->
---
title: "Forensic-Playbook User Guide"
description: "Operational handbook for analysts using the Forensic-Playbook framework."
---

# Überblick

Der **Forensic-Playbook User Guide** richtet sich an Incident-Responder, Threat-Hunter und Digitale-Forensik-Analysten, die mit dem Framework deterministische Untersuchungen durchführen möchten. Die Anleitung folgt dem Forensic-Mode-Grundsatz: **dry-run zuerst, Guard-Checks respektieren, Chain of Custody lückenlos dokumentieren**.

## Zielgruppe & Voraussetzungen

| Rolle | Erwartete Kenntnisse |
| --- | --- |
| Ersthelfer / Triage-Team | Grundlegende CLI-Kenntnisse, Verständnis von Beweisquellen |
| Forensik-Analyst | Erfahrung mit Linux (Kali/Ubuntu), Vertrautheit mit Hashing & Logging |
| Berichtsteam | Kenntnis des Chain-of-Custody-Prozesses, Markdown/HTML |

**Technische Voraussetzungen**

- Linux: Kali 2024.x, Ubuntu 22.04 LTS oder Debian 12 (getestet)
- Python ≥ 3.10 (System oder dedizierte VM)
- Optional: wkhtmltopdf, yara, volatility3, tcpdump/dumpcap – Module melden fehlende Tools mit Guard-Warnungen

## Installation & Erstkonfiguration

```bash
# Systempakete aktualisieren (Kali/Ubuntu)
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip sleuthkit yara

# Repository klonen
git clone https://github.com/161sam/Forensic-Playbook.git
cd Forensic-Playbook

# Virtuelle Umgebung anlegen
python3 -m venv .venv
source .venv/bin/activate

# Framework installiert die CLI im Editiermodus
pip install -e .

# Diagnose ausführen (dry-run standardmäßig aktiviert)
forensic-cli diagnostics --summary
```

> **Hinweis:** Alle Module prüfen vor Ausführung ihre Abhängigkeiten. Fehlende Tools führen zu einer Guard-Warnung statt eines Abbruchs. Die vollständigen Logs finden Sie unter `<workspace>/logs/` sowie im Provenienz-Journal `meta/provenance.jsonl`.

### Konfigurations-Präzedenz

Die Konfiguration folgt strikt der Reihenfolge **CLI > YAML > Defaults**. Dies gilt für Framework-Einstellungen sowie für Module.

```bash
# 1. Built-in Defaults
#    (forensic/core/config.py, Module-Basisklassen)

# 2. YAML-Konfiguration
#    config/framework.yaml
#    config/modules/<module>.yaml

# 3. CLI-Parameter
forensic-cli modules run network_capture   --workspace ~/cases/demo   --case demo_case   --param interface=eth0   --param duration=120
```

> Die aufgelösten Parameter werden im Fallverzeichnis `cases/<id>/meta/resolved_config.yaml` und in `meta/provenance.jsonl` protokolliert. Damit bleibt nachvollziehbar, welche Quelle den Wert geliefert hat.

### Guards & Dry-Run

Alle **Guarded Modules** erzwingen Vorabprüfungen:

- **Tool-Checks:** `forensic-cli diagnostics` meldet fehlende Binärdateien oder Python-Extras.
- **Privilege-Checks:** Module mit Live-Zugriff verlangen Root-Rechte *und* optionale Flags wie `--enable-live-capture`.
- **Dry-Run-First:** Ohne `--dry-run` verweigern sensible Module die Ausführung. Im Dry-Run werden Befehle, Zielpfade und Log-Orte simuliert.

```bash
# Guard-Checks einsehen
forensic-cli diagnostics --modules acquisition.analysis

# Dry-Run einer Akquisition
forensic-cli modules run disk_imaging   --case demo_case   --param source=/dev/sdz   --param out=/evidence/disk.img   --dry-run
```

## Standard-Workflows

### 1. Fall (Case) anlegen und Evidence registrieren

```bash
# Workspace vorbereiten (read-only Planung)
forensic-cli --workspace ~/cases demo plan --dry-run

# Fall erstellen
forensic-cli --workspace ~/cases case create   --name "demo_case"   --description "Incident 2025-05"   --investigator "Analyst"   --timezone "UTC"

# Beweise hinzufügen
forensic-cli --workspace ~/cases evidence add   --case demo_case --path /mnt/images/disk01.E01 --type disk
forensic-cli --workspace ~/cases evidence add   --case demo_case --path /mnt/memory/host01.avml --type memory
```

- Artefakte werden unter `cases/<case>/evidence/` verlinkt.
- Hashes + Metadaten landen in `cases/<case>/meta/chain_of_custody.jsonl`.

### 2. Diagnostics & Guard-Status überprüfen

```bash
# Überblick über Module, Guards, fehlende Tools
a. forensic-cli diagnostics --summary
b. forensic-cli diagnostics --modules acquisition --format table
```

> **Interpretation:** `Guard=hard` bedeutet, dass ohne Root/Flag keine Ausführung erfolgt. Optional installierbare Extras (`pcap`, `report_pdf`, `yara`) werden in der Spalte `Extras` angezeigt.

### 3. Evidence Acquisition

#### Dry-Run (Pflicht in sensiblen Umgebungen)

```bash
# Disk-Imaging simulieren
forensic-cli modules run disk_imaging   --case demo_case   --param source=/dev/nvme0n1   --param out=cases/demo_case/acquisition/disk01.E01   --dry-run
```

#### Gesicherte Ausführung

```bash
# Live-Ausführung (nach Freigabe)
sudo forensic-cli modules run disk_imaging   --case demo_case   --param source=/dev/nvme0n1   --param out=cases/demo_case/acquisition/disk01.E01   --param hash=sha256   --enable-live-capture
```

- Logs: `cases/demo_case/logs/modules/disk_imaging-*.log`
- Provenienz: `cases/demo_case/meta/provenance.jsonl`
- Hashes: `cases/demo_case/acquisition/hashes.json`

### 4. Netzwerk- & Timeline-Analyse

Der Netzwerkpfad nutzt synthetische PCAP-Fixtures. Falls keine Live-Capture-Daten verfügbar sind, erzeugt die CLI JSON-Fallbacks.

```bash
# Netzwerkmodul mit Synth-PCAP
forensic-cli modules run network   --case demo_case   --param source=fixtures/pcap/minimal.pcap   --dry-run

# Fallback generiert JSON-Zusammenfassung, wenn scapy fehlt
a. forensic-cli modules run network --case demo_case --param source=fixtures/pcap/minimal.pcap
b. Artefakte: cases/demo_case/analysis/network/*.json

# Timeline basierend auf Netzwerkbefunden
a. forensic-cli modules run timeline        --case demo_case        --param source=cases/demo_case/analysis/network        --param format=csv
b. Ergebnis: cases/demo_case/analysis/timeline/timeline.csv
```

### 5. Reports erzeugen (HTML & optional PDF)

```bash
# HTML-Report (Standard)
forensic-cli report generate   --case demo_case   --fmt html   --out cases/demo_case/reports/demo_case.html

# PDF nur, wenn Extras vorhanden sind
forensic-cli report generate   --case demo_case   --fmt pdf   --out cases/demo_case/reports/demo_case.pdf   --dry-run  # prüft wkhtmltopdf/weasyprint Verfügbarkeit
```

> **Guard-Hinweis:** Fehlt die PDF-Engine, markiert der Report-Generator die Ausgabe als `skipped` und verweist auf HTML. Alle Exporte werden mit Hashwert und Zeitstempel im Chain-of-Custody-Protokoll ergänzt.

## Router-Forensik (CLI-Gruppe `forensic-cli router`)

Die Router-Suite ersetzt Legacy-Shellskripte durch Guarded-Python-Befehle. Jeder Unterbefehl akzeptiert `--dry-run` und respektiert Konfigurationsprofile in `config/modules/router/`.

```bash
# Umgebung vorbereiten (keine Änderungen ohne Freigabe)
forensic-cli router env init   --root ~/cases/router_demo   --profile default   --dry-run

# Capture-Plan prüfen
forensic-cli router capture plan   --if eth1   --bpf "not port 22"   --duration 300   --dry-run

# Artefakte extrahieren
forensic-cli router extract ui   --input /mnt/router_dump   --out ~/cases/router_demo/extract   --dry-run

# Manifest schreiben & Hashes prüfen
forensic-cli router manifest write   --source ~/cases/router_demo/extract   --out ~/cases/router_demo/manifest.json

# Ergebnisse zusammenfassen
forensic-cli router summarize   --in ~/cases/router_demo/extract   --out ~/cases/router_demo/summary.md
```

> **Legacy-Vergleich:** Mit `--legacy` lässt sich die historische Bash-Implementierung anzeigen. Ohne ausdrückliche Freigabe werden keine Live-Captures gestartet.

## Chain of Custody & Provenienz

- Jeder Befehl erzeugt einen Eintrag in `cases/<case>/meta/chain_of_custody.jsonl`.
- Hashberechnungen werden in `hashes.json` je Modul abgelegt.
- Der Provenienz-Stream `meta/provenance.jsonl` enthält Quelle, Parameter, Guard-Level und Pfade.
- Für MCP-Läufe werden zusätzliche Logs unter `<workspace>/codex_logs/` geschrieben.

**Empfehlung:** Archivieren Sie Workspace-Logs (`logs/*.log`) gemeinsam mit dem Fall, um Audit-Anforderungen zu erfüllen.

## Troubleshooting

| Symptom | Ursache | Abhilfe |
| --- | --- | --- |
| `permission denied` bei Acquisition | Kein Root / `--enable-live-capture` fehlt | Dry-Run prüfen, dann mit sudo + Flag ausführen |
| Meldung „Missing dependency“ | Tool oder Python-Extra fehlt | `forensic-cli diagnostics --modules <name>` → Installationshinweis folgen |
| Keine Ergebnisse im Report | Modul lieferte leere Artefakte | `cases/<case>/logs/modules/*.log` prüfen, Parameter anpassen, ggf. erneut ausführen |
| MCP-Tool nicht sichtbar | MCP-Adapter läuft nicht | `forensic-cli codex status` & `forensic-cli mcp expose` prüfen |

## Beispiele (Copy & Paste)

### Schnellstart (CLI)

```bash
forensic-cli --workspace ~/cases diagnostics --summary
forensic-cli --workspace ~/cases case create --name demo_case --description "Onboarding"
forensic-cli --workspace ~/cases evidence add --case demo_case --path /mnt/evidence/disk01.E01 --type disk
forensic-cli --workspace ~/cases modules run quick_triage --case demo_case --dry-run
```

### SDK-Minimalbeispiel

```python
from pathlib import Path
from forensic.core.framework import ForensicFramework
from forensic.modules.triage.quick_triage import QuickTriageModule

workspace = Path("~/cases").expanduser()
framework = ForensicFramework(workspace=workspace)
framework.register_module("quick_triage", QuickTriageModule)
case = framework.load_case("demo_case")
framework.execute_module("quick_triage", params={"profile": "default"}, dry_run=True)
```

## Glossar

- **Guard-Level:** Einstufung des Sicherheitsniveaus (`soft`, `medium`, `hard`); bestimmt, welche Checks vor Ausführung stattfinden.
- **Dry-Run:** Simulierte Ausführung ohne Änderung am System oder an Beweisen.
- **Chain of Custody (CoC):** Lückenlose Dokumentation aller Zugriffe und Artefakte eines Falls.
- **Provenienz-Log:** Maschinenlesbare Nachweise der Parameter, Pfade und Ergebnisse jedes Moduls.
- **Workspace:** Oberster Ordner für Fälle, Logs, temporäre Dateien (`forensic-cli --workspace`).
- **MCP (Model Context Protocol):** Schnittstelle, über die Codex Forensic-Playbook-Tools aufruft.

## FAQ

**Wie aktualisiere ich das Framework sicher?**  
Nutzen Sie `git pull` im Repository, aktivieren Sie das virtuelle Environment und führen Sie `pip install -e .` erneut aus. Prüfen Sie anschließend `forensic-cli diagnostics` im Dry-Run.

**Kann ich Module parallel ausführen?**  
Ja, solange sich die Artefaktpfade nicht überschneiden. Nutzen Sie getrennte Workspaces oder Cases, um CoC-Kollisionen zu vermeiden.

**Was passiert ohne optionale Extras?**  
Module liefern reduzierte Ergebnisse (z. B. JSON-Fallbacks) und protokollieren den fehlenden Pfad im Provenienz-Log. Die CLI beendet sich ohne Fehler.

**Wie integriere ich MCP/Codex?**  
Folgen Sie [docs/mcp/codex-workflow.md](mcp/codex-workflow.md). Starten Sie immer mit `forensic-cli codex install --dry-run` und aktivieren Sie den Service erst nach Freigabe.

**Wie exportiere ich Berichte für das Incident-Response-Team?**  
Erstellen Sie zuerst den HTML-Report, prüfen Sie ihn, und konvertieren Sie optional in PDF. Packen Sie anschließend `reports/`, `meta/` und relevante Logs in ein Archiv für die Weitergabe.

---

Weitere vertiefende Informationen finden Sie in den [Tutorials](tutorials/01_quick-triage-linux.md), [Modul-Referenzen](MODULES/acquisition.md) sowie im [Developer Guide](Developer-Guide.md).
<!-- AUTODOC:END -->
