# Forensic-Playbook v2.0 - Complete Migration Guide

## 📋 Überblick

Diese Überarbeitung transformiert das Forensic-Playbook von einer Sammlung von Scripts in ein professionelles, modulares Forensik-Framework.

### Hauptverbesserungen

✅ **Modulare Architektur** - Alle Funktionen als wiederverwendbare Module  
✅ **Framework-Orchestrierung** - Zentrales Management mit forensic-cli.py  
✅ **Case Management** - Vollständige Fall-Verwaltung mit Chain of Custody  
✅ **Pipeline-System** - YAML-basierte Workflow-Automatisierung  
✅ **Tool-Integration** - Wrapper für alle Kali Linux Forensik-Tools  
✅ **Standalone-Fähigkeit** - Jedes Modul einzeln nutzbar  
✅ **Einheitliche API** - Konsistente Schnittstellen über alle Module  
✅ **Testabdeckung** - Vollständige pytest Test-Suite  
✅ **Professionelles Logging** - Chain of Custody & Audit Trail  

## 🗂️ Neue Projektstruktur

```
Forensic-Playbook/
├── forensic/                          # NEUE Python Package
│   ├── __init__.py
│   ├── core/                          # Framework-Kern
│   │   ├── framework.py               # Haupt-Orchestrator
│   │   ├── module.py                  # Modul-Basisklasse
│   │   ├── evidence.py                # Evidence Management
│   │   ├── chain_of_custody.py        # CoC Tracking
│   │   ├── config.py                  # Config Management
│   │   └── logger.py                  # Logging System
│   │
│   ├── modules/                       # Forensische Module
│   │   ├── acquisition/
│   │   │   ├── disk_imaging.py        # VERBESSERT von forensic_clone.sh
│   │   │   ├── memory_dump.py         # NEU
│   │   │   ├── network_capture.py     # NEU
│   │   │   └── live_response.py       # NEU
│   │   │
│   │   ├── analysis/
│   │   │   ├── filesystem.py          # NEU (Sleuthkit Wrapper)
│   │   │   ├── memory.py              # NEU (Volatility Wrapper)
│   │   │   ├── network.py             # NEU (Wireshark Wrapper)
│   │   │   ├── timeline.py            # VERBESSERT von timeline_builder.py
│   │   │   ├── ioc_scanning.py        # BEREITS EINGEFÜGT (ioc_scan.py)
│   │   │   └── malware.py             # NEU (YARA Integration)
│   │   │
│   │   ├── triage/
│   │   │   ├── quick_triage.py        # VERBESSERT von triage_offline.sh
│   │   │   ├── system_info.py         # VERBESSERT von identify_disks.sh
│   │   │   └── persistence.py         # NEU
│   │   │
│   │   └── reporting/
│   │       ├── generator.py           # NEU
│   │       └── exporter.py            # NEU
│   │
│   ├── tools/                         # Tool-Wrapper (NEU)
│   │   ├── sleuthkit.py               # TSK Wrapper
│   │   ├── volatility.py              # Volatility Wrapper
│   │   ├── autopsy.py                 # Autopsy Integration
│   │   ├── plaso.py                   # Log2timeline Wrapper
│   │   ├── bulk_extractor.py          # Bulk Extractor Wrapper
│   │   └── yara.py                    # YARA Wrapper
│   │
│   └── utils/                         # Hilfsfunktionen
│       ├── hash.py
│       ├── file_ops.py
│       ├── network.py
│       └── validation.py
│
├── scripts/                           # Standalone Scripts
│   ├── forensic-cli.py                # HAUPT-CLI (NEU)
│   ├── quick-triage.sh                # VERBESSERT
│   ├── setup-environment.sh           # VERBESSERT von install_forensic_deps.sh
│   └── case-init.sh                   # NEU
│
├── pipelines/                         # Vordefinierte Pipelines (NEU)
│   ├── incident_response.yaml
│   ├── malware_analysis.yaml
│   ├── disk_forensics.yaml
│   ├── memory_forensics.yaml
│   └── network_forensics.yaml
│
├── config/                            # Konfiguration (NEU)
│   ├── framework.yaml
│   ├── modules.yaml
│   ├── iocs/
│   │   ├── IoCs.json                  # VERBESSERT von IoCs.txt
│   │   ├── domains.txt
│   │   ├── ips.txt
│   │   └── hashes.txt
│   └── templates/
│       ├── report.html.j2
│       └── timeline.html.j2
│
├── tests/                             # Test Suite (NEU)
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── docs/                              # Dokumentation (NEU)
│   ├── getting_started.md
│   ├── modules/
│   ├── tutorials/
│   └── api/
│
├── router/                            # Router-Forensics (BEHALTEN)
│   └── scripts/                       # VERBESSERT
│       ├── collect_router_ui.py       # VERBESSERT
│       ├── analyze_ui_artifacts.sh    # VERBESSERT
│       └── ...
│
├── README.md                          # KOMPLETT NEU
├── ARCHITECTURE.md                    # NEU
├── CHANGELOG.md                       # NEU
├── setup.py                           # NEU
├── requirements.txt                   # AKTUALISIERT
└── pyproject.toml                     # NEU
```

## 🔄 Mapping: Alt → Neu

### Scripts → Module Migration

| Alt (v1) | Neu (v2) | Status |
|----------|----------|--------|
| `ioc_scan.py` (alt) | `forensic/modules/analysis/ioc_scanning.py` | ✅ Bereits eingefügt |
| `forensic_clone.sh` | `forensic/modules/acquisition/disk_imaging.py` | ✅ Neu implementiert |
| `triage_offline.sh` | `forensic/modules/triage/quick_triage.py` | 🔄 Zu migrieren |
| `forensic_ro_analysis.sh` | `forensic/modules/analysis/filesystem.py` | 🔄 Zu migrieren |
| `timeline_builder.py` | `forensic/modules/analysis/timeline.py` | 🔄 Zu migrieren |
| `install_forensic_deps.sh` | `scripts/setup-environment.sh` | 🔄 Zu migrieren |
| `identify_disks.sh` | `forensic/modules/triage/system_info.py` | 🔄 Zu migrieren |
| `harden_ssh.sh` | `forensic/modules/remediation/ssh_hardening.py` | 🔄 Zu migrieren |
| Router-Scripts | `router/scripts/*` (verbessert) | 🔄 Zu migrieren |

### Neue Komponenten

| Komponente | Beschreibung | Priorität |
|------------|--------------|-----------|
| `forensic/core/framework.py` | Framework-Kern | ✅ Kritisch |
| `forensic/core/module.py` | Modul-Basisklasse | ✅ Kritisch |
| `scripts/forensic-cli.py` | CLI-Interface | ✅ Kritisch |
| `forensic/tools/sleuthkit.py` | TSK Wrapper | 🔥 Hoch |
| `forensic/tools/volatility.py` | Volatility Wrapper | 🔥 Hoch |
| `forensic/modules/analysis/memory.py` | Memory Analysis | 🔥 Hoch |
| `pipelines/*.yaml` | Workflow Pipelines | 📝 Mittel |
| `tests/*` | Test Suite | 📝 Mittel |

## 🚀 Implementierungsplan

### Phase 1: Kern-Framework (Tag 1-2)

**Schritt 1.1: Python Package Structure**
```bash
mkdir -p forensic/{core,modules/{acquisition,analysis,triage,reporting},tools,utils}
touch forensic/__init__.py
touch forensic/core/__init__.py
touch forensic/modules/__init__.py
# ... etc
```

**Schritt 1.2: Kern-Dateien erstellen**
1. `forensic/core/framework.py` ✅ (Bereits im Artifact)
2. `forensic/core/module.py` ✅ (Bereits im Artifact)
3. `forensic/core/evidence.py`
4. `forensic/core/chain_of_custody.py`
5. `forensic/core/logger.py`
6. `forensic/core/config.py`

**Schritt 1.3: CLI erstellen**
- `scripts/forensic-cli.py` ✅ (Bereits im Artifact)

**Schritt 1.4: setup.py & requirements.txt**
- `setup.py` ✅ (Bereits im Artifact)
- `requirements.txt` aktualisieren

### Phase 2: Basis-Module (Tag 3-5)

**Kritische Module:**
1. ✅ `ioc_scanning.py` (Bereits eingefügt)
2. ✅ `disk_imaging.py` (Bereits im Artifact)
3. `quick_triage.py` (Migration von triage_offline.sh)
4. `filesystem.py` (Sleuthkit Wrapper)
5. `timeline.py` (Migration von timeline_builder.py)

**Implementierung pro Modul:**
```python
# Template für Migration
from forensic.core.module import AnalysisModule, ModuleResult

class NewModule(AnalysisModule):
    @property
    def name(self) -> str:
        return "module_name"
    
    def validate_params(self, params: Dict) -> bool:
        # Validierung
        pass
    
    def run(self, evidence, params) -> ModuleResult:
        # Alte Shell-Logic hier in Python
        pass
```

### Phase 3: Tool-Wrapper (Tag 6-7)

**Tool-Integration:**
1. `sleuthkit.py` - TSK Wrapper (fls, icat, mmls, etc.)
2. `volatility.py` - Volatility 2/3 Wrapper
3. `plaso.py` - Log2timeline Wrapper
4. `yara.py` - YARA Integration
5. `bulk_extractor.py` - Bulk Extractor Wrapper

**Wrapper-Template:**
```python
# forensic/tools/sleuthkit.py
class SleuthkitWrapper:
    def __init__(self, image_path):
        self.image_path = image_path
    
    def list_files(self, inode=None):
        """Wrapper für fls"""
        cmd = ['fls', '-r', str(self.image_path)]
        # ... execute & parse
        return files
    
    def read_file(self, inode):
        """Wrapper für icat"""
        cmd = ['icat', str(self.image_path), str(inode)]
        # ... execute & return content
        return content
```

### Phase 4: Pipelines & Testing (Tag 8-10)

**Pipeline-Definitionen:**
1. `pipelines/incident_response.yaml`
2. `pipelines/malware_analysis.yaml`
3. `pipelines/disk_forensics.yaml`

**Test-Suite:**
```bash
mkdir -p tests/{unit,integration,fixtures}

# Unit Tests für jedes Modul
# forensic/modules/acquisition/test_disk_imaging.py
pytest tests/ -v --cov=forensic
```

### Phase 5: Dokumentation (Tag 11-12)

1. ✅ `README.md` (Bereits im Artifact)
2. `ARCHITECTURE.md`
3. `docs/getting_started.md`
4. `docs/modules/` - Modul-Dokumentation
5. API-Dokumentation mit Sphinx

### Phase 6: Migration alte Scripts (Tag 13-15)

**Router-Scripts verbessern:**
- Chain of Custody Integration
- Framework-kompatible Outputs
- Fehlerbehandlung standardisieren

**Legacy-Scripts beibehalten:**
- In `scripts/legacy/` verschieben
- Deprecated-Warnung hinzufügen
- Hinweis auf neue Module

## 📝 Detaillierte Migrations-Beispiele

### Beispiel 1: triage_offline.sh → quick_triage.py

**Alt (Bash):**
```bash
#!/usr/bin/env bash
# triage_offline.sh
grep -RInE 'suspicious|malware' "$TARGET" > findings.txt
find "$TARGET" -type f -perm -4000 > suid.txt
```

**Neu (Python Module):**
```python
# forensic/modules/triage/quick_triage.py
from forensic.core.module import TriageModule, ModuleResult

class QuickTriageModule(TriageModule):
    @property
    def name(self) -> str:
        return "quick_triage"
    
    def run(self, evidence, params) -> ModuleResult:
        findings = []
        
        # SUID Scan
        suid_files = self._find_suid_files(params['target'])
        if suid_files:
            findings.append({
                'type': 'suid_files',
                'count': len(suid_files),
                'files': suid_files
            })
        
        # String search
        suspicious = self._search_strings(
            params['target'],
            ['suspicious', 'malware']
        )
        if suspicious:
            findings.append({
                'type': 'suspicious_strings',
                'matches': suspicious
            })
        
        return ModuleResult(
            result_id=self._generate_result_id(),
            module_name=self.name,
            status="success",
            timestamp=self._get_timestamp(),
            findings=findings
        )
```

**Nutzung:**
```bash
# Alt
./triage_offline.sh /mnt/evidence

# Neu - Framework
./scripts/forensic-cli.py module run quick_triage \
    --param target=/mnt/evidence

# Neu - Standalone
python3 -m forensic.modules.triage.quick_triage \
    --target /mnt/evidence
```

### Beispiel 2: forensic_clone.sh → disk_imaging.py

**Alt:**
```bash
#!/usr/bin/env bash
ddrescue -f /dev/sdb disk.img disk.log
sha256sum /dev/sdb > source.hash
sha256sum disk.img > image.hash
```

**Neu:**
```python
# Bereits implementiert als disk_imaging.py
# Siehe Artifact: forensic/modules/acquisition/disk_imaging.py
```

**Nutzung:**
```bash
# Alt
sudo ./forensic_clone.sh --source /dev/sdb --target disk.img

# Neu
sudo ./scripts/forensic-cli.py module run disk_imaging \
    --param source=/dev/sdb \
    --param output=disk.img \
    --param tool=ddrescue \
    --param hash_algorithm=sha256
```

## 🧪 Testing-Strategie

### Unit Tests

```python
# tests/unit/test_disk_imaging.py
import pytest
from forensic.modules.acquisition.disk_imaging import DiskImagingModule

def test_validate_params():
    module = DiskImagingModule(case_dir=Path("/tmp"), config={})
    
    # Valid params
    assert module.validate_params({
        'source': '/dev/sdb',
        'output': 'disk.img'
    })
    
    # Missing required param
    assert not module.validate_params({
        'source': '/dev/sdb'
    })

@pytest.mark.integration
def test_disk_imaging(tmp_path):
    # Create test disk image
    test_disk = tmp_path / "test.img"
    # ... create test disk
    
    module = DiskImagingModule(case_dir=tmp_path, config={})
    result = module.run(None, {
        'source': str(test_disk),
        'output': str(tmp_path / "output.img")
    })
    
    assert result.status == "success"
```

### Integration Tests

```python
# tests/integration/test_full_workflow.py
def test_incident_response_pipeline(tmp_path):
    framework = ForensicFramework(workspace=tmp_path)
    
    # Create case
    case = framework.create_case("Test Case", "Test", "Tester")
    
    # Execute pipeline
    results = framework.execute_pipeline(
        Path("pipelines/incident_response.yaml")
    )
    
    assert len(results) > 0
    assert all(r.status in ["success", "partial"] for r in results)
```

## 🔧 Konfiguration

### framework.yaml

```yaml
# config/framework.yaml
logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  
execution:
  parallel: true
  max_workers: 4
  timeout: 3600  # seconds
  
evidence:
  hash_algorithm: sha256
  verify_integrity: true
  
chain_of_custody:
  enabled: true
  log_all_access: true
  
output:
  formats:
    - json
    - html
  compression: true
  
tools:
  volatility:
    path: /usr/bin/vol.py
    profiles_dir: /usr/share/volatility/profiles
  
  sleuthkit:
    path: /usr/bin
  
  plaso:
    path: /usr/bin/log2timeline.py
```

### modules.yaml

```yaml
# config/modules.yaml
modules:
  acquisition:
    - name: disk_imaging
      enabled: true
      requires_root: true
    
    - name: memory_dump
      enabled: true
      requires_root: true
  
  analysis:
    - name: ioc_scan
      enabled: true
      config:
        default_ioc_file: config/iocs/IoCs.json
    
    - name: timeline
      enabled: true
      config:
        default_format: csv
  
  triage:
    - name: quick_triage
      enabled: true
```

## 📦 Installation

### Entwicklungsumgebung

```bash
# Clone Repository
git clone https://github.com/your-org/Forensic-Playbook.git
cd Forensic-Playbook

# Virtuelle Umgebung erstellen
python3 -m venv venv
source venv/bin/activate

# Development Installation
pip install -e ".[dev]"

# Forensic Tools installieren
sudo ./scripts/setup-environment.sh

# Tests ausführen
pytest tests/ -v

# Pre-commit hooks
pre-commit install
```

### Produktionsinstallation

```bash
# Aus PyPI (nach Veröffentlichung)
pip install forensic-playbook

# Oder direkt von GitHub
pip install git+https://github.com/your-org/Forensic-Playbook.git

# Oder lokale Installation
pip install .

# Forensic Tools
sudo apt install sleuthkit volatility plaso-tools yara

# Verify Installation
forensic-cli version
forensic-cli check-tools
```

## 🎯 Nächste Schritte

### Sofort (Priorität 1)

1. ✅ Kern-Framework implementieren (framework.py, module.py)
2. ✅ CLI-Interface erstellen (forensic-cli.py)
3. ✅ IoC Scanner integrieren (bereits eingefügt)
4. ✅ Disk Imaging Modul (disk_imaging.py)
5. 🔄 setup.py & requirements.txt finalisieren
6. 🔄 README.md vervollständigen

### Kurzfristig (Priorität 2)

7. Quick Triage Modul (Migration von triage_offline.sh)
8. Filesystem Analysis Modul (Sleuthkit Wrapper)
9. Timeline Modul (Migration von timeline_builder.py)
10. Basis Test-Suite
11. Erste Pipeline (incident_response.yaml)

### Mittelfristig (Priorität 3)

12. Memory Analysis Modul (Volatility Wrapper)
13. Network Analysis Modul
14. Reporting Engine
15. Tool-Wrapper vervollständigen
16. Dokumentation erweitern

### Langfristig (Priorität 4)

17. Web UI Dashboard
18. Cloud Forensics Module
19. Mobile Forensics
20. AI-basierte Anomalieerkennung

## ✅ Checkliste für Release v2.0

- [ ] Alle Kern-Module implementiert
- [ ] CLI vollständig funktional
- [ ] Mind. 3 Pipelines verfügbar
- [ ] Test-Coverage >92%
- [ ] Dokumentation vollständig
- [ ] Alle Legacy-Scripts migriert oder deprecated
- [ ] Chain of Custody funktional
- [ ] Installation getestet (Kali, Ubuntu)
- [ ] Beispiel-Cases dokumentiert
- [ ] Performance-Tests durchgeführt

## 📞 Support & Hilfe

Bei Fragen zur Migration:
1. GitHub Issues: https://github.com/your-org/Forensic-Playbook/issues
2. Discussions: https://github.com/your-org/Forensic-Playbook/discussions
3. Wiki: https://github.com/your-org/Forensic-Playbook/wiki

---

**Diese Migration transformiert das Playbook in ein professionelles Forensik-Framework mit Enterprise-Qualität!**
