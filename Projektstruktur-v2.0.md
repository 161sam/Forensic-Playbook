# Forensic-Playbook - Projektstruktur v2.0

```
Forensic-Playbook/
├── README.md                          # Hauptdokumentation
├── ARCHITECTURE.md                    # Architektur & Design
├── CHANGELOG.md                       # Versionshistorie
├── LICENSE                            # MIT License
├── requirements.txt                   # Python Dependencies
├── setup.py                           # Installation Script
│
├── config/                            # Konfigurationsdateien
│   ├── framework.yaml                 # Framework-Konfiguration
│   ├── modules.yaml                   # Modul-Aktivierung
│   ├── iocs/                          # IoC-Dateien
│   │   ├── IoCs.json                  # Hauptliste
│   │   ├── domains.txt               
│   │   ├── ips.txt
│   │   └── hashes.txt
│   └── templates/                     # Report-Templates
│       ├── report.html.j2
│       └── timeline.html.j2
│
├── forensic/                          # Python Package
│   ├── __init__.py
│   ├── core/                          # Kernfunktionalität
│   │   ├── __init__.py
│   │   ├── framework.py               # Hauptframework
│   │   ├── module.py                  # Modul-Basisklasse
│   │   ├── evidence.py                # Evidence Handler
│   │   ├── chain_of_custody.py        # CoC Management
│   │   ├── config.py                  # Config Management
│   │   └── logger.py                  # Logging System
│   │
│   ├── modules/                       # Forensische Module
│   │   ├── __init__.py
│   │   ├── acquisition/               # Datenakquise
│   │   │   ├── __init__.py
│   │   │   ├── disk_imaging.py        # DD/DDrescue
│   │   │   ├── memory_dump.py         # RAM-Capture
│   │   │   ├── network_capture.py     # Packet Capture
│   │   │   └── live_response.py       # Live System
│   │   │
│   │   ├── analysis/                  # Analyse-Module
│   │   │   ├── __init__.py
│   │   │   ├── filesystem.py          # FS-Analyse
│   │   │   ├── registry.py            # Windows Registry
│   │   │   ├── memory.py              # Memory Analysis
│   │   │   ├── network.py             # Network Analysis
│   │   │   ├── malware.py             # Malware Analysis
│   │   │   ├── timeline.py            # Timeline Generation
│   │   │   └── ioc_scanning.py        # IoC Scanner
│   │   │
│   │   ├── triage/                    # Triage-Module
│   │   │   ├── __init__.py
│   │   │   ├── quick_triage.py        # Quick Assessment
│   │   │   ├── system_info.py         # System Information
│   │   │   └── persistence.py         # Persistence Check
│   │   │
│   │   └── reporting/                 # Reporting
│   │       ├── __init__.py
│   │       ├── generator.py           # Report Generator
│   │       └── exporter.py            # Export Funktionen
│   │
│   ├── tools/                         # Tool-Wrapper
│   │   ├── __init__.py
│   │   ├── sleuthkit.py               # TSK Wrapper
│   │   ├── volatility.py              # Volatility Wrapper
│   │   ├── autopsy.py                 # Autopsy Integration
│   │   ├── plaso.py                   # Log2timeline
│   │   ├── bulk_extractor.py          # Bulk Extractor
│   │   └── yara.py                    # YARA Integration
│   │
│   └── utils/                         # Hilfsfunktionen
│       ├── __init__.py
│       ├── hash.py                    # Hashing Functions
│       ├── file_ops.py                # File Operations
│       ├── network.py                 # Network Utils
│       └── validation.py              # Input Validation
│
├── scripts/                           # Standalone Scripts
│   ├── forensic-cli.py                # CLI-Interface
│   ├── quick-triage.sh                # Quick Triage
│   ├── setup-environment.sh           # Environment Setup
│   └── case-init.sh                   # Case Initialization
│
├── pipelines/                         # Vordefinierte Pipelines
│   ├── incident_response.yaml         # IR Pipeline
│   ├── malware_analysis.yaml          # Malware Pipeline
│   ├── disk_forensics.yaml            # Disk Forensics
│   ├── memory_forensics.yaml          # Memory Forensics
│   └── network_forensics.yaml         # Network Forensics
│
├── tests/                             # Test Suite
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/                          # Unit Tests
│   ├── integration/                   # Integration Tests
│   └── fixtures/                      # Test Fixtures
│       ├── disk_images/
│       ├── memory_dumps/
│       └── pcap_files/
│
├── docs/                              # Dokumentation
│   ├── getting_started.md
│   ├── modules/                       # Modul-Dokumentation
│   ├── tutorials/                     # Tutorials
│   ├── api/                           # API-Dokumentation
│   └── examples/                      # Beispiele
│
├── templates/                         # Case Templates
│   ├── case_template/
│   │   ├── evidence/
│   │   ├── analysis/
│   │   ├── reports/
│   │   └── README.md
│   └── report_template.md
│
└── contrib/                           # Community Contributions
    ├── modules/                       # Zusatz-Module
    ├── scripts/                       # Zusatz-Scripts
    └── tools/                         # Zusatz-Tools

## Modul-Kategorien

### Acquisition (Akquise)
- Disk Imaging (dd, ddrescue, ewfacquire)
- Memory Acquisition (LiME, AVML, DumpIt)
- Network Capture (tcpdump, Wireshark)
- Live Response (volatile data collection)
- Cloud Evidence (AWS, Azure, GCP)

### Analysis (Analyse)
- Filesystem Analysis (Sleuthkit, fls, icat)
- Memory Analysis (Volatility 2/3)
- Network Analysis (Wireshark, NetworkMiner)
- Malware Analysis (YARA, Cuckoo, strings)
- Log Analysis (plaso/log2timeline)
- Registry Analysis (RegRipper)
- Timeline Generation (plaso, mactime)

### Triage (Schnelluntersuchung)
- Quick Triage (KAPE-ähnlich)
- System Information Gathering
- Persistence Mechanisms Detection
- IoC Scanning
- Process Analysis
- Network Connections

### Reporting
- HTML Reports
- PDF Generation
- Timeline Visualization
- Evidence Summary
- Chain of Custody Reports

## Technologie-Stack

### Kern
- Python 3.10+
- Click (CLI)
- PyYAML (Config)
- Jinja2 (Templates)
- SQLite (Case DB)

### Forensic Tools Integration
- Sleuthkit/Autopsy
- Volatility 2 & 3
- plaso/log2timeline
- YARA
- Bulk Extractor
- Foremost/Scalpel
- binwalk
- ClamAV/YARA
- Wireshark/tshark

### Zusätzlich
- pytest (Testing)
- Black/flake8 (Linting)
- Sphinx (Docs)
- Docker (Containerization)

###########################################

## Forensic-Playbook - Projektstruktur v2.0

```
Forensic-Playbook/
├── README.md                          # Hauptdokumentation
├── ARCHITECTURE.md                    # Architektur & Design
├── CHANGELOG.md                       # Versionshistorie
├── LICENSE                            # MIT License
├── requirements.txt                   # Python Dependencies
├── setup.py                           # Installation Script
│
├── config/                            # Konfigurationsdateien
│   ├── framework.yaml                 # Framework-Konfiguration
│   ├── modules.yaml                   # Modul-Aktivierung
│   ├── iocs/                          # IoC-Dateien
│   │   ├── IoCs.json                  # Hauptliste
│   │   ├── domains.txt               
│   │   ├── ips.txt
│   │   └── hashes.txt
│   └── templates/                     # Report-Templates
│       ├── report.html.j2
│       └── timeline.html.j2
│
├── forensic/                          # Python Package
│   ├── __init__.py
│   ├── core/                          # Kernfunktionalität
│   │   ├── __init__.py
│   │   ├── framework.py               # Hauptframework
│   │   ├── module.py                  # Modul-Basisklasse
│   │   ├── evidence.py                # Evidence Handler
│   │   ├── chain_of_custody.py        # CoC Management
│   │   ├── config.py                  # Config Management
│   │   └── logger.py                  # Logging System
│   │
│   ├── modules/                       # Forensische Module
│   │   ├── __init__.py
│   │   ├── acquisition/               # Datenakquise
│   │   │   ├── __init__.py
│   │   │   ├── disk_imaging.py        # DD/DDrescue
│   │   │   ├── memory_dump.py         # RAM-Capture
│   │   │   ├── network_capture.py     # Packet Capture
│   │   │   └── live_response.py       # Live System
│   │   │
│   │   ├── analysis/                  # Analyse-Module
│   │   │   ├── __init__.py
│   │   │   ├── filesystem.py          # FS-Analyse
│   │   │   ├── registry.py            # Windows Registry
│   │   │   ├── memory.py              # Memory Analysis
│   │   │   ├── network.py             # Network Analysis
│   │   │   ├── malware.py             # Malware Analysis
│   │   │   ├── timeline.py            # Timeline Generation
│   │   │   └── ioc_scanning.py        # IoC Scanner
│   │   │
│   │   ├── triage/                    # Triage-Module
│   │   │   ├── __init__.py
│   │   │   ├── quick_triage.py        # Quick Assessment
│   │   │   ├── system_info.py         # System Information
│   │   │   └── persistence.py         # Persistence Check
│   │   │
│   │   └── reporting/                 # Reporting
│   │       ├── __init__.py
│   │       ├── generator.py           # Report Generator
│   │       └── exporter.py            # Export Funktionen
│   │
│   ├── tools/                         # Tool-Wrapper
│   │   ├── __init__.py
│   │   ├── sleuthkit.py               # TSK Wrapper
│   │   ├── volatility.py              # Volatility Wrapper
│   │   ├── autopsy.py                 # Autopsy Integration
│   │   ├── plaso.py                   # Log2timeline
│   │   ├── bulk_extractor.py          # Bulk Extractor
│   │   └── yara.py                    # YARA Integration
│   │
│   └── utils/                         # Hilfsfunktionen
│       ├── __init__.py
│       ├── hash.py                    # Hashing Functions
│       ├── file_ops.py                # File Operations
│       ├── network.py                 # Network Utils
│       └── validation.py              # Input Validation
│
├── scripts/                           # Standalone Scripts
│   ├── forensic-cli.py                # CLI-Interface
│   ├── quick-triage.sh                # Quick Triage
│   ├── setup-environment.sh           # Environment Setup
│   └── case-init.sh                   # Case Initialization
│
├── pipelines/                         # Vordefinierte Pipelines
│   ├── incident_response.yaml         # IR Pipeline
│   ├── malware_analysis.yaml          # Malware Pipeline
│   ├── disk_forensics.yaml            # Disk Forensics
│   ├── memory_forensics.yaml          # Memory Forensics
│   └── network_forensics.yaml         # Network Forensics
│
├── tests/                             # Test Suite
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/                          # Unit Tests
│   ├── integration/                   # Integration Tests
│   └── fixtures/                      # Test Fixtures
│       ├── disk_images/
│       ├── memory_dumps/
│       └── pcap_files/
│
├── docs/                              # Dokumentation
│   ├── getting_started.md
│   ├── modules/                       # Modul-Dokumentation
│   ├── tutorials/                     # Tutorials
│   ├── api/                           # API-Dokumentation
│   └── examples/                      # Beispiele
│
├── templates/                         # Case Templates
│   ├── case_template/
│   │   ├── evidence/
│   │   ├── analysis/
│   │   ├── reports/
│   │   └── README.md
│   └── report_template.md
│
└── contrib/                           # Community Contributions
    ├── modules/                       # Zusatz-Module
    ├── scripts/                       # Zusatz-Scripts
    └── tools/                         # Zusatz-Tools

## Modul-Kategorien

### Acquisition (Akquise)
- Disk Imaging (dd, ddrescue, ewfacquire)
- Memory Acquisition (LiME, AVML, DumpIt)
- Network Capture (tcpdump, Wireshark)
- Live Response (volatile data collection)
- Cloud Evidence (AWS, Azure, GCP)

### Analysis (Analyse)
- Filesystem Analysis (Sleuthkit, fls, icat)
- Memory Analysis (Volatility 2/3)
- Network Analysis (Wireshark, NetworkMiner)
- Malware Analysis (YARA, Cuckoo, strings)
- Log Analysis (plaso/log2timeline)
- Registry Analysis (RegRipper)
- Timeline Generation (plaso, mactime)

### Triage (Schnelluntersuchung)
- Quick Triage (KAPE-ähnlich)
- System Information Gathering
- Persistence Mechanisms Detection
- IoC Scanning
- Process Analysis
- Network Connections

### Reporting
- HTML Reports
- PDF Generation
- Timeline Visualization
- Evidence Summary
- Chain of Custody Reports

## Technologie-Stack

### Kern
- Python 3.10+
- Click (CLI)
- PyYAML (Config)
- Jinja2 (Templates)
- SQLite (Case DB)

### Forensic Tools Integration
- Sleuthkit/Autopsy
- Volatility 2 & 3
- plaso/log2timeline
- YARA
- Bulk Extractor
- Foremost/Scalpel
- binwalk
- ClamAV/YARA
- Wireshark/tshark

### Zusätzlich
- pytest (Testing)
- Black/flake8 (Linting)
- Sphinx (Docs)
- Docker (Containerization)
