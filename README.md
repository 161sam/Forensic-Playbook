# Forensic-Playbook v2.0

**Professional Digital Forensics Investigation Framework**

A comprehensive, modular Python framework for digital forensic investigations with full chain of custody tracking, evidence management, and automated analysis capabilities.

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-75%25%20complete-yellow.svg)

---

## 🎯 Overview

Forensic-Playbook v2.0 is a complete rewrite of the forensic analysis framework, designed for professional digital forensic investigators. It provides:

- **Modular Architecture**: Extensible plugin system for custom modules
- **Chain of Custody**: Automated tracking of all evidence handling
- **Evidence Management**: Comprehensive evidence collection and integrity verification
- **Multi-Platform Support**: Linux, Windows, and macOS analysis capabilities
- **Automated Analysis**: Pre-configured analysis workflows and playbooks
- **Report Generation**: Professional HTML, PDF, JSON, and Markdown reports
- **CLI Interface**: Powerful command-line interface for automation

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Modules](#-modules)
- [Usage Examples](#-usage-examples)
- [Configuration](#-configuration)
- [Development](#-development)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Core Framework
- ✅ **Case Management**: Create, load, and manage investigation cases
- ✅ **Evidence Tracking**: Automatic hash calculation and integrity verification
- ✅ **Chain of Custody**: Comprehensive event logging and audit trail
- ✅ **Module System**: Extensible architecture for custom analysis modules
- ✅ **Logging**: Detailed logging with configurable verbosity
- ✅ **Database Backend**: SQLite for case and CoC storage

### Acquisition Modules
- ✅ **Disk Imaging**: Create forensic images (RAW, E01, AFF4)
- 🚧 **Memory Dump**: Live memory acquisition (planned)
- ✅ **File Collection**: Selective file acquisition with integrity preservation

### Analysis Modules
- ✅ **Filesystem Analysis**: Comprehensive filesystem metadata extraction
- ✅ **Timeline Generation**: MAC time timeline creation
- ✅ **IoC Scanning**: Indicator of Compromise detection
- ✅ **Memory Analysis**: Volatility 3 integration for memory forensics
- ✅ **Registry Analysis**: Windows Registry forensic analysis
- ✅ **Network Analysis**: PCAP analysis and traffic forensics
- ✅ **Hash Analysis**: File hash computation and verification
- ✅ **String Extraction**: Automated string extraction and analysis

### Triage Modules
- ✅ **Quick Triage**: Rapid initial assessment
- ✅ **Live System Triage**: Running system analysis

### Reporting Modules
- ✅ **HTML Reports**: Professional interactive reports
- ✅ **PDF Reports**: Print-ready forensic reports
- ✅ **JSON Export**: Machine-readable output
- ✅ **Markdown Reports**: Text-based documentation

---

## 🚀 Installation

### Prerequisites

- **Python 3.8 or higher**
- **Linux** (primary), Windows, or macOS
- Root/Administrator privileges (for some modules)

### System Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    sleuthkit ewf-tools afflib-tools \
    volatility3 yara \
    tshark wireshark-common \
    wkhtmltopdf \
    hashdeep md5deep
```

#### RHEL/CentOS/Fedora
```bash
sudo dnf install -y \
    python3 python3-pip \
    sleuthkit libewf afflib \
    volatility3 yara \
    wireshark-cli \
    wkhtmltopdf \
    md5deep
```

#### macOS
```bash
brew install python3 sleuthkit libewf afflib yara wireshark wkhtmltopdf
```

### Framework Installation

#### Option 1: From Source (Recommended for Development)

```bash
# Clone repository
git clone https://github.com/yourusername/forensic-playbook-v2.git
cd forensic-playbook-v2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Verify installation
forensic-cli --version
```

#### Option 2: Using pip (When Published)

```bash
pip install forensic-playbook
```

---

## 🎬 Quick Start

### 1. Create a New Case

```bash
# Initialize workspace (first time only)
forensic-cli init --workspace /path/to/workspace

# Create a new investigation case
forensic-cli case create \
    --name "Case-2025-001" \
    --description "Investigation of suspicious activity" \
    --investigator "John Doe"
```

### 2. Add Evidence

```bash
# Add evidence to case
forensic-cli evidence add \
    --type file \
    --source /path/to/evidence/disk.img \
    --description "Suspect's hard drive image"
```

### 3. Run Analysis

```bash
# Filesystem analysis
forensic-cli analyze filesystem_analysis \
    --target /mnt/evidence \
    --max-depth 10 \
    --analyze-permissions true

# IoC scanning
forensic-cli analyze ioc_scan \
    --target /mnt/evidence \
    --ioc-file indicators.json \
    --scan-hashes true

# Timeline generation
forensic-cli analyze timeline \
    --target /mnt/evidence
```

### 4. Generate Report

```bash
# Generate HTML report
forensic-cli report generate \
    --format html \
    --output report.html \
    --executive-summary true
```

---

## 🏗️ Architecture

### Directory Structure

```
forensic-playbook-v2/
├── forensic/
│   ├── core/                    # Core framework components
│   │   ├── framework.py         # Main framework class
│   │   ├── evidence.py          # Evidence management
│   │   ├── module.py            # Module base classes
│   │   ├── chain_of_custody.py  # CoC tracking
│   │   └── logger.py            # Logging system
│   ├── modules/                 # Analysis modules
│   │   ├── acquisition/         # Evidence acquisition
│   │   │   ├── disk_imaging.py
│   │   │   └── memory_dump.py
│   │   ├── analysis/            # Forensic analysis
│   │   │   ├── filesystem.py
│   │   │   ├── timeline.py
│   │   │   ├── ioc_scanning.py
│   │   │   ├── memory.py
│   │   │   ├── registry.py
│   │   │   └── network.py
│   │   ├── triage/              # Quick triage
│   │   │   └── quick_triage.py
│   │   └── reporting/           # Report generation
│   │       └── generator.py
│   └── cli/                     # Command-line interface
│       └── forensic_cli.py
├── tests/                       # Test suite
│   ├── test_framework.py
│   └── test_modules.py
├── docs/                        # Documentation
├── examples/                    # Usage examples
├── requirements.txt             # Dependencies
├── setup.py                     # Installation script
└── README.md                    # This file
```

### Component Overview

```
┌─────────────────────────────────────────┐
│         Forensic CLI Interface          │
│         (forensic-cli.py)               │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│       Forensic Framework Core           │
│  - Case Management                      │
│  - Evidence Management                  │
│  - Module Orchestration                 │
│  - Chain of Custody                     │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴──────────┐
        │                    │
┌───────▼────────┐  ┌────────▼──────────┐
│  Acquisition   │  │    Analysis       │
│  Modules       │  │    Modules        │
├────────────────┤  ├───────────────────┤
│ • Disk Imaging │  │ • Filesystem      │
│ • Memory Dump  │  │ • Timeline        │
│ • File Copy    │  │ • IoC Scanning    │
└────────────────┘  │ • Memory Analysis │
                    │ • Registry        │
        ┌───────────┤ • Network         │
        │           └───────────────────┘
┌───────▼────────┐  ┌───────────────────┐
│    Triage      │  │    Reporting      │
│    Modules     │  │    Modules        │
├────────────────┤  ├───────────────────┤
│ • Quick Triage │  │ • HTML Reports    │
│ • Live Triage  │  │ • PDF Reports     │
└────────────────┘  │ • JSON Export     │
                    └───────────────────┘
```

---

## 📦 Modules

### Acquisition Modules

#### Disk Imaging
Creates forensic disk images with hash verification.

**Supported Formats:**
- RAW (dd)
- E01 (EnCase/ewfacquire)
- AFF4 (Advanced Forensic Format)

**Usage:**
```bash
forensic-cli analyze disk_imaging \
    --source /dev/sda \
    --format e01 \
    --compression fast \
    --verify true
```

### Analysis Modules

#### Filesystem Analysis
Comprehensive filesystem metadata extraction and analysis.

**Features:**
- File enumeration with metadata
- Hidden file detection
- Suspicious file identification
- Permission analysis
- Large file detection
- Recently modified files

**Usage:**
```bash
forensic-cli analyze filesystem_analysis \
    --target /mnt/evidence \
    --max-depth 10 \
    --analyze-permissions true \
    --detect-suspicious true
```

#### IoC Scanner
Scans for Indicators of Compromise.

**Supported IoC Types:**
- File hashes (MD5, SHA1, SHA256)
- IP addresses
- Domain names
- Filenames
- File paths
- YARA rules

**Usage:**
```bash
forensic-cli analyze ioc_scan \
    --target /mnt/evidence \
    --ioc-file indicators.json \
    --scan-hashes true \
    --scan-strings true \
    --yara-rules rules.yar
```

#### Timeline Module
Generates MAC (Modified, Accessed, Changed) time timelines.

**Usage:**
```bash
forensic-cli analyze timeline \
    --target /mnt/evidence \
    --output-format csv
```

#### Memory Analysis
Memory forensics using Volatility 3.

**Supported Plugins:**
- Process listing (pslist)
- Network connections (netscan)
- DLL analysis (dlllist)
- Command line (cmdline)
- Registry analysis (registry)

**Usage:**
```bash
forensic-cli analyze memory_analysis \
    --memory-dump memory.raw \
    --profile Win10x64 \
    --plugins pslist,netscan,cmdline
```

#### Registry Analysis
Windows Registry forensic analysis.

**Capabilities:**
- Registry hive parsing
- User activity extraction
- Persistence mechanism detection
- USB device history
- Network configuration
- Program execution evidence

**Usage:**
```bash
forensic-cli analyze registry_analysis \
    --target /mnt/windows \
    --regripper true
```

#### Network Analysis
PCAP file analysis and network forensics.

**Features:**
- Protocol distribution analysis
- Connection tracking
- DNS query analysis
- HTTP request/response analysis
- Suspicious traffic detection
- File extraction from streams

**Usage:**
```bash
forensic-cli analyze network_analysis \
    --pcap capture.pcap \
    --analyze-dns true \
    --analyze-http true \
    --extract-files true
```

### Triage Modules

#### Quick Triage
Rapid initial assessment of a system.

**Checks:**
- System information
- Running processes
- Network connections
- Scheduled tasks
- Startup items
- Recent files

**Usage:**
```bash
forensic-cli analyze quick_triage \
    --target /mnt/system
```

### Reporting Modules

#### Report Generator
Professional forensic investigation reports.

**Formats:**
- HTML (interactive, styled)
- PDF (print-ready)
- JSON (machine-readable)
- Markdown (text-based)

**Sections:**
- Executive Summary
- Evidence Inventory
- Analysis Findings
- Timeline
- Chain of Custody

**Usage:**
```bash
forensic-cli report generate \
    --format html \
    --output report.html \
    --executive-summary true \
    --timeline true \
    --chain-of-custody true
```

---

## 💡 Usage Examples

### Example 1: Complete Disk Analysis

```bash
# Create case
forensic-cli case create \
    --name "CompanyX-Breach-2025" \
    --investigator "Alice Smith"

# Add disk image as evidence
forensic-cli evidence add \
    --type file \
    --source /evidence/disk.e01 \
    --description "Employee laptop disk image"

# Mount and analyze filesystem
forensic-cli analyze filesystem_analysis \
    --target /mnt/disk \
    --max-depth 15

# Generate timeline
forensic-cli analyze timeline \
    --target /mnt/disk

# Scan for IoCs
forensic-cli analyze ioc_scan \
    --target /mnt/disk \
    --ioc-file apt-indicators.json

# Generate report
forensic-cli report generate --format html
```

### Example 2: Memory Forensics

```bash
# Create case
forensic-cli case create \
    --name "Malware-Analysis-2025"

# Add memory dump
forensic-cli evidence add \
    --type memory \
    --source /evidence/memory.raw

# Run memory analysis
forensic-cli analyze memory_analysis \
    --memory-dump /evidence/memory.raw \
    --profile Win10x64 \
    --plugins pslist,netscan,malfind,cmdline

# Generate report
forensic-cli report generate --format pdf
```

### Example 3: Network Traffic Analysis

```bash
# Create case
forensic-cli case create \
    --name "Network-Intrusion-2025"

# Add PCAP
forensic-cli evidence add \
    --type network \
    --source /evidence/capture.pcap

# Analyze network traffic
forensic-cli analyze network_analysis \
    --pcap /evidence/capture.pcap \
    --analyze-dns true \
    --analyze-http true \
    --detect-suspicious true \
    --extract-files true

# Generate report
forensic-cli report generate --format html
```

### Example 4: Windows Registry Analysis

```bash
# Create case
forensic-cli case create \
    --name "Windows-Investigation"

# Analyze registry
forensic-cli analyze registry_analysis \
    --target /mnt/windows \
    --regripper true

# Generate report
forensic-cli report generate --format markdown
```

---

## ⚙️ Configuration

### Framework Configuration

Create `config.yaml` in workspace directory:

```yaml
# Workspace configuration
workspace:
  path: /forensics/workspace
  case_retention_days: 365

# Logging configuration
logging:
  level: INFO
  file: forensic.log
  max_size: 10485760  # 10MB
  backup_count: 5

# Evidence handling
evidence:
  auto_hash: true
  hash_algorithms:
    - sha256
    - md5
  verify_integrity: true

# Chain of Custody
coc:
  require_actor: true
  auto_log_events: true
  signature_required: false

# Module configuration
modules:
  acquisition:
    disk_imaging:
      default_format: e01
      compression: fast
      split_size: 2GB
  
  analysis:
    filesystem:
      max_depth: 10
      follow_symlinks: false
    
    ioc_scan:
      default_ioc_file: indicators.json
      parallel_scan: true
    
    memory:
      volatility_path: /usr/bin/vol
      default_profile: auto
    
    registry:
      use_regripper: true
    
    network:
      extract_files: true
      suspicious_ports:
        - 4444
        - 5555
        - 6666

# Reporting
reporting:
  default_format: html
  include_executive_summary: true
  include_timeline: true
  include_coc: true
```

---

## 🔧 Development

### Adding Custom Modules

```python
from forensic.core.module import AnalysisModule, ModuleResult
from forensic.core.evidence import Evidence

class CustomAnalysisModule(AnalysisModule):
    @property
    def name(self) -> str:
        return "custom_analysis"
    
    @property
    def description(self) -> str:
        return "Custom analysis module"
    
    @property
    def requires_root(self) -> bool:
        return False
    
    def validate_params(self, params: dict) -> bool:
        return 'target' in params
    
    def run(self, evidence: Evidence, params: dict) -> ModuleResult:
        # Your analysis logic here
        findings = []
        
        # ... perform analysis ...
        
        return ModuleResult(
            result_id=self._generate_result_id(),
            module_name=self.name,
            status="success",
            findings=findings
        )
```

### Registering Modules

```python
from forensic.core.framework import ForensicFramework

framework = ForensicFramework()
framework.register_module('custom_analysis', CustomAnalysisModule)
```

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_framework.py -v

# Run with coverage
pytest tests/ --cov=forensic --cov-report=html

# Run specific test class
pytest tests/test_modules.py::TestFilesystemAnalysisModule -v
```

### Test Structure

```
tests/
├── test_framework.py      # Core framework tests
├── test_modules.py         # Module tests
├── test_evidence.py        # Evidence management tests
├── test_coc.py            # Chain of custody tests
└── fixtures/              # Test data
```

---

## 📈 Project Status

**Version:** 2.0  
**Completion:** 75%

### ✅ Completed Components
- Core framework architecture
- Case management system
- Evidence management
- Chain of Custody tracking
- Filesystem analysis module
- IoC scanning module
- Timeline generation module
- Memory analysis module
- Registry analysis module
- Network analysis module
- Quick triage module
- Report generation (HTML, PDF, JSON, Markdown)
- CLI interface
- Test suite (core + modules)

### 🚧 In Progress
- Memory dump acquisition module
- Advanced YARA integration
- Cloud evidence acquisition

### 📋 Planned Features
- Web UI dashboard
- Multi-user support
- Case collaboration features
- Advanced malware analysis
- Mobile forensics support
- Cloud forensics (AWS, Azure, GCP)
- Docker container analysis

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/yourusername/forensic-playbook-v2.git
cd forensic-playbook-v2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/forensic-playbook-v2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/forensic-playbook-v2/discussions)

---

## 🙏 Acknowledgments

- Volatility Foundation for memory forensics tools
- The Sleuth Kit project
- YARA project
- Wireshark/tshark developers
- Digital forensics community

---

## 📚 References

- [NIST Guide to Integrating Forensic Techniques](https://www.nist.gov/publications)
- [SANS Digital Forensics Resources](https://www.sans.org/digital-forensics)
- [Volatility Documentation](https://volatility3.readthedocs.io)
- [The Sleuth Kit Documentation](https://www.sleuthkit.org/sleuthkit/docs.php)

---

**Forensic-Playbook v2.0** - Professional Digital Forensics Framework  
© 2025 | Built with ❤️ for the digital forensics community
