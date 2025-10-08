# Forensic-Playbook v2.0

Professional Digital Forensics Investigation Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Overview

Forensic-Playbook is a comprehensive, modular digital forensics framework designed for incident response, forensic investigations, and security analysis. It integrates industry-standard tools (Sleuthkit, Volatility, Autopsy, plaso) with custom analysis modules in a unified, scriptable interface.

### Key Features

- **Modular Architecture**: Plug-and-play forensic modules
- **Case Management**: Complete case tracking with Chain of Custody
- **Evidence Handling**: Secure evidence acquisition and management
- **Pipeline Execution**: Automated analysis workflows
- **Tool Integration**: Wraps popular forensic tools (TSK, Volatility, YARA, etc.)
- **Multiple Output Formats**: JSON, CSV, HTML, PDF reports
- **Extensible**: Easy to add custom modules and tools
- **Standalone & Framework Mode**: Scripts work independently or as integrated framework

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/Forensic-Playbook.git
cd Forensic-Playbook

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .

# Verify installation
./scripts/forensic-cli.py version
./scripts/forensic-cli.py check-tools
```

### Basic Usage

```bash
# 1. Create a case
./scripts/forensic-cli.py case create "Incident-2025-001" \
    --investigator "John Doe" \
    --description "Suspected malware infection"

# 2. Add evidence
./scripts/forensic-cli.py evidence add /mnt/evidence/disk.img \
    --type disk \
    --description "Suspect workstation image"

# 3. Run analysis module
./scripts/forensic-cli.py module run ioc_scan \
    --param ioc_file=config/iocs/IoCs.json \
    --param timeline=true

# 4. Generate report
./scripts/forensic-cli.py report --format html
```

### Quick Triage (No Case Setup)

```bash
# Quick IoC scan
./scripts/forensic-cli.py ioc-scan /mnt/evidence \
    config/iocs/IoCs.json \
    --format json \
    --output results.json

# Quick system triage
./scripts/forensic-cli.py quick-triage /mnt/evidence \
    --investigator "John Doe"
```

## 📁 Architecture

### Directory Structure

```
Forensic-Playbook/
├── forensic/              # Python package
│   ├── core/              # Framework core
│   ├── modules/           # Forensic modules
│   │   ├── acquisition/   # Data acquisition
│   │   ├── analysis/      # Analysis modules
│   │   ├── triage/        # Quick triage
│   │   └── reporting/     # Report generation
│   ├── tools/             # Tool wrappers
│   └── utils/             # Utilities
├── scripts/               # Standalone scripts
├── pipelines/             # Predefined workflows
├── config/                # Configuration
└── docs/                  # Documentation
```

### Module Categories

#### Acquisition
- **disk_imaging**: Forensic disk imaging (dd, ddrescue, ewfacquire)
- **memory_dump**: RAM acquisition (LiME, AVML, DumpIt)
- **network_capture**: Packet capture (tcpdump, Wireshark)
- **live_response**: Volatile data collection

#### Analysis
- **filesystem**: Filesystem analysis (Sleuthkit)
- **memory**: Memory analysis (Volatility 2/3)
- **network**: Network traffic analysis
- **timeline**: Timeline generation (plaso)
- **ioc_scanning**: IoC detection
- **malware**: Malware analysis (YARA, strings)

#### Triage
- **quick_triage**: Rapid assessment
- **persistence**: Persistence mechanism detection
- **system_info**: System information gathering

## 🔧 Modules

### IoC Scanner Module

Comprehensive IoC scanning with multiple detection methods:

```bash
# Standalone usage
python3 forensic/modules/analysis/ioc_scan.py \
    --path /mnt/evidence \
    --ioc-file config/iocs/IoCs.json \
    --format json \
    --timeline \
    --extract-strings \
    --scan-npm

# Framework usage
./scripts/forensic-cli.py module run ioc_scan \
    --param path=/mnt/evidence \
    --param ioc_file=config/iocs/IoCs.json \
    --param format=json
```

**Features:**
- Detects defanged domains ([.])
- Base64/hex-encoded IoCs
- Timeline correlation from logs
- npm/yarn/pnpm malicious package detection
- Multiple output formats (JSON, CSV, SARIF)
- File hashing of matches

### Disk Imaging Module

Forensic disk imaging with verification:

```bash
./scripts/forensic-cli.py module run disk_imaging \
    --param source=/dev/sdb \
    --param output=evidence/disk.img \
    --param tool=ddrescue \
    --param hash_algorithm=sha256
```

**Features:**
- Multiple tools (dd, ddrescue, ewfacquire)
- Automatic hash verification
- Bad sector recovery and logging
- Device metadata capture

### Timeline Module

Create forensic timelines:

```bash
./scripts/forensic-cli.py module run timeline \
    --param source=/mnt/evidence \
    --param output=timeline.csv \
    --param format=supertimeline
```

## 📋 Pipelines

Pipelines define automated workflows. Example:

```yaml
# pipelines/incident_response.yaml
name: "Incident Response Pipeline"
description: "Complete IR workflow"

modules:
  - name: disk_imaging
    params:
      source: /dev/sdb
      output: evidence/disk.img
      tool: ddrescue
    
  - name: quick_triage
    params:
      target: evidence/disk.img
  
  - name: ioc_scan
    params:
      path: evidence/disk.img
      ioc_file: config/iocs/IoCs.json
      timeline: true
  
  - name: timeline
    params:
      source: evidence/disk.img
      output: timeline.csv
  
  - name: memory_analysis
    params:
      dump: evidence/memory.dmp
      profile: Win10x64
```

**Execute pipeline:**
```bash
./scripts/forensic-cli.py pipeline pipelines/incident_response.yaml
```

## 🛠️ Tool Integration

### Supported Tools

The framework integrates with industry-standard forensic tools:

| Category | Tools |
|----------|-------|
| **Disk Forensics** | Sleuthkit (fls, icat, mmls), Autopsy, ewftools |
| **Memory Forensics** | Volatility 2/3, LiME, AVML |
| **Network Forensics** | Wireshark, tshark, tcpdump, NetworkMiner |
| **Timeline** | plaso (log2timeline), mactime |
| **Malware Analysis** | YARA, ClamAV, strings, binwalk |
| **File Carving** | Foremost, Scalpel, PhotoRec |
| **Analysis** | Bulk Extractor, RegRipper |

### Installing Forensic Tools (Kali Linux)

```bash
# Core forensic tools
sudo apt update
sudo apt install -y \
    sleuthkit autopsy \
    volatility volatility3 \
    plaso-tools \
    yara \
    clamav \
    bulk-extractor \
    foremost scalpel \
    binwalk \
    ewf-tools \
    libewf-dev \
    ddrescue \
    wireshark tshark

# Python forensic libraries
pip install volatility3 yara-python

# Check installation
./scripts/forensic-cli.py check-tools
```

## 📝 Configuration

### Framework Configuration

`config/framework.yaml`:

```yaml
# Logging
log_level: INFO

# Execution
parallel_execution: true
max_workers: 4

# Evidence
hash_algorithm: sha256
enable_coc: true

# Output
output_formats:
  - json
  - html
  
# Tool paths (optional)
tools:
  volatility: /usr/bin/vol.py
  autopsy: /usr/bin/autopsy
```

### IoC Configuration

`config/iocs/IoCs.json`:

```json
[
  {
    "type": "domain",
    "value": "evil[.]com",
    "tags": ["apt28", "phishing"],
    "source": "ThreatFeed",
    "comment": "Known C2 domain"
  },
  {
    "type": "ip",
    "value": "192.0.2.1",
    "tags": ["scanning"],
    "comment": "Malicious scanner"
  },
  {
    "type": "hash_sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tags": ["malware", "trojan"]
  }
]
```

## 🔐 Chain of Custody

All evidence handling is automatically logged:

```bash
# View chain of custody
sqlite3 forensic_workspace/chain_of_custody.db \
    "SELECT * FROM events WHERE case_id='CASE_20251008_143000'"
```

**Logged events:**
- CASE_CREATED
- EVIDENCE_ADDED
- MODULE_EXECUTION_START
- MODULE_EXECUTION_COMPLETE
- EVIDENCE_MODIFIED
- REPORT_GENERATED

## 📊 Reporting

### Generate Reports

```bash
# HTML report
./scripts/forensic-cli.py report --format html --output report.html

# PDF report (requires wkhtmltopdf)
./scripts/forensic-cli.py report --format pdf --output report.pdf

# JSON export
./scripts/forensic-cli.py report --format json --output report.json
```

### Report Contents

- Executive summary
- Case metadata
- Evidence inventory
- Analysis results
- Timeline visualization
- Findings summary
- Chain of custody log

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test category
pytest tests/unit/ -v
pytest tests/integration/ -v

# With coverage
pytest tests/ --cov=forensic --cov-report=html
```

## 🔌 Creating Custom Modules

Example custom module:

```python
# forensic/modules/analysis/my_module.py
from forensic.core.module import AnalysisModule, ModuleResult
from pathlib import Path
from typing import Dict, Optional
from forensic.core.evidence import Evidence

class MyCustomModule(AnalysisModule):
    @property
    def name(self) -> str:
        return "my_custom_module"
    
    @property
    def description(self) -> str:
        return "My custom analysis module"
    
    def validate_params(self, params: Dict) -> bool:
        # Validate required parameters
        return 'target' in params
    
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        # Your analysis logic here
        findings = []
        
        # ... perform analysis ...
        
        return ModuleResult(
            result_id=self._generate_result_id(),
            module_name=self.name,
            status="success",
            timestamp=self._get_timestamp(),
            findings=findings,
            metadata={'custom_field': 'value'}
        )
```

**Register and use:**

```python
# In forensic-cli.py or custom script
from forensic.modules.analysis.my_module import MyCustomModule

framework.register_module('my_custom_module', MyCustomModule)
framework.execute_module('my_custom_module', params={'target': '/path'})
```

## 📚 Examples

### Example 1: Disk Forensics Workflow

```bash
# 1. Create case
./scripts/forensic-cli.py case create "Disk Analysis" \
    --investigator "Jane Investigator"

# 2. Image disk
./scripts/forensic-cli.py module run disk_imaging \
    --param source=/dev/sdb \
    --param output=disk.img \
    --param tool=ddrescue

# 3. Filesystem analysis
./scripts/forensic-cli.py module run filesystem \
    --param image=disk.img

# 4. IoC scan
./scripts/forensic-cli.py module run ioc_scan \
    --param path=disk.img \
    --param ioc_file=config/iocs/IoCs.json

# 5. Timeline generation
./scripts/forensic-cli.py module run timeline \
    --param source=disk.img

# 6. Generate report
./scripts/forensic-cli.py report --format html
```

### Example 2: Memory Forensics

```bash
# Create case and add memory dump
./scripts/forensic-cli.py case create "Memory Analysis" \
    --investigator "John Analyst"

./scripts/forensic-cli.py evidence add memory.dmp \
    --type memory \
    --description "Suspect workstation RAM dump"

# Memory analysis
./scripts/forensic-cli.py module run memory_analysis \
    --param dump=memory.dmp \
    --param profile=Win10x64_19041
```

### Example 3: Network Forensics

```bash
# Analyze PCAP file
./scripts/forensic-cli.py case create "Network Investigation" \
    --investigator "Network Analyst"

./scripts/forensic-cli.py evidence add capture.pcap \
    --type network \
    --description "Suspicious network traffic"

./scripts/forensic-cli.py module run network_analysis \
    --param pcap=capture.pcap \
    --param extract_files=true
```

## 🐛 Troubleshooting

### Common Issues

**Module not found:**
```bash
# Ensure module is registered
./scripts/forensic-cli.py module list
```

**Permission denied:**
```bash
# Some modules require root
sudo ./scripts/forensic-cli.py module run disk_imaging ...
```

**Tool not found:**
```bash
# Check tool installation
./scripts/forensic-cli.py check-tools

# Install missing tools
sudo apt install sleuthkit volatility
```

## 📖 Documentation

- [Getting Started Guide](docs/getting_started.md)
- [Module Documentation](docs/modules/)
- [API Reference](docs/api/)
- [Development Guide](docs/development.md)
- [Examples](docs/examples/)

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

Areas for contribution:
- New forensic modules
- Tool integrations
- Bug fixes
- Documentation
- Test cases

## 📄 License

MIT License - see [LICENSE](LICENSE)

## 🙏 Acknowledgments

This framework integrates and wraps the following excellent open-source projects:

- [The Sleuth Kit](https://www.sleuthkit.org/)
- [Volatility Framework](https://www.volatilityfoundation.org/)
- [Plaso / Log2timeline](https://github.com/log2timeline/plaso)
- [YARA](https://virustotal.github.io/yara/)
- [Autopsy](https://www.autopsy.com/)

## 📞 Support

- Issues: [GitHub Issues](https://github.com/your-org/Forensic-Playbook/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/Forensic-Playbook/discussions)

## 🗺️ Roadmap

- [ ] Cloud forensics modules (AWS, Azure, GCP)
- [ ] Mobile forensics (Android, iOS)
- [ ] Container forensics (Docker, Kubernetes)
- [ ] Web UI dashboard
- [ ] AI-powered anomaly detection
- [ ] Distributed analysis support
- [ ] Real-time streaming analysis

---

**Made with 🔍 for the forensic community**
