# Getting Started with Forensic-Playbook v2.0

**Quick Start Guide for Forensic Investigators**

---

## 🚀 Installation

### Prerequisites

**Operating System:**
- Kali Linux (recommended)
- Ubuntu 20.04+ 
- Debian 11+

**Python:**
- Python 3.10 or higher

**Forensic Tools:**
```bash
# On Kali Linux (most tools pre-installed)
sudo apt update
sudo apt install -y \
    sleuthkit \
    ddrescue \
    ewf-tools \
    plaso-tools \
    yara \
    python3-pip \
    python3-venv
```

### Framework Installation

```bash
# Clone repository
git clone https://github.com/your-org/Forensic-Playbook.git
cd Forensic-Playbook

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install framework
pip install -e .

# Verify installation
forensic-cli version
forensic-cli check-tools
```

> **Fixture policy:** PCAP-Fixtures werden zur Laufzeit über einen Synthesizer
> erzeugt. Falls das nicht möglich ist, nutzt die CLI JSON-Fallbacks – dadurch
> benötigen wir keine Binär-Fixtures im Repository und vermeiden Plattform-
> Abweichungen.

---

## 📖 Basic Concepts

### Case Structure

Every investigation is organized as a **Case**:
- Unique Case ID
- Evidence collection
- Analysis results
- Chain of Custody log
- Reports

### Module Types

1. **Acquisition** - Collect evidence (disk imaging, memory dump)
2. **Analysis** - Examine evidence (filesystem, timeline, IoCs)
3. **Triage** - Quick assessment (system info, persistence)
4. **Reporting** - Generate reports (HTML, PDF, JSON)

---

## 🎯 Quick Start Workflows

### Scenario 1: Disk Forensics Investigation

**Objective:** Analyze a suspect disk image for malware indicators

```bash
# Step 1: Create case
forensic-cli case create "Malware Investigation 2025-001" \
    --investigator "John Smith" \
    --description "Suspected ransomware on workstation"

# Step 2: Add evidence (disk image)
forensic-cli evidence add /path/to/disk.img \
    --type disk \
    --description "Suspect workstation C: drive"

# Step 3: Filesystem analysis
forensic-cli module run filesystem_analysis \
    --param image=/path/to/disk.img \
    --param include_deleted=true \
    --param compute_hashes=true

# Step 4: IoC scan
forensic-cli module run ioc_scan \
    --param path=/mnt/evidence \
    --param ioc_file=config/iocs/IoCs.json \
    --param timeline=true \
    --param scan_npm=true \
    --param format=json

# Step 5: Generate timeline
forensic-cli module run timeline \
    --param source=/path/to/disk.img \
    --param format=csv \
    --param type=plaso

# Step 6: Generate report
forensic-cli report --format html
```

**Results Location:**
```
forensic_workspace/
└── cases/
    └── CASE_20251008_120000/
        ├── evidence/
        ├── analysis/
        │   ├── filesystem_analysis/
        │   │   ├── file_list.json
        │   │   └── file_hashes.json
        │   ├── ioc_scan/
        │   │   └── ioc_scan_results.json
        │   └── timeline/
        │       └── timeline.csv
        └── reports/
            └── report_20251008_120500.html
```

---

### Scenario 2: Quick Triage (No Case Setup)

**Objective:** Rapid assessment of mounted filesystem

```bash
# Quick triage command
forensic-cli quick-triage /mnt/suspect_system \
    --name "Quick Triage 2025-001" \
    --investigator "Jane Doe"
```

**Output:**
- SUID/SGID binaries
- User accounts
- Persistence mechanisms
- SSH keys
- Recent files
- Suspicious files
- Network config
- Log summary

---

### Scenario 3: IoC Hunting

**Objective:** Scan system for known IoCs

```bash
# Standalone IoC scan
forensic-cli ioc-scan /mnt/evidence \
    config/iocs/IoCs.json \
    --format json \
    --timeline \
    --scan-npm \
    --out-file results.json
```

**IoC File Format (`config/iocs/IoCs.json`):**
```json
[
  {
    "type": "domain",
    "value": "evil[.]com",
    "tags": ["apt28", "phishing"],
    "comment": "Known C2 domain"
  },
  {
    "type": "ip",
    "value": "192.0.2.1",
    "tags": ["scanning"]
  },
  {
    "type": "hash_sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tags": ["malware", "trojan"]
  }
]
```

---

### Scenario 4: Forensic Disk Imaging

**Objective:** Create forensically sound disk image

```bash
# Create case first
forensic-cli case create "Disk Imaging - Server01" \
    --investigator "Forensic Team"

# Image disk with verification
sudo forensic-cli module run disk_imaging \
    --param source=/dev/sdb \
    --param output=evidence/server01_disk.img \
    --param tool=ddrescue \
    --param hash_algorithm=sha256 \
    --param retries=3
```

**Features:**
- Automatic hash verification
- Bad sector recovery
- Device metadata capture
- Chain of Custody logging

---

## 🔍 Module Reference

### Available Modules

```bash
# List all modules
forensic-cli module list
```

**Current Modules:**
- `disk_imaging` - Forensic disk imaging
- `filesystem_analysis` - Filesystem analysis with Sleuthkit
- `ioc_scan` - IoC detection
- `timeline` - Timeline generation
- `quick_triage` - System triage

### Module Parameters

#### **disk_imaging**
```bash
--param source=/dev/sdb              # Required: Source device
--param output=disk.img              # Required: Output file
--param tool=ddrescue                # Optional: dd|ddrescue|ewfacquire
--param hash_algorithm=sha256        # Optional: sha256|sha1|md5
--param block_size=4M                # Optional: Block size
--param skip_verify=false            # Optional: Skip hash verification
```

#### **filesystem_analysis**
```bash
--param image=disk.img               # Required: Disk image
--param partition=0                  # Optional: Partition number
--param include_deleted=true         # Optional: Include deleted files
--param extract_strings=false        # Optional: Extract strings
--param compute_hashes=false         # Optional: Compute file hashes
--param max_depth=0                  # Optional: Max directory depth
```

#### **ioc_scan**
```bash
--param path=/mnt/evidence           # Required: Scan path
--param ioc_file=IoCs.json           # Required: IoC file
--param timeline=false               # Optional: Timeline correlation
--param extract_strings=false        # Optional: Extract from binaries
--param hash_files=false             # Optional: Hash matching files
--param scan_npm=false               # Optional: Scan npm packages
--param format=json                  # Optional: json|csv|sarif|text
```

#### **timeline**
```bash
--param source=/mnt/evidence         # Required: Evidence source
--param format=csv                   # Optional: csv|l2tcsv|json
--param type=auto                    # Optional: auto|plaso|mactime|simple
--param start_date=2025-01-01        # Optional: Filter start date
--param end_date=2025-12-31          # Optional: Filter end date
--param include_mft=true             # Optional: Include MFT
--param include_browser=true         # Optional: Browser history
```

#### **quick_triage**
```bash
--param target=/mnt/evidence         # Required: Target system
```

---

## 📊 Working with Results

### JSON Output

All modules output structured JSON:

```json
{
  "result_id": "module_20251008_120000",
  "module_name": "ioc_scan",
  "status": "success",
  "timestamp": "2025-10-08T12:00:00Z",
  "findings": [
    {
      "type": "ioc_match",
      "ioc_type": "domain",
      "ioc_value": "evil.com",
      "file_path": "/var/log/syslog",
      "line_number": 42,
      "context": "DNS query to evil.com",
      "timestamp": "2025-10-08T11:30:00Z"
    }
  ],
  "metadata": {
    "total_matches": 5,
    "files_scanned": 1234
  }
}
```

### Accessing Results

```bash
# View results
cat forensic_workspace/cases/CASE_*/analysis/ioc_scan/ioc_scan_results.json | jq .

# Count findings
jq '.findings | length' results.json

# Filter by type
jq '.findings[] | select(.ioc_type == "domain")' results.json

# Export to CSV
jq -r '.findings[] | [.ioc_type, .ioc_value, .file_path] | @csv' results.json
```

---

## 🔒 Chain of Custody

All evidence handling is automatically logged:

```bash
# View Chain of Custody
sqlite3 forensic_workspace/chain_of_custody.db \
    "SELECT * FROM coc_events WHERE case_id='CASE_20251008_120000'"
```

**Logged Events:**
- `CASE_CREATED`
- `EVIDENCE_ADDED`
- `MODULE_EXECUTION_START`
- `MODULE_EXECUTION_COMPLETE`
- `EVIDENCE_MODIFIED`
- `REPORT_GENERATED`

---

## 🐛 Troubleshooting

### Module Not Found

```bash
# List available modules
forensic-cli module list

# Check module registration in forensic/cli.py
```

### Permission Denied

```bash
# Some modules require root (disk imaging)
sudo forensic-cli module run disk_imaging ...
```

### Tool Not Found

```bash
# Check tool availability
forensic-cli check-tools

# Install missing tools
sudo apt install sleuthkit plaso-tools
```

### No Results from Module

```bash
# Check module logs
cat forensic_workspace/logs/forensic_*.log

# Verify parameters
forensic-cli module run MODULE_NAME --param key=value
```

---

## 📚 Advanced Usage

### Custom IoC Lists

Create custom IoC files:

```json
[
  {
    "type": "domain",
    "value": "suspicious[.]site",
    "tags": ["custom", "internal"],
    "source": "Internal Threat Intel",
    "comment": "Phishing campaign 2025-Q1"
  }
]
```

### Multiple Evidence Sources

```bash
# Create case
forensic-cli case create "Multi-Evidence Case"

# Add multiple evidence items
forensic-cli evidence add disk1.img --type disk
forensic-cli evidence add memory.dmp --type memory
forensic-cli evidence add capture.pcap --type network

# Run analysis on each
forensic-cli module run filesystem_analysis --param image=disk1.img
forensic-cli module run ioc_scan --param path=/mnt/disk1
```

### Case Management

```bash
# List all cases
forensic-cli case list

# Load existing case
forensic-cli case load CASE_20251008_120000

# Continue investigation
forensic-cli module run timeline --param source=/mnt/evidence
```

---

## 🎓 Next Steps

### Learn More
- Read `/docs/modules/` for detailed module documentation
- Check `/docs/examples/` for complete workflows
- Review `/docs/api/` for API reference

### Contribute
- Add custom modules in `forensic/modules/`
- Share IoC lists in `config/iocs/`
- Report bugs on GitHub Issues

### Advanced Features (Coming Soon)
- Pipeline automation (YAML workflows)
- Memory forensics (Volatility integration)
- Network analysis (PCAP dissection)
- Malware analysis (YARA scanning)
- Reporting engine (HTML/PDF)

---

## 📞 Support

- **Documentation:** `/docs/`
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Email:** forensic-playbook@example.com

---

**Happy Investigating! 🔍**
