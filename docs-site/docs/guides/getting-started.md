<!-- AUTODOC:BEGIN -->
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
forensic-cli diagnostics --summary
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

### Module Types & Guard Levels

1. **Acquisition** – Collect evidence (disk imaging, memory dump, live response)
2. **Analysis** – Examine evidence (filesystem, timeline, network)
3. **Triage** – Quick assessment (system info, persistence, quick triage)
4. **Reporting** – Generate reports (HTML baseline, optional PDF)

Each module advertises a **Guard level** in the CLI. A Guarded module performs
pre-flight checks (tool availability, privileges, dry-run) before touching
evidence. Missing prerequisites result in a friendly message instead of a
traceback.

### Configuration defaults

Parameters come from three tiers: built-in defaults, YAML configuration
(`config/framework.yaml` and `config/modules/*.yaml`) and CLI `--param` options.
CLI values always win. The resolved configuration is written to the case
metadata and to `meta/provenance.jsonl`.

### Dry-run support

Most Guarded modules accept `--dry-run`. In this mode the CLI prints the steps
that would be executed and exits without producing artefacts. Use this whenever
you validate configuration or run exercises on development machines.

### Optional: Codex/MCP (Forensic Mode)

Codex baut auf denselben Guard-Schritten wie der CLI/SDK-Weg auf. Planen Sie zuerst alle Aktionen als Dry-Run und halten Sie Freigaben schriftlich fest.

```bash
forensic-cli codex install --dry-run
forensic-cli codex start --foreground --dry-run
forensic-cli mcp expose --json
```

Nutzen Sie anschließend `forensic-cli mcp run diagnostics.ping --local --json`, um Adapter lokal zu testen. Ausführliche Workflows finden Sie in `docs/mcp/codex-workflow.md`, die Guardrails in `docs/mcp/forensic-mode.md`.

## 🎯 Quick Start Workflows

### Scenario 1: Disk & Network Investigation (Guarded Modules)

**Objective:** Acquire evidence and correlate disk/network artefacts while
respecting guard rails.

```bash
# Step 1: Create workspace + case (records provenance metadata)
forensic-cli --workspace ~/forensic cases init
forensic-cli --workspace ~/forensic case create \
    "Malware Investigation 2025-001" \
    --investigator "John Smith" \
    --description "Suspected ransomware on workstation"

# Step 2: Review module guards and defaults
forensic-cli --workspace ~/forensic diagnostics

# Step 3: Plan live acquisitions safely
forensic-cli --workspace ~/forensic modules run live_response \
    --case Malware\ Investigation\ 2025-001 \
    --dry-run

forensic-cli --workspace ~/forensic modules run network_capture \
    --case Malware\ Investigation\ 2025-001 \
    --dry-run \
    --param interface=eth0

# Step 4: Execute disk imaging when ready
sudo forensic-cli --workspace ~/forensic modules run disk_imaging \
    --case Malware\ Investigation\ 2025-001 \
    --param source=/dev/sdb \
    --param output=evidence/disk.img

# Step 5: Analyse network data with runtime PCAP fixtures
forensic-cli --workspace ~/forensic modules run network \
    --case Malware\ Investigation\ 2025-001 \
    --param pcap-json=-

# Step 6: Generate HTML report (PDF optional)
forensic-cli --workspace ~/forensic report generate \
    --case Malware\ Investigation\ 2025-001 \
    --fmt html
```

**Notes:**

- When a native PCAP capture is unavailable the network module accepts JSON
  flow data via `--param pcap-json=-`. The CLI feeds runtime synthesised data or
  uses JSON fallbacks in CI.
- Every module invocation appends a record to `meta/provenance.jsonl`, including
  resolved parameters and artefact hashes.
- PDF exports require the optional `report_pdf` extra. Without it the HTML
  report is still generated and the skipped renderer is documented.

---

### Scenario 2: Quick Triage Snapshot

**Objective:** Capture persistence and system information from a mounted target
without modifying it.

```bash
forensic-cli --workspace ~/forensic modules run quick_triage \
  --case Malware\ Investigation\ 2025-001 \
  --param target=/mnt/suspect_system \
  --dry-run

# When satisfied with the plan, rerun without --dry-run.
forensic-cli --workspace ~/forensic modules run quick_triage \
  --case Malware\ Investigation\ 2025-001 \
  --param target=/mnt/suspect_system
```

The module consolidates SUID/SGID binaries, suspicious startup entries and
recent file changes. All artefacts are stored under
`cases/<case-id>/analysis/quick_triage/` with hashes in the chain-of-custody log.

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

### Scenario 7: Router Artefact Collection (Guarded Python Modules)

**Objective:** Guard router forensics with deterministic Python modules that
mirror the legacy scripts while keeping dry-run previews the default.

```bash
# Dry-run the full workflow first (no filesystem writes)
forensic-cli router env init --case demo_case --dry-run
forensic-cli router extract ui --case demo_case --param input=./evidence/router_exports --dry-run
forensic-cli router manifest write --case demo_case --param source=./cases/demo_case/router/20240101T000000Z --dry-run
forensic-cli router summarize --case demo_case --param source=./cases/demo_case/router/20240101T000000Z --dry-run

# When satisfied, run without --dry-run (still using synthetic fixtures)
forensic-cli router extract ui --case demo_case --param input=./evidence/router_exports --no-dry-run
forensic-cli router manifest write --case demo_case --param source=./cases/demo_case/router/20240101T000000Z --no-dry-run
forensic-cli router summarize --case demo_case --param source=./cases/demo_case/router/20240101T000000Z --no-dry-run
```

**Notes:**

- Router commands honour **CLI > YAML > built-in defaults**. Edit
  `config/modules/router/*.yaml` for team-wide defaults.
- All regression tests use text/JSON fixtures created at runtime—binary PCAPs or
  firmware dumps stay out of scope for CI.
- Reuse the timestamped extraction directory reported by `router extract ui`
  when calling `router manifest write` and `router summarize`.
- Use `--legacy` on each sub-command if you need to compare against the Bash
  originals during validation.

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
<!-- AUTODOC:END -->
