#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ioc_scan.py — Unified IoC Scanner for Forensic Analysis

Features:
- Scans filesystems, logs, npm/yarn/pnpm lockfiles for IoCs
- Supports defanged domains ([.]), base64, hex-encoded IoCs
- Timeline correlation (extracts timestamps from logs)
- Multiple output formats: JSON, CSV, SARIF
- File hashing (optional)
- Fully offline-capable (no network calls)
- Modular design for integration into other tools

Usage:
    python3 ioc_scan.py --path /mnt/evidence --ioc-file IoCs.json \\
        --format json --timeline --extract-strings --hash-files \\
        --out-dir ./output

Author: Forensic-Playbook Contributors
License: MIT
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ============================================================================
# Configuration & Constants
# ============================================================================

VERSION = "2.0.0"
DEFAULT_EXCLUDES = [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/__pycache__/**",
]

MALICIOUS_NPM_PACKAGES = {
    "ansi-styles": {"6.2.2"},
    "strip-ansi": {"7.1.1"},
    "ansi-regex": {"6.2.1"},
    "debug": {"4.4.2"},
    "color-convert": {"3.1.1"},
    "color-name": {"2.0.1"},
    "supports-color": {"10.2.1"},
    "chalk": {"5.6.1"},
    "wrap-ansi": {"9.0.1"},
    "slice-ansi": {"7.1.1"},
    "color": {"5.0.1"},
}

# Timestamp patterns for log parsing
TIMESTAMP_PATTERNS = [
    # ISO 8601
    re.compile(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'),
    # Syslog: Oct  8 07:49:02
    re.compile(r'\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b'),
    # Common log: [08/Oct/2025:14:32:10 +0000]
    re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]'),
]

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class IoC:
    """Represents a single Indicator of Compromise"""
    type: str  # domain, ip, hash, wallet, package, url
    value: str
    tags: List[str] = field(default_factory=list)
    source: Optional[str] = None
    comment: Optional[str] = None

@dataclass
class Match:
    """Represents a match of an IoC in a file"""
    ioc: IoC
    file_path: str
    line_number: Optional[int] = None
    context: Optional[str] = None
    timestamp: Optional[str] = None
    file_hash: Optional[str] = None

@dataclass
class ScanResult:
    """Complete scan results"""
    scan_id: str
    timestamp: str
    scan_path: str
    ioc_file: str
    matches: List[Match] = field(default_factory=list)
    npm_packages: List[Dict[str, str]] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)

# ============================================================================
# IoC Loading & Processing
# ============================================================================

class IoC LoadError(Exception):
    """Raised when IoC file cannot be loaded"""
    pass

def load_iocs(ioc_file: Path) -> List[IoC]:
    """
    Load IoCs from JSON or text file.
    
    JSON format:
        [
            {"type": "domain", "value": "evil.com", "tags": ["apt28"], "comment": "C2"},
            {"type": "ip", "value": "1.2.3.4"},
            ...
        ]
    
    Text format (legacy):
        evil.com
        1.2.3.4
        package@version
    """
    if not ioc_file.exists():
        raise IoCLoadError(f"IoC file not found: {ioc_file}")
    
    iocs = []
    
    # Try JSON first
    try:
        with open(ioc_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        iocs.append(IoC(
                            type=item.get('type', 'unknown'),
                            value=item.get('value', ''),
                            tags=item.get('tags', []),
                            source=item.get('source'),
                            comment=item.get('comment')
                        ))
                return iocs
    except (json.JSONDecodeError, KeyError):
        pass  # Fall through to text format
    
    # Text format (auto-detect type)
    with open(ioc_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            ioc_type = detect_ioc_type(line)
            iocs.append(IoC(type=ioc_type, value=line))
    
    return iocs

def detect_ioc_type(value: str) -> str:
    """Auto-detect IoC type from value"""
    value_lower = value.lower()
    
    # Package (contains @)
    if '@' in value and '/' not in value and not value.startswith('0x'):
        return 'package'
    
    # IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
    
    # URL
    if value.startswith(('http://', 'https://', 'ftp://')):
        return 'url'
    
    # Hash (SHA256=64 hex, MD5=32 hex)
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'hash_md5'
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'hash_sha256'
    
    # Crypto wallet
    if value.startswith(('1', '3', 'bc1')) and len(value) > 25:
        return 'wallet_btc'
    if value.startswith('0x') and len(value) == 42:
        return 'wallet_eth'
    if value.startswith('T') and len(value) == 34:
        return 'wallet_tron'
    if value.startswith('L') and len(value) == 34:
        return 'wallet_litecoin'
    if len(value) == 44 and value.replace('0-9A-Za-z', ''):
        return 'wallet_solana'
    
    # Domain (contains dot, no spaces)
    if '.' in value and ' ' not in value:
        return 'domain'
    
    return 'unknown'

def generate_ioc_variants(ioc: IoC) -> List[str]:
    """
    Generate variants of an IoC for matching:
    - Plain (refanged)
    - Defanged ([.] → .)
    - Base64-encoded
    - Hex-encoded
    """
    variants = []
    value = ioc.value
    
    # Refang (convert [.] to .)
    refanged = value.replace('[.]', '.').replace('(.)', '.')
    variants.append(refanged)
    
    # Keep original if defanged
    if '[.]' in value or '(.)' in value:
        variants.append(value)
    
    # Base64 variants
    try:
        import base64
        b64 = base64.b64encode(refanged.encode('utf-8')).decode('utf-8')
        variants.extend([b64, b64.rstrip('=')])
    except Exception:
        pass
    
    # Hex variant
    try:
        hex_val = refanged.encode('utf-8').hex()
        variants.append(hex_val)
    except Exception:
        pass
    
    return list(set(variants))

# ============================================================================
# File Scanning
# ============================================================================

def should_exclude(path: Path, excludes: List[str]) -> bool:
    """Check if path matches any exclusion pattern"""
    path_str = str(path)
    for pattern in excludes:
        if pattern.endswith('/**'):
            if pattern[:-3] in path_str:
                return True
        elif pattern.startswith('**/'):
            if pattern[3:] in path_str:
                return True
        else:
            if pattern in path_str:
                return True
    return False

def extract_strings(file_path: Path, min_length: int = 4) -> List[str]:
    """Extract printable strings from binary file"""
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            # Find sequences of printable ASCII (0x20-0x7E)
            pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            for match in re.finditer(pattern, data):
                strings.append(match.group().decode('latin-1'))
    except Exception:
        pass
    return strings

def scan_file_for_iocs(
    file_path: Path,
    iocs: List[IoC],
    ioc_variants: Dict[str, List[str]],
    extract_binary_strings: bool = False,
    hash_matches: bool = False,
    enable_timeline: bool = False
) -> List[Match]:
    """
    Scan a single file for IoC matches.
    
    Returns list of Match objects.
    """
    matches = []
    
    # Check if binary
    is_binary = False
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                is_binary = True
    except Exception:
        return matches
    
    # Binary file handling
    if is_binary:
        if not extract_binary_strings:
            return matches
        
        strings = extract_strings(file_path)
        for s in strings:
            s_lower = s.lower()
            for ioc in iocs:
                for variant in ioc_variants.get(ioc.value, [ioc.value]):
                    if variant.lower() in s_lower:
                        matches.append(Match(
                            ioc=ioc,
                            file_path=str(file_path),
                            context=s[:200]
                        ))
        return matches
    
    # Text file handling
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_lower = line.lower()
                
                for ioc in iocs:
                    for variant in ioc_variants.get(ioc.value, [ioc.value]):
                        if variant.lower() in line_lower:
                            timestamp = None
                            if enable_timeline:
                                timestamp = extract_timestamp(line)
                            
                            file_hash = None
                            if hash_matches:
                                file_hash = compute_file_hash(file_path)
                            
                            matches.append(Match(
                                ioc=ioc,
                                file_path=str(file_path),
                                line_number=line_num,
                                context=line.strip()[:500],
                                timestamp=timestamp,
                                file_hash=file_hash
                            ))
                            break  # Only count once per line
    except Exception:
        pass
    
    return matches

def extract_timestamp(line: str) -> Optional[str]:
    """Extract timestamp from log line"""
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            ts_str = match.group(1)
            try:
                # Try to parse to ISO format
                if 'T' in ts_str or len(ts_str) > 20:
                    # Already ISO-ish
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                else:
                    # Syslog format - add current year
                    from datetime import datetime as dt_module
                    year = dt_module.now().year
                    parts = ts_str.split()
                    dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                
                return dt.isoformat() + 'Z'
            except Exception:
                return ts_str
    return None

def compute_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
    """Compute file hash"""
    h = hashlib.sha256() if algorithm == 'sha256' else hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''

# ============================================================================
# NPM Package Scanning
# ============================================================================

def scan_npm_lockfiles(scan_path: Path) -> List[Dict[str, str]]:
    """
    Scan npm/yarn/pnpm lockfiles for known malicious packages.
    
    Returns list of dicts: [{"package": "name@version", "file": "path"}, ...]
    """
    findings = []
    
    for root, dirs, files in os.walk(scan_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if not should_exclude(Path(root) / d, DEFAULT_EXCLUDES)]
        
        for fname in files:
            fpath = Path(root) / fname
            
            if fname == "package-lock.json" or fname == "npm-shrinkwrap.json":
                findings.extend(scan_package_lock(fpath))
            elif fname == "yarn.lock":
                findings.extend(scan_yarn_lock(fpath))
            elif fname == "pnpm-lock.yaml":
                findings.extend(scan_pnpm_lock(fpath))
    
    return findings

def scan_package_lock(file_path: Path) -> List[Dict[str, str]]:
    """Scan npm package-lock.json for malicious packages"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return findings
    
    def check_deps(deps):
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version", ""))
            if name in MALICIOUS_NPM_PACKAGES and version in MALICIOUS_NPM_PACKAGES[name]:
                findings.append({
                    "package": f"{name}@{version}",
                    "file": str(file_path)
                })
            # Recurse
            if "dependencies" in info:
                check_deps(info["dependencies"])
    
    if "dependencies" in data:
        check_deps(data["dependencies"])
    
    if "packages" in data:
        for pkg_path, info in data.get("packages", {}).items():
            if not isinstance(info, dict):
                continue
            name = info.get("name")
            version = str(info.get("version", ""))
            if name and name in MALICIOUS_NPM_PACKAGES and version in MALICIOUS_NPM_PACKAGES[name]:
                findings.append({
                    "package": f"{name}@{version}",
                    "file": str(file_path)
                })
    
    return findings

def scan_yarn_lock(file_path: Path) -> List[Dict[str, str]]:
    """Scan yarn.lock for malicious packages"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception:
        return findings
    
    current_pkg = None
    for line in text.splitlines():
        line = line.rstrip()
        
        # Package declaration line
        if line and not line.startswith(' ') and line.endswith(':'):
            pkg_id = line[:-1].strip('"')
            if '@' in pkg_id:
                # Extract package name
                if pkg_id.startswith('@'):
                    # Scoped package
                    parts = pkg_id.split('@', 2)
                    if len(parts) >= 3:
                        current_pkg = '@' + parts[1]
                else:
                    current_pkg = pkg_id.split('@')[0]
        
        # Version line
        if line.strip().startswith('version'):
            parts = line.split()
            if len(parts) >= 2:
                version = parts[1].strip('"')
                if current_pkg and current_pkg in MALICIOUS_NPM_PACKAGES:
                    if version in MALICIOUS_NPM_PACKAGES[current_pkg]:
                        findings.append({
                            "package": f"{current_pkg}@{version}",
                            "file": str(file_path)
                        })
    
    return findings

def scan_pnpm_lock(file_path: Path) -> List[Dict[str, str]]:
    """Scan pnpm-lock.yaml for malicious packages"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception:
        return findings
    
    # Simple regex-based parsing (YAML parsing would require pyyaml)
    for line in text.splitlines():
        for pkg_name, versions in MALICIOUS_NPM_PACKAGES.items():
            for version in versions:
                if f"{pkg_name}@{version}" in line or f"{pkg_name}/{version}" in line:
                    findings.append({
                        "package": f"{pkg_name}@{version}",
                        "file": str(file_path)
                    })
    
    return findings

# ============================================================================
# Output Formatting
# ============================================================================

def format_json(result: ScanResult) -> str:
    """Format results as JSON"""
    return json.dumps(asdict(result), indent=2, default=str)

def format_csv(result: ScanResult) -> str:
    """Format results as CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['IoC Type', 'IoC Value', 'File Path', 'Line Number', 'Timestamp', 'File Hash', 'Context'])
    
    # Data rows
    for match in result.matches:
        writer.writerow([
            match.ioc.type,
            match.ioc.value,
            match.file_path,
            match.line_number or '',
            match.timestamp or '',
            match.file_hash or '',
            (match.context or '')[:100]
        ])
    
    return output.getvalue()

def format_sarif(result: ScanResult) -> str:
    """Format results as SARIF 2.1.0"""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ioc_scan.py",
                    "version": VERSION,
                    "informationUri": "https://github.com/your-org/Forensic-Playbook",
                    "rules": [
                        {
                            "id": "IOC_MATCH",
                            "name": "Indicator of Compromise Detected",
                            "shortDescription": {"text": "File contains known IoC"},
                            "fullDescription": {"text": "The file contains a known Indicator of Compromise from the provided IoC list."},
                            "defaultConfiguration": {"level": "error"}
                        }
                    ]
                }
            },
            "results": []
        }]
    }
    
    for match in result.matches:
        sarif["runs"][0]["results"].append({
            "ruleId": "IOC_MATCH",
            "level": "error",
            "message": {"text": f"IoC detected: {match.ioc.type} = {match.ioc.value}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": match.file_path},
                    "region": {
                        "startLine": match.line_number or 1
                    }
                }
            }],
            "properties": {
                "iocType": match.ioc.type,
                "iocValue": match.ioc.value,
                "timestamp": match.timestamp,
                "fileHash": match.file_hash,
                "context": match.context
            }
        })
    
    return json.dumps(sarif, indent=2)

# ============================================================================
# Main Scanner
# ============================================================================

def scan_directory(
    scan_path: Path,
    iocs: List[IoC],
    exclude_patterns: List[str],
    extract_binary_strings: bool = False,
    hash_matches: bool = False,
    enable_timeline: bool = False
) -> Tuple[List[Match], Dict[str, int]]:
    """
    Recursively scan directory for IoC matches.
    
    Returns:
        (matches, stats)
    """
    matches = []
    stats = defaultdict(int)
    
    # Pre-compute IoC variants
    ioc_variants = {}
    for ioc in iocs:
        ioc_variants[ioc.value] = generate_ioc_variants(ioc)
    
    # Walk directory
    for root, dirs, files in os.walk(scan_path):
        # Filter excluded directories
        dirs[:] = [d for d in dirs if not should_exclude(Path(root) / d, exclude_patterns)]
        
        for fname in files:
            fpath = Path(root) / fname
            
            if should_exclude(fpath, exclude_patterns):
                continue
            
            stats['files_scanned'] += 1
            
            file_matches = scan_file_for_iocs(
                fpath,
                iocs,
                ioc_variants,
                extract_binary_strings,
                hash_matches,
                enable_timeline
            )
            
            if file_matches:
                matches.extend(file_matches)
                stats['files_with_matches'] += 1
                stats['total_matches'] += len(file_matches)
    
    return matches, dict(stats)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Unified IoC Scanner for Forensic Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 ioc_scan.py --path /mnt/evidence --ioc-file IoCs.json

  # Full scan with all features
  python3 ioc_scan.py --path /mnt/evidence --ioc-file IoCs.json \\
      --format json --timeline --extract-strings --hash-files \\
      --out-dir ./output --scan-npm

  # CSV output with timeline
  python3 ioc_scan.py --path /var/log --ioc-file IoCs.json \\
      --format csv --timeline --out-file results.csv
        """
    )
    
    parser.add_argument('-p', '--path', type=Path, required=True,
                        help='Path to scan (directory or file)')
    parser.add_argument('-i', '--ioc-file', type=Path, required=True,
                        help='IoC file (JSON or text format)')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'sarif', 'text'],
                        default='text', help='Output format')
    parser.add_argument('-o', '--out-file', type=Path,
                        help='Output file (default: stdout)')
    parser.add_argument('--out-dir', type=Path,
                        help='Output directory for all artifacts')
    parser.add_argument('-t', '--timeline', action='store_true',
                        help='Enable timeline correlation')
    parser.add_argument('-x', '--extract-strings', action='store_true',
                        help='Extract strings from binary files')
    parser.add_argument('--hash-files', action='store_true',
                        help='Compute SHA256 hash of files with matches')
    parser.add_argument('--scan-npm', action='store_true',
                        help='Scan npm/yarn/pnpm lockfiles for malicious packages')
    parser.add_argument('--exclude', action='append',
                        help='Exclude patterns (can be used multiple times)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.path.exists():
        print(f"Error: Scan path does not exist: {args.path}", file=sys.stderr)
        return 1
    
    # Load IoCs
    try:
        iocs = load_iocs(args.ioc_file)
        if args.verbose:
            print(f"Loaded {len(iocs)} IoCs from {args.ioc_file}", file=sys.stderr)
    except IoCLoadError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Setup output directory
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    
    # Scan
    if args.verbose:
        print(f"Scanning: {args.path}", file=sys.stderr)
    
    exclude_patterns = args.exclude or DEFAULT_EXCLUDES
    matches, stats = scan_directory(
        args.path,
        iocs,
        exclude_patterns,
        args.extract_strings,
        args.hash_files,
        args.timeline
    )
    
    # NPM scan if requested
    npm_packages = []
    if args.scan_npm:
        if args.verbose:
            print("Scanning npm/yarn/pnpm lockfiles...", file=sys.stderr)
        npm_packages = scan_npm_lockfiles(args.path)
        stats['npm_malicious_packages'] = len(npm_packages)
    
    # Sort matches by timestamp if timeline enabled
    if args.timeline:
        matches.sort(key=lambda m: m.timestamp or '9999-12-31')
    
    # Create result object
    result = ScanResult(
        scan_id=f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        timestamp=datetime.utcnow().isoformat() + 'Z',
        scan_path=str(args.path),
        ioc_file=str(args.ioc_file),
        matches=matches,
        npm_packages=npm_packages,
        stats=stats
    )
    
    # Format output
    if args.format == 'json':
        output = format_json(result)
    elif args.format == 'csv':
        output = format_csv(result)
    elif args.format == 'sarif':
        output = format_sarif(result)
    else:  # text
        output = format_text(result)
    
    # Write output
    if args.out_file:
        args.out_file.write_text(output, encoding='utf-8')
        if args.verbose:
            print(f"Results written to: {args.out_file}", file=sys.stderr)
    else:
        print(output)
    
    # Summary
    if args.verbose:
        print(f"\nScan complete:", file=sys.stderr)
        print(f"  Files scanned: {stats.get('files_scanned', 0)}", file=sys.stderr)
        print(f"  Files with matches: {stats.get('files_with_matches', 0)}", file=sys.stderr)
        print(f"  Total matches: {stats.get('total_matches', 0)}", file=sys.stderr)
        if npm_packages:
            print(f"  Malicious npm packages: {len(npm_packages)}", file=sys.stderr)
    
    return 0 if not matches else 2  # Exit code 2 if IoCs found

def format_text(result: ScanResult) -> str:
    """Format results as human-readable text"""
    lines = []
    lines.append(f"=== IoC Scan Results ===")
    lines.append(f"Scan ID: {result.scan_id}")
    lines.append(f"Timestamp: {result.timestamp}")
    lines.append(f"Scan Path: {result.scan_path}")
    lines.append(f"IoC File: {result.ioc_file}")
    lines.append(f"\nStatistics:")
    for key, value in result.stats.items():
        lines.append(f"  {key}: {value}")
    
    if result.matches:
        lines.append(f"\n=== Matches ({len(result.matches)}) ===")
        for match in result.matches:
            lines.append(f"\n[{match.ioc.type}] {match.ioc.value}")
            lines.append(f"  File: {match.file_path}")
            if match.line_number:
                lines.append(f"  Line: {match.line_number}")
            if match.timestamp:
                lines.append(f"  Timestamp: {match.timestamp}")
            if match.file_hash:
                lines.append(f"  File Hash: {match.file_hash}")
            if match.context:
                lines.append(f"  Context: {match.context[:200]}")
    
    if result.npm_packages:
        lines.append(f"\n=== Malicious NPM Packages ({len(result.npm_packages)}) ===")
        for pkg in result.npm_packages:
            lines.append(f"  {pkg['package']} in {pkg['file']}")
    
    return '\n'.join(lines)

if __name__ == '__main__':
    sys.exit(main())
