#!/usr/bin/env python3
"""
Quick Triage Module
Rapid assessment of system or disk image
Migrated from triage_offline.sh with enhancements
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import ModuleResult, TriageModule
from ...core.time_utils import utc_isoformat


class QuickTriageModule(TriageModule):
    """
    Quick triage module for rapid system assessment
    
    Performs:
    - SUID/SGID binary identification
    - Suspicious file detection
    - Persistence mechanism detection
    - User account enumeration
    - Network configuration analysis
    - Log file summary
    - Recent file activity
    - SSH key detection
    """
    
    @property
    def name(self) -> str:
        return "quick_triage"
    
    @property
    def description(self) -> str:
        return "Quick system triage and assessment"
    
    @property
    def requires_root(self) -> bool:
        return False  # Can run as non-root on mounted images
    
    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if 'target' not in params:
            self.logger.error("Missing required parameter: target")
            return False
        
        target = Path(params['target'])
        if not target.exists():
            self.logger.error(f"Target does not exist: {target}")
            return False
        
        return True
    
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute quick triage"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        
        target = Path(params['target'])
        findings = []
        errors = []
        metadata = {
            'target': str(target),
            'triage_start': timestamp
        }
        
        self.logger.info(f"Starting quick triage of: {target}")
        
        # Determine if target is mounted filesystem or image
        is_mounted = target.is_dir()
        
        if not is_mounted:
            self.logger.warning("Target is not a directory. Attempting to mount...")
            # TODO: Implement automatic mounting logic
            errors.append("Target is not a mounted filesystem")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors
            )
        
        # Execute triage checks
        try:
            # 1. SUID/SGID binaries
            suid_findings = self._check_suid_sgid(target)
            if suid_findings:
                findings.extend(suid_findings)
            
            # 2. User accounts
            user_findings = self._analyze_users(target)
            if user_findings:
                findings.extend(user_findings)
            
            # 3. Persistence mechanisms
            persistence_findings = self._check_persistence(target)
            if persistence_findings:
                findings.extend(persistence_findings)
            
            # 4. SSH keys
            ssh_findings = self._check_ssh_keys(target)
            if ssh_findings:
                findings.extend(ssh_findings)
            
            # 5. Recent files
            recent_findings = self._find_recent_files(target)
            if recent_findings:
                findings.extend(recent_findings)
            
            # 6. Suspicious files
            suspicious_findings = self._find_suspicious_files(target)
            if suspicious_findings:
                findings.extend(suspicious_findings)
            
            # 7. Network configuration
            network_findings = self._analyze_network_config(target)
            if network_findings:
                findings.extend(network_findings)
            
            # 8. Log file summary
            log_findings = self._summarize_logs(target)
            if log_findings:
                findings.extend(log_findings)
            
        except Exception as e:
            self.logger.error(f"Triage failed: {e}")
            errors.append(f"Triage failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors
            )
        
        metadata['triage_end'] = utc_isoformat()
        metadata['total_findings'] = len(findings)
        
        # Generate summary report
        summary_file = self.output_dir / "triage_summary.txt"
        self._generate_summary_report(findings, summary_file)
        
        status = "success" if not errors else "partial"
        
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=summary_file,
            findings=findings,
            metadata=metadata,
            errors=errors
        )
    
    def _check_suid_sgid(self, target: Path) -> List[Dict]:
        """Check for SUID/SGID binaries"""
        findings = []
        
        try:
            # Find SUID files
            stdout, stderr, rc = self._run_command([
                'find', str(target),
                '-xdev', '-type', 'f',
                '(', '-perm', '-4000', '-o', '-perm', '-2000', ')',
                '-ls'
            ], timeout=300)
            
            suid_files = []
            for line in stdout.splitlines():
                if line.strip():
                    suid_files.append(line)
            
            # Check for suspicious SUID files
            suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp', '/home']
            suspicious_suid = []
            
            for line in suid_files:
                for sus_path in suspicious_paths:
                    if sus_path in line:
                        suspicious_suid.append(line)
                        break
            
            findings.append({
                'type': 'suid_sgid',
                'severity': 'medium' if suspicious_suid else 'info',
                'description': 'SUID/SGID binaries found',
                'total_count': len(suid_files),
                'suspicious_count': len(suspicious_suid),
                'suspicious_files': suspicious_suid[:10]  # Limit output
            })
            
            # Save full list
            suid_file = self.output_dir / "suid_sgid_files.txt"
            with open(suid_file, 'w') as f:
                f.write('\n'.join(suid_files))
            
        except Exception as e:
            self.logger.warning(f"SUID check failed: {e}")
        
        return findings
    
    def _analyze_users(self, target: Path) -> List[Dict]:
        """Analyze user accounts"""
        findings = []
        
        try:
            passwd_file = target / "etc" / "passwd"
            if not passwd_file.exists():
                return findings
            
            users = []
            interactive_shells = ['/bin/bash', '/bin/zsh', '/bin/sh', '/bin/ash']
            
            with open(passwd_file) as f:
                for line in f:
                    if not line.strip() or line.startswith('#'):
                        continue
                    
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = parts[2]
                        shell = parts[6]
                        
                        users.append({
                            'username': username,
                            'uid': uid,
                            'shell': shell,
                            'has_interactive_shell': shell in interactive_shells
                        })
            
            # Find suspicious users
            suspicious_users = [
                u for u in users
                if u['has_interactive_shell'] and int(u['uid']) >= 1000
            ]
            
            findings.append({
                'type': 'user_accounts',
                'severity': 'info',
                'description': 'User accounts enumerated',
                'total_users': len(users),
                'interactive_users': len(suspicious_users),
                'users': suspicious_users[:20]
            })
            
        except Exception as e:
            self.logger.warning(f"User analysis failed: {e}")
        
        return findings
    
    def _check_persistence(self, target: Path) -> List[Dict]:
        """Check for persistence mechanisms"""
        findings = []
        
        persistence_locations = [
            ('Crontab', target / "etc" / "crontab"),
            ('Cron.d', target / "etc" / "cron.d"),
            ('Systemd services', target / "etc" / "systemd" / "system"),
            ('Init.d', target / "etc" / "init.d"),
            ('Bashrc', target / "etc" / "bash.bashrc"),
            ('Profile', target / "etc" / "profile"),
        ]
        
        found_persistence = []
        
        for name, path in persistence_locations:
            if path.exists():
                # Check for suspicious content
                suspicious = self._scan_for_suspicious_content(path)
                if suspicious:
                    found_persistence.append({
                        'location': name,
                        'path': str(path),
                        'suspicious_entries': suspicious[:5]
                    })
        
        if found_persistence:
            findings.append({
                'type': 'persistence_mechanisms',
                'severity': 'high' if found_persistence else 'info',
                'description': 'Potential persistence mechanisms detected',
                'locations': found_persistence
            })
        
        return findings
    
    def _scan_for_suspicious_content(self, path: Path) -> List[str]:
        """Scan file or directory for suspicious patterns"""
        suspicious = []
        suspicious_patterns = [
            r'curl.*http',
            r'wget.*http',
            r'/tmp/\.',
            r'base64 -d',
            r'bash -c',
            r'nc -l',
            r'socat',
            r'/dev/tcp/'
        ]
        
        try:
            if path.is_file():
                files = [path]
            else:
                files = list(path.rglob('*'))
                files = [f for f in files if f.is_file()][:50]  # Limit
            
            for file in files:
                try:
                    with open(file, 'r', errors='ignore') as f:
                        content = f.read(1024 * 100)  # Max 100KB
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                suspicious.append(f"{file}: {pattern}")
                except Exception:
                    continue
        except Exception as e:
            self.logger.debug(f"Scan failed for {path}: {e}")
        
        return suspicious
    
    def _check_ssh_keys(self, target: Path) -> List[Dict]:
        """Check for SSH keys"""
        findings = []
        
        try:
            ssh_keys = []
            
            # Check common locations
            search_paths = [
                target / "root" / ".ssh",
                target / "home"
            ]
            
            for search_path in search_paths:
                if not search_path.exists():
                    continue
                
                for key_file in search_path.rglob('id_*'):
                    if key_file.is_file() and not key_file.name.endswith('.pub'):
                        ssh_keys.append({
                            'path': str(key_file),
                            'size': key_file.stat().st_size
                        })
            
            if ssh_keys:
                findings.append({
                    'type': 'ssh_keys',
                    'severity': 'medium',
                    'description': 'SSH private keys found',
                    'count': len(ssh_keys),
                    'keys': ssh_keys[:10]
                })
        
        except Exception as e:
            self.logger.warning(f"SSH key check failed: {e}")
        
        return findings
    
    def _find_recent_files(self, target: Path, days: int = 7) -> List[Dict]:
        """Find recently modified files"""
        findings = []
        
        try:
            stdout, stderr, rc = self._run_command([
                'find', str(target),
                '-xdev', '-type', 'f',
                '-mtime', f'-{days}',
                '-ls'
            ], timeout=300)
            
            recent_files = []
            for line in stdout.splitlines()[:100]:  # Limit to 100
                if line.strip():
                    recent_files.append(line)
            
            if recent_files:
                findings.append({
                    'type': 'recent_files',
                    'severity': 'info',
                    'description': f'Files modified in last {days} days',
                    'count': len(recent_files),
                    'files': recent_files[:20]
                })
        
        except Exception as e:
            self.logger.warning(f"Recent files check failed: {e}")
        
        return findings
    
    def _find_suspicious_files(self, target: Path) -> List[Dict]:
        """Find suspicious files (hidden, unusual locations)"""
        findings = []
        
        suspicious_locations = [
            target / "tmp",
            target / "dev" / "shm",
            target / "var" / "tmp"
        ]
        
        suspicious_files = []
        
        for location in suspicious_locations:
            if not location.exists():
                continue
            
            try:
                for item in location.rglob('*'):
                    if item.is_file():
                        # Check for hidden files
                        if item.name.startswith('.'):
                            suspicious_files.append(str(item))
                        # Check for ELF binaries
                        elif self._is_elf_binary(item):
                            suspicious_files.append(str(item))
            except Exception:
                continue
        
        if suspicious_files:
            findings.append({
                'type': 'suspicious_files',
                'severity': 'high',
                'description': 'Suspicious files in temporary directories',
                'count': len(suspicious_files),
                'files': suspicious_files[:20]
            })
        
        return findings
    
    def _is_elf_binary(self, file_path: Path) -> bool:
        """Check if file is ELF binary"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False
    
    def _analyze_network_config(self, target: Path) -> List[Dict]:
        """Analyze network configuration"""
        findings = []
        
        try:
            resolv_conf = target / "etc" / "resolv.conf"
            hosts_file = target / "etc" / "hosts"
            
            network_info = {}
            
            if resolv_conf.exists():
                with open(resolv_conf) as f:
                    network_info['nameservers'] = [
                        line.split()[1]
                        for line in f
                        if line.startswith('nameserver')
                    ]
            
            if hosts_file.exists():
                suspicious_hosts = []
                with open(hosts_file) as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            if 'localhost' not in line.lower():
                                suspicious_hosts.append(line.strip())
                
                if suspicious_hosts:
                    network_info['suspicious_hosts'] = suspicious_hosts[:10]
            
            if network_info:
                findings.append({
                    'type': 'network_config',
                    'severity': 'info',
                    'description': 'Network configuration analyzed',
                    'config': network_info
                })
        
        except Exception as e:
            self.logger.warning(f"Network config analysis failed: {e}")
        
        return findings
    
    def _summarize_logs(self, target: Path) -> List[Dict]:
        """Summarize log files"""
        findings = []
        
        log_dir = target / "var" / "log"
        if not log_dir.exists():
            return findings
        
        try:
            log_files = list(log_dir.rglob('*.log'))[:10]
            
            log_summary = []
            for log_file in log_files:
                try:
                    size = log_file.stat().st_size
                    lines = 0
                    with open(log_file, errors='ignore') as f:
                        lines = sum(1 for _ in f)
                    
                    log_summary.append({
                        'file': str(log_file.relative_to(target)),
                        'size_bytes': size,
                        'line_count': lines
                    })
                except Exception:
                    continue
            
            if log_summary:
                findings.append({
                    'type': 'log_summary',
                    'severity': 'info',
                    'description': 'Log files summarized',
                    'logs': log_summary
                })
        
        except Exception as e:
            self.logger.warning(f"Log summary failed: {e}")
        
        return findings
    
    def _generate_summary_report(self, findings: List[Dict], output_path: Path):
        """Generate human-readable summary report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("QUICK TRIAGE SUMMARY REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {utc_isoformat()}\n")
            f.write(f"Total Findings: {len(findings)}\n\n")
            
            for finding in findings:
                f.write("-" * 80 + "\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"Description: {finding['description']}\n")
                
                # Write type-specific details
                for key, value in finding.items():
                    if key not in ['type', 'severity', 'description']:
                        f.write(f"{key}: {value}\n")
                
                f.write("\n")
        
        self.logger.info(f"Summary report written to: {output_path}")
