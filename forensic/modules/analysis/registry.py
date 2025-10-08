#!/usr/bin/env python3
"""
Windows Registry Analysis Module
Comprehensive Windows Registry forensics

Features:
- Registry hive parsing (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
- User activity extraction (recent files, typed paths, run history)
- System configuration analysis
- Persistence mechanism detection
- USB device history
- Network configuration
- Program execution evidence
- Timezone and system info
- RegRipper integration (optional)
"""

import json
import re
import struct
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.evidence import Evidence, EvidenceType
from ...core.module import AnalysisModule, ModuleResult


class RegistryAnalysisModule(AnalysisModule):
    """
    Windows Registry analysis module
    
    Analyzes Windows Registry for:
    - User activity traces
    - System configuration
    - Persistence mechanisms
    - Program execution evidence
    - Network configuration
    - USB device history
    """
    
    # Registry hive locations
    HIVE_LOCATIONS = {
        'SYSTEM': 'Windows/System32/config/SYSTEM',
        'SOFTWARE': 'Windows/System32/config/SOFTWARE',
        'SAM': 'Windows/System32/config/SAM',
        'SECURITY': 'Windows/System32/config/SECURITY',
        'NTUSER': 'Users/*/NTUSER.DAT',
        'USRCLASS': 'Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat',
    }
    
    @property
    def name(self) -> str:
        return "registry_analysis"
    
    @property
    def description(self) -> str:
        return "Windows Registry forensic analysis"
    
    @property
    def requires_root(self) -> bool:
        return False
    
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
        """Execute registry analysis"""
        result_id = self._generate_result_id()
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        target = Path(params['target'])
        use_regripper = params.get('regripper', 'false').lower() == 'true'
        
        findings = []
        errors = []
        metadata = {
            'target': str(target),
            'analysis_start': timestamp
        }
        
        self.logger.info(f"Analyzing Windows Registry: {target}")
        
        try:
            # 1. Locate registry hives
            self.logger.info("Locating registry hives...")
            hives = self._locate_hives(target)
            metadata['hives_found'] = len(hives)
            
            if not hives:
                errors.append("No registry hives found")
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    findings=findings,
                    metadata=metadata,
                    errors=errors
                )
            
            findings.append({
                'type': 'registry_hives',
                'description': f'Found {len(hives)} registry hives',
                'hives': list(hives.keys())
            })
            
            # 2. System Information
            if 'SYSTEM' in hives:
                self.logger.info("Extracting system information...")
                system_info = self._analyze_system_info(hives['SYSTEM'])
                if system_info:
                    findings.append({
                        'type': 'system_info',
                        'description': 'System configuration',
                        **system_info
                    })
            
            # 3. User Activity
            ntuser_hives = [h for k, h in hives.items() if k.startswith('NTUSER_')]
            if ntuser_hives:
                self.logger.info(f"Analyzing {len(ntuser_hives)} user profiles...")
                for user_hive_key in [k for k in hives.keys() if k.startswith('NTUSER_')]:
                    user_findings = self._analyze_user_activity(
                        hives[user_hive_key],
                        user_hive_key
                    )
                    findings.extend(user_findings)
            
            # 4. Persistence Mechanisms
            self.logger.info("Detecting persistence mechanisms...")
            if 'SOFTWARE' in hives:
                persistence = self._detect_persistence(hives['SOFTWARE'])
                if persistence:
                    findings.append({
                        'type': 'persistence_mechanisms',
                        'description': f'Found {len(persistence)} persistence entries',
                        'severity': 'high',
                        'entries': persistence
                    })
            
            # 5. USB Device History
            if 'SYSTEM' in hives:
                self.logger.info("Extracting USB device history...")
                usb_devices = self._extract_usb_devices(hives['SYSTEM'])
                if usb_devices:
                    findings.append({
                        'type': 'usb_devices',
                        'description': f'Found {len(usb_devices)} USB devices',
                        'devices': usb_devices
                    })
            
            # 6. Network Configuration
            if 'SYSTEM' in hives:
                self.logger.info("Analyzing network configuration...")
                network_config = self._analyze_network_config(hives['SYSTEM'])
                if network_config:
                    findings.append({
                        'type': 'network_config',
                        'description': 'Network configuration',
                        **network_config
                    })
            
            # 7. Program Execution Evidence
            if 'NTUSER' in hives or any(k.startswith('NTUSER_') for k in hives):
                self.logger.info("Extracting program execution evidence...")
                for user_hive_key in [k for k in hives.keys() if k.startswith('NTUSER_')]:
                    exec_evidence = self._extract_execution_evidence(
                        hives[user_hive_key],
                        user_hive_key
                    )
                    if exec_evidence:
                        findings.append({
                            'type': 'program_execution',
                            'description': f'Program execution evidence for {user_hive_key}',
                            **exec_evidence
                        })
            
            # 8. RegRipper Analysis (optional)
            if use_regripper and self._verify_tool('rip.pl'):
                self.logger.info("Running RegRipper...")
                regripper_results = self._run_regripper(hives)
                if regripper_results:
                    findings.append({
                        'type': 'regripper_analysis',
                        'description': 'RegRipper comprehensive analysis',
                        'output_files': regripper_results
                    })
            
            # Generate comprehensive report
            report_file = self.output_dir / "registry_analysis_report.json"
            with open(report_file, 'w') as f:
                json.dump({
                    'metadata': metadata,
                    'findings': findings
                }, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Registry analysis failed: {e}")
            errors.append(f"Analysis failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors
            )
        
        metadata['analysis_end'] = datetime.utcnow().isoformat() + "Z"
        metadata['total_findings'] = len(findings)
        
        status = "success" if not errors else "partial"
        
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=report_file,
            findings=findings,
            metadata=metadata,
            errors=errors
        )
    
    def _locate_hives(self, target: Path) -> Dict[str, Path]:
        """Locate registry hives on target system"""
        hives = {}
        
        for hive_name, hive_path in self.HIVE_LOCATIONS.items():
            if '*' in hive_path:
                # Wildcard path (NTUSER.DAT)
                base_path = hive_path.split('*')[0]
                pattern = hive_path.split('*')[1]
                
                search_dir = target / base_path.rstrip('/')
                if search_dir.exists():
                    for user_dir in search_dir.iterdir():
                        if user_dir.is_dir():
                            hive_file = user_dir / pattern.lstrip('/')
                            if hive_file.exists():
                                key = f"{hive_name}_{user_dir.name}"
                                hives[key] = hive_file
            else:
                hive_file = target / hive_path
                if hive_file.exists():
                    hives[hive_name] = hive_file
        
        return hives
    
    def _analyze_system_info(self, system_hive: Path) -> Dict:
        """Extract system information from SYSTEM hive"""
        info = {}
        
        try:
            # Use reglookup or read directly
            if self._verify_tool('reglookup'):
                stdout, stderr, rc = self._run_command([
                    'reglookup',
                    '-p', 'ControlSet001/Control/ComputerName/ComputerName',
                    str(system_hive)
                ])
                
                for line in stdout.splitlines():
                    if 'ComputerName' in line and 'REG_SZ' in line:
                        parts = line.split(',')
                        if len(parts) >= 3:
                            info['computer_name'] = parts[2].strip()
                
                # Timezone
                stdout, stderr, rc = self._run_command([
                    'reglookup',
                    '-p', 'ControlSet001/Control/TimeZoneInformation',
                    str(system_hive)
                ])
                
                for line in stdout.splitlines():
                    if 'TimeZoneKeyName' in line:
                        parts = line.split(',')
                        if len(parts) >= 3:
                            info['timezone'] = parts[2].strip()
            
        except Exception as e:
            self.logger.warning(f"System info extraction failed: {e}")
        
        return info
    
    def _analyze_user_activity(self, ntuser_hive: Path, user_key: str) -> List[Dict]:
        """Analyze user activity from NTUSER.DAT"""
        findings = []
        
        try:
            if not self._verify_tool('reglookup'):
                return findings
            
            # Recent Docs
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs',
                str(ntuser_hive)
            ], timeout=60)
            
            recent_docs = []
            for line in stdout.splitlines():
                if 'REG_BINARY' in line or 'REG_SZ' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        doc = parts[2].strip()
                        if doc and len(doc) > 2:
                            recent_docs.append(doc)
            
            if recent_docs:
                findings.append({
                    'type': 'recent_documents',
                    'description': f'Recent documents for {user_key}',
                    'user': user_key,
                    'documents': recent_docs[:20]
                })
            
            # Typed Paths
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'Software/Microsoft/Windows/CurrentVersion/Explorer/TypedPaths',
                str(ntuser_hive)
            ], timeout=60)
            
            typed_paths = []
            for line in stdout.splitlines():
                if 'REG_SZ' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        path = parts[2].strip()
                        if path:
                            typed_paths.append(path)
            
            if typed_paths:
                findings.append({
                    'type': 'typed_paths',
                    'description': f'Typed paths for {user_key}',
                    'user': user_key,
                    'paths': typed_paths
                })
            
            # Run MRU
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU',
                str(ntuser_hive)
            ], timeout=60)
            
            run_commands = []
            for line in stdout.splitlines():
                if 'REG_SZ' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        cmd = parts[2].strip()
                        if cmd and cmd != 'MRUList':
                            run_commands.append(cmd)
            
            if run_commands:
                findings.append({
                    'type': 'run_mru',
                    'description': f'Run command history for {user_key}',
                    'user': user_key,
                    'severity': 'medium',
                    'commands': run_commands
                })
        
        except Exception as e:
            self.logger.warning(f"User activity analysis failed: {e}")
        
        return findings
    
    def _detect_persistence(self, software_hive: Path) -> List[Dict]:
        """Detect persistence mechanisms in registry"""
        persistence = []
        
        # Common persistence locations
        persistence_keys = [
            'Microsoft/Windows/CurrentVersion/Run',
            'Microsoft/Windows/CurrentVersion/RunOnce',
            'Microsoft/Windows/CurrentVersion/RunServices',
            'Microsoft/Windows/CurrentVersion/RunServicesOnce',
        ]
        
        try:
            if not self._verify_tool('reglookup'):
                return persistence
            
            for key in persistence_keys:
                stdout, stderr, rc = self._run_command([
                    'reglookup',
                    '-p', key,
                    str(software_hive)
                ], timeout=60)
                
                for line in stdout.splitlines():
                    if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                        parts = line.split(',')
                        if len(parts) >= 3:
                            value_name = parts[1].strip()
                            value_data = parts[2].strip()
                            
                            if value_data:
                                persistence.append({
                                    'key': key,
                                    'value_name': value_name,
                                    'value_data': value_data
                                })
        
        except Exception as e:
            self.logger.warning(f"Persistence detection failed: {e}")
        
        return persistence
    
    def _extract_usb_devices(self, system_hive: Path) -> List[Dict]:
        """Extract USB device history"""
        devices = []
        
        try:
            if not self._verify_tool('reglookup'):
                return devices
            
            # USB STOR
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'ControlSet001/Enum/USBSTOR',
                str(system_hive)
            ], timeout=120)
            
            current_device = {}
            for line in stdout.splitlines():
                if 'FriendlyName' in line and 'REG_SZ' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        current_device['name'] = parts[2].strip()
                elif 'ParentIdPrefix' in line and 'REG_SZ' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        current_device['id'] = parts[2].strip()
                        if current_device:
                            devices.append(current_device.copy())
                            current_device = {}
        
        except Exception as e:
            self.logger.warning(f"USB device extraction failed: {e}")
        
        return devices
    
    def _analyze_network_config(self, system_hive: Path) -> Dict:
        """Analyze network configuration"""
        config = {}
        
        try:
            if not self._verify_tool('reglookup'):
                return config
            
            # Network interfaces
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'ControlSet001/Services/Tcpip/Parameters/Interfaces',
                str(system_hive)
            ], timeout=60)
            
            interfaces = []
            current_if = {}
            
            for line in stdout.splitlines():
                if 'IPAddress' in line and 'REG' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        current_if['ip'] = parts[2].strip()
                elif 'SubnetMask' in line and 'REG' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        current_if['subnet'] = parts[2].strip()
                elif 'DefaultGateway' in line and 'REG' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        current_if['gateway'] = parts[2].strip()
                        if current_if:
                            interfaces.append(current_if.copy())
                            current_if = {}
            
            if interfaces:
                config['interfaces'] = interfaces
        
        except Exception as e:
            self.logger.warning(f"Network config analysis failed: {e}")
        
        return config
    
    def _extract_execution_evidence(self, ntuser_hive: Path, user_key: str) -> Dict:
        """Extract program execution evidence"""
        evidence = {}
        
        try:
            if not self._verify_tool('reglookup'):
                return evidence
            
            # UserAssist (programs run via Explorer)
            stdout, stderr, rc = self._run_command([
                'reglookup',
                '-p', 'Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist',
                str(ntuser_hive)
            ], timeout=60)
            
            programs = []
            for line in stdout.splitlines():
                if 'REG_BINARY' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        # UserAssist entries are ROT13 encoded
                        encoded_name = parts[1].strip()
                        try:
                            decoded = self._rot13_decode(encoded_name)
                            if decoded and '.exe' in decoded.lower():
                                programs.append(decoded)
                        except Exception:
                            pass
            
            if programs:
                evidence['userassist_programs'] = programs[:20]
        
        except Exception as e:
            self.logger.warning(f"Execution evidence extraction failed: {e}")
        
        return evidence
    
    def _rot13_decode(self, text: str) -> str:
        """ROT13 decode for UserAssist"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def _run_regripper(self, hives: Dict[str, Path]) -> List[str]:
        """Run RegRipper on hives"""
        output_files = []
        
        for hive_name, hive_path in hives.items():
            output_file = self.output_dir / f"regripper_{hive_name}.txt"
            
            try:
                with open(output_file, 'w') as f:
                    subprocess.run(
                        ['rip.pl', '-r', str(hive_path), '-a'],
                        stdout=f,
                        stderr=subprocess.PIPE,
                        timeout=300
                    )
                
                output_files.append(str(output_file))
            except Exception as e:
                self.logger.warning(f"RegRipper failed for {hive_name}: {e}")
        
        return output_files
