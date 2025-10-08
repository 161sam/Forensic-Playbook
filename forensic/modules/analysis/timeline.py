#!/usr/bin/env python3
"""
Timeline Generation Module
Forensic timeline creation using plaso/log2timeline and mactime

Features:
- plaso (log2timeline) integration for comprehensive timelines
- Sleuthkit mactime support for filesystem timelines
- Multi-source timeline correlation
- Filtering by date range, file types, user activity
- Multiple output formats (CSV, L2TCSV, body, JSON)
- Timeline visualization support
"""

import csv
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...core.evidence import Evidence, EvidenceType
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat


class TimelineModule(AnalysisModule):
    """
    Timeline generation module
    
    Creates forensic timelines from:
    - Disk images
    - Mounted filesystems
    - Log directories
    - Memory dumps (limited support)
    - Network captures (limited support)
    """
    
    @property
    def name(self) -> str:
        return "timeline"
    
    @property
    def description(self) -> str:
        return "Generate forensic timeline from evidence"
    
    @property
    def requires_root(self) -> bool:
        return False
    
    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if 'source' not in params:
            self.logger.error("Missing required parameter: source")
            return False
        
        source = Path(params['source'])
        if not source.exists():
            self.logger.error(f"Source does not exist: {source}")
            return False
        
        return True
    
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute timeline generation"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        
        source = Path(params['source'])
        output_format = params.get('format', 'csv').lower()
        timeline_type = params.get('type', 'auto').lower()  # auto, plaso, mactime
        
        # Date filtering
        start_date = params.get('start_date')
        end_date = params.get('end_date')
        
        # Advanced options
        include_mft = params.get('include_mft', 'true').lower() == 'true'
        include_usnjrnl = params.get('include_usnjrnl', 'false').lower() == 'true'
        include_browser = params.get('include_browser', 'true').lower() == 'true'
        include_logs = params.get('include_logs', 'true').lower() == 'true'
        
        findings = []
        errors = []
        metadata = {
            'source': str(source),
            'timeline_type': timeline_type,
            'output_format': output_format,
            'start': timestamp
        }
        
        self.logger.info(f"Generating timeline from: {source}")
        
        # Auto-detect source type
        if timeline_type == 'auto':
            timeline_type = self._detect_timeline_type(source)
            self.logger.info(f"Auto-detected timeline type: {timeline_type}")
        metadata['timeline_type'] = timeline_type

        requirements = {
            'plaso': ['log2timeline.py'],
            'mactime': ['fls', 'mactime'],
        }
        required_tools = requirements.get(timeline_type, [])
        missing_tools = [tool for tool in required_tools if not self._verify_tool(tool)]
        if missing_tools:
            guidance = "Install the required timeline tooling to enable this mode."
            return self._missing_tool_result(
                result_id,
                missing_tools,
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
            )

        # Generate timeline
        try:
            if timeline_type == 'plaso':
                timeline_file, stats = self._generate_plaso_timeline(
                    source,
                    output_format,
                    start_date,
                    end_date,
                    include_mft,
                    include_usnjrnl,
                    include_browser,
                    include_logs
                )
            elif timeline_type == 'mactime':
                timeline_file, stats = self._generate_mactime_timeline(
                    source,
                    output_format,
                    start_date,
                    end_date
                )
            elif timeline_type == 'simple':
                timeline_file, stats = self._generate_simple_timeline(
                    source,
                    output_format
                )
            else:
                errors.append(f"Unknown timeline type: {timeline_type}")
                return ModuleResult(
                    result_id=result_id,
                    module_name=self.name,
                    status="failed",
                    timestamp=timestamp,
                    findings=findings,
                    metadata=metadata,
                    errors=errors
                )
            
            metadata.update(stats)
            
            findings.append({
                'type': 'timeline_generated',
                'description': f'Timeline created with {stats.get("total_events", 0)} events',
                'timeline_type': timeline_type,
                'output_file': str(timeline_file)
            })
            
            # Generate summary
            if timeline_file.exists():
                summary = self._analyze_timeline(timeline_file, output_format)
                findings.append({
                    'type': 'timeline_summary',
                    'description': 'Timeline analysis summary',
                    **summary
                })
            
        except Exception as e:
            self.logger.error(f"Timeline generation failed: {e}")
            errors.append(f"Timeline generation failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors
            )
        
        metadata['end'] = utc_isoformat()
        
        status = "success" if not errors else "partial"
        
        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=timeline_file,
            findings=findings,
            metadata=metadata,
            errors=errors
        )
    
    def _detect_timeline_type(self, source: Path) -> str:
        """Auto-detect appropriate timeline type"""
        # Check for plaso availability
        if self._verify_tool('log2timeline.py'):
            return 'plaso'
        
        # Check for Sleuthkit
        if self._verify_tool('fls') and self._verify_tool('mactime'):
            return 'mactime'
        
        # Fallback to simple
        return 'simple'
    
    def _generate_plaso_timeline(
        self,
        source: Path,
        output_format: str,
        start_date: Optional[str],
        end_date: Optional[str],
        include_mft: bool,
        include_usnjrnl: bool,
        include_browser: bool,
        include_logs: bool
    ) -> Tuple[Path, Dict]:
        """Generate timeline using plaso/log2timeline"""
        self.logger.info("Using plaso/log2timeline for timeline generation")
        
        if not self._verify_tool('log2timeline.py'):
            raise RuntimeError("plaso/log2timeline not installed")
        
        stats = {}
        
        # Create plaso storage file
        plaso_file = self.output_dir / "timeline.plaso"
        
        # Build log2timeline command
        cmd = [
            'log2timeline.py',
            '--status_view', 'none',  # Suppress progress
            '--storage-file', str(plaso_file)
        ]
        
        # Parser selection
        parsers = []
        if include_mft:
            parsers.append('mft')
        if include_usnjrnl:
            parsers.append('usnjrnl')
        if include_browser:
            parsers.extend(['chrome_history', 'firefox_history', 'safari_history'])
        if include_logs:
            parsers.extend(['syslog', 'apache_access', 'wevt'])
        
        if parsers:
            cmd.extend(['--parsers', ','.join(parsers)])
        
        # Add source
        cmd.append(str(source))
        
        # Execute log2timeline
        self.logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                self.logger.warning(f"log2timeline warning: {result.stderr}")
            
            stats['log2timeline_rc'] = result.returncode
        except subprocess.TimeoutExpired:
            raise RuntimeError("log2timeline timeout")
        except Exception as e:
            raise RuntimeError(f"log2timeline failed: {e}")
        
        # Convert to desired format using psort
        if output_format == 'l2tcsv':
            output_file = self.output_dir / "timeline.l2tcsv"
            output_arg = 'l2tcsv'
        elif output_format == 'json':
            output_file = self.output_dir / "timeline.jsonl"
            output_arg = 'json_line'
        else:  # csv
            output_file = self.output_dir / "timeline.csv"
            output_arg = 'dynamic'
        
        psort_cmd = [
            'psort.py',
            '--output_time_zone', 'UTC',
            '-o', output_arg,
            '-w', str(output_file)
        ]
        
        # Date filtering
        if start_date:
            psort_cmd.extend(['--date_filter', f'{start_date}..{end_date or "9999-12-31"}'])
        
        psort_cmd.append(str(plaso_file))
        
        self.logger.info(f"Running: {' '.join(psort_cmd)}")
        
        try:
            result = subprocess.run(
                psort_cmd,
                capture_output=True,
                text=True,
                timeout=1800
            )
            
            if result.returncode != 0:
                self.logger.warning(f"psort warning: {result.stderr}")
            
            stats['psort_rc'] = result.returncode
        except Exception as e:
            raise RuntimeError(f"psort failed: {e}")
        
        # Count events
        if output_file.exists():
            stats['total_events'] = sum(1 for _ in open(output_file)) - 1  # Minus header
        
        return output_file, stats
    
    def _generate_mactime_timeline(
        self,
        source: Path,
        output_format: str,
        start_date: Optional[str],
        end_date: Optional[str]
    ) -> Tuple[Path, Dict]:
        """Generate timeline using Sleuthkit mactime"""
        self.logger.info("Using Sleuthkit mactime for timeline generation")
        
        if not self._verify_tool('fls'):
            raise RuntimeError("Sleuthkit not installed")
        
        stats = {}
        
        # Generate body file
        body_file = self.output_dir / "bodyfile.txt"
        
        cmd = [
            'fls',
            '-r',  # Recursive
            '-m', '/',  # Mount point
            str(source)
        ]
        
        self.logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            with open(body_file, 'w') as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=1800
                )
            
            if result.returncode != 0:
                self.logger.warning(f"fls warning: {result.stderr}")
            
            stats['fls_rc'] = result.returncode
        except Exception as e:
            raise RuntimeError(f"fls failed: {e}")
        
        # Generate timeline from body file
        timeline_file = self.output_dir / "timeline.csv"
        
        mactime_cmd = [
            'mactime',
            '-b', str(body_file),
            '-d'  # CSV output
        ]
        
        # Date filtering
        if start_date:
            mactime_cmd.extend(['-z', 'UTC'])
            # mactime uses different date format
            # Convert YYYY-MM-DD to MM/DD/YYYY
            if start_date:
                start_parts = start_date.split('-')
                if len(start_parts) == 3:
                    mactime_cmd.extend(['-s', f"{start_parts[1]}/{start_parts[2]}/{start_parts[0]}"])
            if end_date:
                end_parts = end_date.split('-')
                if len(end_parts) == 3:
                    mactime_cmd.extend(['-e', f"{end_parts[1]}/{end_parts[2]}/{end_parts[0]}"])
        
        self.logger.info(f"Running: {' '.join(mactime_cmd)}")
        
        try:
            with open(timeline_file, 'w') as f:
                result = subprocess.run(
                    mactime_cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=600
                )
            
            if result.returncode != 0:
                self.logger.warning(f"mactime warning: {result.stderr}")
            
            stats['mactime_rc'] = result.returncode
        except Exception as e:
            raise RuntimeError(f"mactime failed: {e}")
        
        # Count events
        if timeline_file.exists():
            stats['total_events'] = sum(1 for _ in open(timeline_file))
        
        return timeline_file, stats
    
    def _generate_simple_timeline(
        self,
        source: Path,
        output_format: str
    ) -> Tuple[Path, Dict]:
        """Generate simple timeline using find + stat"""
        self.logger.info("Using simple timeline generation (find + stat)")
        
        stats = {}
        timeline_file = self.output_dir / "timeline.csv"
        
        events = []
        
        # Walk directory tree
        for root, dirs, files in source.walk() if source.is_dir() else [(source.parent, [], [source.name])]:
            for fname in files:
                fpath = Path(root) / fname
                
                try:
                    stat = fpath.stat()
                    
                    # Add events for each timestamp
                    events.append({
                        'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat() + 'Z',
                        'type': 'MACB',
                        'path': str(fpath),
                        'size': stat.st_size,
                        'description': 'File modified'
                    })
                    
                    events.append({
                        'timestamp': datetime.fromtimestamp(stat.st_atime).isoformat() + 'Z',
                        'type': 'MACB',
                        'path': str(fpath),
                        'size': stat.st_size,
                        'description': 'File accessed'
                    })
                    
                    events.append({
                        'timestamp': datetime.fromtimestamp(stat.st_ctime).isoformat() + 'Z',
                        'type': 'MACB',
                        'path': str(fpath),
                        'size': stat.st_size,
                        'description': 'File changed (metadata)'
                    })
                except Exception:
                    continue
        
        # Sort by timestamp
        events.sort(key=lambda e: e['timestamp'])
        
        # Write to CSV
        with open(timeline_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'path', 'size', 'description'])
            writer.writeheader()
            writer.writerows(events)
        
        stats['total_events'] = len(events)
        
        return timeline_file, stats
    
    def _analyze_timeline(self, timeline_file: Path, output_format: str) -> Dict:
        """Analyze timeline for summary statistics"""
        summary = {}
        
        try:
            with open(timeline_file, 'r') as f:
                lines = list(f)
            
            summary['total_events'] = len(lines) - 1  # Minus header
            
            # Date range
            if output_format == 'csv' and len(lines) > 2:
                # Assume first column is timestamp
                first_line = lines[1].split(',')[0]
                last_line = lines[-1].split(',')[0]
                
                summary['date_range_start'] = first_line.strip('"')
                summary['date_range_end'] = last_line.strip('"')
            
            # File size
            summary['timeline_size_bytes'] = timeline_file.stat().st_size
            
        except Exception as e:
            self.logger.warning(f"Timeline analysis failed: {e}")
        
        return summary
