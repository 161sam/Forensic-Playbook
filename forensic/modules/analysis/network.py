#!/usr/bin/env python3
"""
Network Forensics Module
PCAP analysis and network traffic forensics

Features:
- PCAP file parsing (tcpdump, Wireshark)
- Protocol dissection (HTTP, DNS, FTP, SMB, etc.)
- Connection timeline
- Suspicious traffic detection
- File extraction from network streams
- DNS query analysis
- HTTP request/response analysis
- TLS/SSL analysis
- Malicious IP detection
- Statistics and visualization
"""

import csv
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ...core.evidence import Evidence, EvidenceType
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat


class NetworkAnalysisModule(AnalysisModule):
    """
    Network forensics module
    
    Analyzes network traffic captures (PCAP files) for:
    - Connection patterns
    - Protocol usage
    - Suspicious traffic
    - Data exfiltration
    - C2 communication
    - DNS tunneling
    """
    
    @property
    def name(self) -> str:
        return "network_analysis"
    
    @property
    def description(self) -> str:
        return "Network traffic analysis from PCAP files"
    
    @property
    def requires_root(self) -> bool:
        return False
    
    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if 'pcap' not in params:
            self.logger.error("Missing required parameter: pcap")
            return False
        
        pcap = Path(params['pcap'])
        if not pcap.exists():
            self.logger.error(f"PCAP file does not exist: {pcap}")
            return False
        
        return True
    
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute network analysis"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()
        
        pcap_file = Path(params['pcap'])
        extract_files = params.get('extract_files', 'false').lower() == 'true'
        analyze_dns = params.get('analyze_dns', 'true').lower() == 'true'
        analyze_http = params.get('analyze_http', 'true').lower() == 'true'
        detect_suspicious = params.get('detect_suspicious', 'true').lower() == 'true'
        
        findings = []
        errors = []
        metadata = {
            'pcap_file': str(pcap_file),
            'pcap_size': pcap_file.stat().st_size,
            'analysis_start': timestamp
        }
        
        self.logger.info(f"Analyzing PCAP: {pcap_file}")

        # Check tool availability
        if not self._verify_tool('tshark'):
            guidance = "Install wireshark/tshark to analyze network captures."
            return self._missing_tool_result(
                result_id,
                'tshark',
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
            )
        
        try:
            # 1. Basic PCAP statistics
            self.logger.info("Extracting basic statistics...")
            stats = self._get_pcap_statistics(pcap_file)
            metadata.update(stats)
            
            findings.append({
                'type': 'pcap_statistics',
                'description': 'PCAP file statistics',
                **stats
            })
            
            # 2. Connection analysis
            self.logger.info("Analyzing connections...")
            connections = self._analyze_connections(pcap_file)
            
            # Save connections
            conn_file = self.output_dir / "connections.json"
            with open(conn_file, 'w') as f:
                json.dump(connections, f, indent=2)
            
            findings.append({
                'type': 'connections',
                'description': f'Found {len(connections)} unique connections',
                'total': len(connections),
                'output_file': str(conn_file)
            })
            
            # 3. Protocol distribution
            protocol_dist = self._analyze_protocol_distribution(pcap_file)
            findings.append({
                'type': 'protocol_distribution',
                'description': 'Protocol usage statistics',
                'protocols': protocol_dist
            })
            
            # 4. DNS analysis
            if analyze_dns:
                self.logger.info("Analyzing DNS traffic...")
                dns_queries = self._analyze_dns(pcap_file)
                
                if dns_queries:
                    # Save DNS queries
                    dns_file = self.output_dir / "dns_queries.json"
                    with open(dns_file, 'w') as f:
                        json.dump(dns_queries, f, indent=2)
                    
                    findings.append({
                        'type': 'dns_queries',
                        'description': f'Analyzed {len(dns_queries)} DNS queries',
                        'total': len(dns_queries),
                        'output_file': str(dns_file)
                    })
                    
                    # Check for suspicious DNS
                    suspicious_dns = self._detect_suspicious_dns(dns_queries)
                    if suspicious_dns:
                        findings.append({
                            'type': 'suspicious_dns',
                            'description': f'Found {len(suspicious_dns)} suspicious DNS queries',
                            'severity': 'high',
                            'queries': suspicious_dns
                        })
            
            # 5. HTTP analysis
            if analyze_http:
                self.logger.info("Analyzing HTTP traffic...")
                http_requests = self._analyze_http(pcap_file)
                
                if http_requests:
                    # Save HTTP requests
                    http_file = self.output_dir / "http_requests.json"
                    with open(http_file, 'w') as f:
                        json.dump(http_requests, f, indent=2)
                    
                    findings.append({
                        'type': 'http_requests',
                        'description': f'Analyzed {len(http_requests)} HTTP requests',
                        'total': len(http_requests),
                        'output_file': str(http_file)
                    })
                    
                    # Check for suspicious HTTP
                    suspicious_http = self._detect_suspicious_http(http_requests)
                    if suspicious_http:
                        findings.append({
                            'type': 'suspicious_http',
                            'description': f'Found {len(suspicious_http)} suspicious HTTP requests',
                            'severity': 'high',
                            'requests': suspicious_http
                        })
            
            # 6. File extraction
            if extract_files:
                self.logger.info("Extracting files from network streams...")
                extracted = self._extract_files(pcap_file)
                
                if extracted:
                    findings.append({
                        'type': 'extracted_files',
                        'description': f'Extracted {len(extracted)} files',
                        'files': extracted
                    })
            
            # 7. Suspicious traffic detection
            if detect_suspicious:
                self.logger.info("Detecting suspicious traffic patterns...")
                suspicious_traffic = self._detect_suspicious_traffic(
                    connections,
                    protocol_dist
                )
                
                if suspicious_traffic:
                    findings.append({
                        'type': 'suspicious_traffic',
                        'description': f'Detected {len(suspicious_traffic)} suspicious patterns',
                        'severity': 'critical',
                        'patterns': suspicious_traffic
                    })
            
            # 8. Timeline generation
            self.logger.info("Generating connection timeline...")
            timeline = self._generate_connection_timeline(connections)
            
            if timeline:
                timeline_file = self.output_dir / "network_timeline.csv"
                with open(timeline_file, 'w', newline='') as f:
                    if timeline:
                        writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
                        writer.writeheader()
                        writer.writerows(timeline)
                
                findings.append({
                    'type': 'network_timeline',
                    'description': 'Connection timeline generated',
                    'output_file': str(timeline_file)
                })
            
            # Generate comprehensive report
            report_file = self.output_dir / "network_analysis_report.json"
            with open(report_file, 'w') as f:
                json.dump({
                    'metadata': metadata,
                    'findings': findings,
                    'statistics': stats,
                    'connections': connections[:100]  # First 100 for report
                }, f, indent=2)
        
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
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
        
        metadata['analysis_end'] = utc_isoformat()
        
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
    
    def _get_pcap_statistics(self, pcap_file: Path) -> Dict:
        """Get basic PCAP statistics"""
        stats = {}
        
        try:
            # Use capinfos for statistics
            stdout, stderr, rc = self._run_command([
                'capinfos',
                str(pcap_file)
            ])
            
            for line in stdout.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    if key in ['number_of_packets', 'file_size', 'data_size']:
                        try:
                            # Extract numeric value
                            num = re.search(r'(\d+)', value)
                            if num:
                                stats[key] = int(num.group(1))
                        except:
                            stats[key] = value
                    else:
                        stats[key] = value
        
        except Exception as e:
            self.logger.warning(f"Statistics extraction failed: {e}")
            # Fallback
            stats['file_size'] = pcap_file.stat().st_size
        
        return stats
    
    def _analyze_connections(self, pcap_file: Path) -> List[Dict]:
        """Analyze all connections in PCAP"""
        connections = []
        
        try:
            # Use tshark to extract conversation data
            stdout, stderr, rc = self._run_command([
                'tshark',
                '-r', str(pcap_file),
                '-q',
                '-z', 'conv,tcp',
                '-z', 'conv,udp'
            ], timeout=300)
            
            current_proto = None
            for line in stdout.splitlines():
                if 'TCP Conversations' in line:
                    current_proto = 'TCP'
                    continue
                elif 'UDP Conversations' in line:
                    current_proto = 'UDP'
                    continue
                
                # Parse conversation line
                if current_proto and '<->' in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            src = parts[0]
                            dst = parts[2]
                            
                            # Extract IPs and ports
                            src_match = re.match(r'(.+):(\d+)', src)
                            dst_match = re.match(r'(.+):(\d+)', dst)
                            
                            if src_match and dst_match:
                                connections.append({
                                    'protocol': current_proto,
                                    'src_ip': src_match.group(1),
                                    'src_port': int(src_match.group(2)),
                                    'dst_ip': dst_match.group(1),
                                    'dst_port': int(dst_match.group(2)),
                                    'frames': parts[3],
                                    'bytes': parts[4]
                                })
                        except:
                            continue
        
        except Exception as e:
            self.logger.warning(f"Connection analysis failed: {e}")
        
        return connections
    
    def _analyze_protocol_distribution(self, pcap_file: Path) -> Dict[str, int]:
        """Analyze protocol distribution"""
        protocols = defaultdict(int)
        
        try:
            # Use tshark to get protocol hierarchy statistics
            stdout, stderr, rc = self._run_command([
                'tshark',
                '-r', str(pcap_file),
                '-q',
                '-z', 'io,phs'
            ], timeout=180)
            
            for line in stdout.splitlines():
                # Parse protocol hierarchy
                match = re.match(r'\s+(\w+)\s+frames:(\d+)', line)
                if match:
                    proto = match.group(1)
                    count = int(match.group(2))
                    protocols[proto] = count
        
        except Exception as e:
            self.logger.warning(f"Protocol analysis failed: {e}")
        
        return dict(protocols)
    
    def _analyze_dns(self, pcap_file: Path) -> List[Dict]:
        """Analyze DNS queries"""
        dns_queries = []
        
        try:
            # Extract DNS queries
            stdout, stderr, rc = self._run_command([
                'tshark',
                '-r', str(pcap_file),
                '-Y', 'dns.flags.response == 0',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'dns.qry.name',
                '-e', 'dns.qry.type',
                '-E', 'header=y',
                '-E', 'separator=|'
            ], timeout=300)
            
            lines = stdout.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:  # Skip header
                    parts = line.split('|')
                    if len(parts) >= 4:
                        dns_queries.append({
                            'timestamp': parts[0].strip(),
                            'src_ip': parts[1].strip(),
                            'query': parts[2].strip(),
                            'type': parts[3].strip()
                        })
        
        except Exception as e:
            self.logger.warning(f"DNS analysis failed: {e}")
        
        return dns_queries
    
    def _detect_suspicious_dns(self, dns_queries: List[Dict]) -> List[Dict]:
        """Detect suspicious DNS patterns"""
        suspicious = []
        
        for query in dns_queries:
            q = query.get('query', '').lower()
            
            # Check for suspicious patterns
            suspicious_reasons = []
            
            # Very long subdomain (possible tunneling)
            if len(q) > 60:
                suspicious_reasons.append('unusually_long_domain')
            
            # High entropy (possible encoded data)
            if len(q) > 20:
                unique_chars = len(set(q))
                if unique_chars / len(q) > 0.7:
                    suspicious_reasons.append('high_entropy')
            
            # Numeric subdomain
            if re.match(r'^\d+\.', q):
                suspicious_reasons.append('numeric_subdomain')
            
            # Too many subdomains
            if q.count('.') > 5:
                suspicious_reasons.append('excessive_subdomains')
            
            # DGA-like patterns (random looking strings)
            parts = q.split('.')
            if len(parts) > 1:
                subdomain = parts[0]
                if len(subdomain) > 10 and not any(vowel in subdomain for vowel in 'aeiou'):
                    suspicious_reasons.append('possible_dga')
            
            if suspicious_reasons:
                suspicious.append({
                    **query,
                    'reasons': suspicious_reasons
                })
        
        return suspicious
    
    def _analyze_http(self, pcap_file: Path) -> List[Dict]:
        """Analyze HTTP requests"""
        http_requests = []
        
        try:
            # Extract HTTP requests
            stdout, stderr, rc = self._run_command([
                'tshark',
                '-r', str(pcap_file),
                '-Y', 'http.request',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'http.request.method',
                '-e', 'http.request.uri',
                '-e', 'http.host',
                '-e', 'http.user_agent',
                '-E', 'header=y',
                '-E', 'separator=|'
            ], timeout=300)
            
            lines = stdout.splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split('|')
                    if len(parts) >= 7:
                        http_requests.append({
                            'timestamp': parts[0].strip(),
                            'src_ip': parts[1].strip(),
                            'dst_ip': parts[2].strip(),
                            'method': parts[3].strip(),
                            'uri': parts[4].strip(),
                            'host': parts[5].strip(),
                            'user_agent': parts[6].strip()
                        })
        
        except Exception as e:
            self.logger.warning(f"HTTP analysis failed: {e}")
        
        return http_requests
    
    def _detect_suspicious_http(self, http_requests: List[Dict]) -> List[Dict]:
        """Detect suspicious HTTP patterns"""
        suspicious = []
        
        for req in http_requests:
            suspicious_reasons = []
            
            uri = req.get('uri', '').lower()
            user_agent = req.get('user_agent', '').lower()
            
            # Check for suspicious URIs
            if any(keyword in uri for keyword in ['cmd.exe', 'powershell', '/etc/passwd', '../']):
                suspicious_reasons.append('suspicious_uri_keyword')
            
            # Encoded characters in URI
            if uri.count('%') > 5:
                suspicious_reasons.append('excessive_encoding')
            
            # Suspicious user agents
            suspicious_ua = ['curl', 'wget', 'python', 'powershell', 'scanner']
            if any(ua in user_agent for ua in suspicious_ua):
                suspicious_reasons.append('suspicious_user_agent')
            
            # Empty or very short user agent
            if len(user_agent) < 10:
                suspicious_reasons.append('minimal_user_agent')
            
            # POST to unusual paths
            if req.get('method') == 'POST' and any(ext in uri for ext in ['.jpg', '.png', '.gif']):
                suspicious_reasons.append('post_to_image')
            
            if suspicious_reasons:
                suspicious.append({
                    **req,
                    'reasons': suspicious_reasons
                })
        
        return suspicious
    
    def _extract_files(self, pcap_file: Path) -> List[Dict]:
        """Extract files from network streams"""
        extracted = []
        extract_dir = self.output_dir / "extracted_files"
        extract_dir.mkdir(exist_ok=True)
        
        try:
            # Use tshark to export HTTP objects
            subprocess.run([
                'tshark',
                '-r', str(pcap_file),
                '--export-objects', f'http,{extract_dir}'
            ], check=False, timeout=300, capture_output=True)
            
            # List extracted files
            for file in extract_dir.iterdir():
                if file.is_file():
                    extracted.append({
                        'filename': file.name,
                        'size': file.stat().st_size,
                        'path': str(file),
                        'hash': self._compute_hash(file)
                    })
        
        except Exception as e:
            self.logger.warning(f"File extraction failed: {e}")
        
        return extracted
    
    def _detect_suspicious_traffic(
        self,
        connections: List[Dict],
        protocol_dist: Dict[str, int]
    ) -> List[Dict]:
        """Detect suspicious traffic patterns"""
        suspicious = []
        
        # Check for connections to suspicious ports
        suspicious_ports = {
            4444: 'Common backdoor port',
            5555: 'Common backdoor port',
            6666: 'IRC/Malware C2',
            8080: 'HTTP proxy/backdoor',
            31337: 'Elite/backdoor port'
        }
        
        for conn in connections:
            dst_port = conn.get('dst_port')
            if dst_port in suspicious_ports:
                suspicious.append({
                    'type': 'suspicious_port',
                    'reason': suspicious_ports[dst_port],
                    **conn
                })
        
        # Check for excessive connections to single IP
        dst_counts = defaultdict(int)
        for conn in connections:
            dst_counts[conn.get('dst_ip')] += 1
        
        for dst_ip, count in dst_counts.items():
            if count > 100:
                suspicious.append({
                    'type': 'excessive_connections',
                    'reason': f'{count} connections to single IP',
                    'dst_ip': dst_ip,
                    'connection_count': count
                })
        
        # Check for unusual protocol usage
        total_frames = sum(protocol_dist.values())
        for proto, count in protocol_dist.items():
            percentage = (count / total_frames) * 100 if total_frames > 0 else 0
            
            # Flag if unusual protocol is >10% of traffic
            if proto.lower() in ['irc', 'telnet', 'ftp'] and percentage > 10:
                suspicious.append({
                    'type': 'unusual_protocol',
                    'reason': f'{proto} comprises {percentage:.1f}% of traffic',
                    'protocol': proto,
                    'percentage': percentage
                })
        
        return suspicious
    
    def _generate_connection_timeline(self, connections: List[Dict]) -> List[Dict]:
        """Generate timeline of connections"""
        # This is a simplified timeline; ideally would extract packet timestamps
        timeline = []
        
        for idx, conn in enumerate(connections):
            timeline.append({
                'sequence': idx,
                'protocol': conn.get('protocol'),
                'src': f"{conn.get('src_ip')}:{conn.get('src_port')}",
                'dst': f"{conn.get('dst_ip')}:{conn.get('dst_port')}",
                'frames': conn.get('frames'),
                'bytes': conn.get('bytes')
            })
        
        return timeline
