#!/usr/bin/env python3
"""
Memory Analysis Module
Memory forensics using Volatility 2 and Volatility 3

Features:
- Automatic profile/symbol detection
- Process analysis (pslist, pstree, psscan)
- Network connections (netscan, netstat)
- DLL/module analysis
- Registry extraction
- Malware detection (malfind, hollowfind)
- Timeline generation
- String extraction
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ...core.evidence import Evidence
from ...core.module import AnalysisModule, ModuleResult
from ...core.time_utils import utc_isoformat

from ...tools import volatility as volatility_wrapper


class MemoryAnalysisModule(AnalysisModule):
    TOOL_WRAPPERS = {"Volatility": volatility_wrapper}

    """
    Memory forensics module using Volatility

    Supports:
    - Volatility 2 (legacy)
    - Volatility 3 (preferred)
    - Automatic tool detection
    - Multiple analysis plugins
    """

    @property
    def name(self) -> str:
        return "memory_analysis"

    @property
    def description(self) -> str:
        return "Memory forensics using Volatility"

    @property
    def requires_root(self) -> bool:
        return False

    def validate_params(self, params: Dict) -> bool:
        """Validate parameters"""
        if "dump" not in params:
            self.logger.error("Missing required parameter: dump")
            return False

        dump = Path(params["dump"])
        if not dump.exists():
            self.logger.error(f"Memory dump not found: {dump}")
            return False

        return True

    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """Execute memory analysis"""
        result_id = self._generate_result_id()
        timestamp = utc_isoformat()

        dump = Path(params["dump"])
        profile = params.get("profile")  # Optional: Windows profile/Linux kernel

        # Analysis options
        analyze_processes = params.get("processes", "true").lower() == "true"
        analyze_network = params.get("network", "true").lower() == "true"
        analyze_registry = params.get("registry", "false").lower() == "true"
        detect_malware = params.get("malware", "true").lower() == "true"
        extract_strings = params.get("strings", "false").lower() == "true"

        findings = []
        errors = []
        metadata = {"dump": str(dump), "profile": profile, "analysis_start": timestamp}

        self.logger.info(f"Analyzing memory dump: {dump}")

        # Detect Volatility version
        vol_version = self._detect_volatility()
        if not vol_version:
            guidance = "Install volatility3 or volatility to analyze memory dumps."
            return self._missing_tool_result(
                result_id,
                ["vol", "vol3", "vol.py", "volatility"],
                metadata=metadata,
                guidance=guidance,
                timestamp=timestamp,
            )

        metadata["volatility_version"] = vol_version
        self.logger.info(f"Using Volatility {vol_version}")

        try:
            # 1. Image info / profile detection
            if not profile:
                self.logger.info("Detecting profile/symbols...")
                profile = self._detect_profile(dump, vol_version)
                metadata["detected_profile"] = profile

            findings.append(
                {
                    "type": "profile",
                    "description": "Memory dump profile/OS detected",
                    "profile": profile,
                }
            )

            # 2. Process analysis
            if analyze_processes:
                self.logger.info("Analyzing processes...")
                process_findings = self._analyze_processes(dump, profile, vol_version)
                findings.extend(process_findings)

            # 3. Network analysis
            if analyze_network:
                self.logger.info("Analyzing network connections...")
                network_findings = self._analyze_network(dump, profile, vol_version)
                findings.extend(network_findings)

            # 4. Registry analysis (Windows only)
            if analyze_registry and "Win" in profile:
                self.logger.info("Extracting registry...")
                registry_findings = self._analyze_registry(dump, profile, vol_version)
                findings.extend(registry_findings)

            # 5. Malware detection
            if detect_malware:
                self.logger.info("Detecting malware indicators...")
                malware_findings = self._detect_malware(dump, profile, vol_version)
                findings.extend(malware_findings)

            # 6. String extraction
            if extract_strings:
                self.logger.info("Extracting strings...")
                strings_file = self._extract_strings(dump)
                if strings_file:
                    findings.append(
                        {
                            "type": "strings",
                            "description": "Strings extracted from memory",
                            "output_file": str(strings_file),
                        }
                    )

            # Generate summary
            summary = self._generate_summary(findings)
            metadata.update(summary)

        except Exception as e:
            self.logger.error(f"Memory analysis failed: {e}")
            errors.append(f"Analysis failed: {e}")
            return ModuleResult(
                result_id=result_id,
                module_name=self.name,
                status="failed",
                timestamp=timestamp,
                findings=findings,
                metadata=metadata,
                errors=errors,
            )

        metadata["analysis_end"] = utc_isoformat()

        # Save comprehensive report
        report_file = self.output_dir / "memory_analysis_report.json"
        with open(report_file, "w") as f:
            json.dump(
                {"metadata": metadata, "findings": findings},
                f,
                indent=2,
                sort_keys=True,
            )

        status = "success" if not errors else "partial"

        return ModuleResult(
            result_id=result_id,
            module_name=self.name,
            status=status,
            timestamp=timestamp,
            output_path=report_file,
            findings=findings,
            metadata=metadata,
            errors=errors,
        )

    def _detect_volatility(self) -> Optional[str]:
        """Detect available Volatility version"""
        # Check Vol3 first (preferred)
        if self._verify_tool("vol") or self._verify_tool("vol3"):
            try:
                stdout, stderr, rc = self._run_command(["vol", "--help"], timeout=10)
                if rc == 0:
                    return "3"
            except Exception:
                pass

        # Check Vol2
        if self._verify_tool("vol.py") or self._verify_tool("volatility"):
            try:
                stdout, stderr, rc = self._run_command(["vol.py", "--help"], timeout=10)
                if rc == 0:
                    return "2"
            except Exception:
                pass

        return None

    def _detect_profile(self, dump: Path, vol_version: str) -> str:
        """Detect memory profile/symbols"""
        if vol_version == "3":
            # Vol3: Use imageinfo plugin
            cmd = ["vol", "-f", str(dump), "windows.info"]

            try:
                stdout, stderr, rc = self._run_command(cmd, timeout=120)

                # Parse output for OS info
                for line in stdout.splitlines():
                    if "NTBuildLab" in line:
                        # Extract Windows version
                        match = re.search(r"(\d+\.\d+\.\d+)", line)
                        if match:
                            return f"Win{match.group(1)}"

                # Fallback
                return "Win10x64_19041"
            except Exception:
                return "Win10x64_19041"

        else:  # Vol2
            cmd = ["vol.py", "-f", str(dump), "imageinfo"]

            try:
                stdout, stderr, rc = self._run_command(cmd, timeout=120)

                # Parse suggested profiles
                for line in stdout.splitlines():
                    if "Suggested Profile" in line:
                        # Extract first profile
                        match = re.search(r":\s+([^,\s]+)", line)
                        if match:
                            return match.group(1)

                return "Win7SP1x64"
            except Exception:
                return "Win7SP1x64"

    def _analyze_processes(
        self, dump: Path, profile: str, vol_version: str
    ) -> List[Dict]:
        """Analyze processes"""
        findings = []

        # Get process list
        if vol_version == "3":
            cmd = ["vol", "-f", str(dump), "windows.pslist"]
        else:
            cmd = ["vol.py", "-f", str(dump), "--profile", profile, "pslist"]

        try:
            stdout, stderr, rc = self._run_command(cmd, timeout=300)

            processes = self._parse_process_list(stdout, vol_version)

            # Save process list
            process_file = self.output_dir / "processes.json"
            with open(process_file, "w") as f:
                json.dump(processes, f, indent=2, sort_keys=True)

            findings.append(
                {
                    "type": "processes",
                    "description": f"Found {len(processes)} processes",
                    "total": len(processes),
                    "output_file": str(process_file),
                    "processes": processes[:20],  # First 20 for summary
                }
            )

            # Detect suspicious processes
            suspicious = self._detect_suspicious_processes(processes)
            if suspicious:
                findings.append(
                    {
                        "type": "suspicious_processes",
                        "description": f"Found {len(suspicious)} suspicious processes",
                        "severity": "high",
                        "processes": suspicious,
                    }
                )

        except Exception as e:
            self.logger.warning(f"Process analysis failed: {e}")

        return findings

    def _parse_process_list(self, output: str, vol_version: str) -> List[Dict]:
        """Parse process list output"""
        processes = []

        lines = output.splitlines()

        for line in lines:
            # Skip headers
            if "PID" in line or "---" in line or not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 4:
                try:
                    processes.append(
                        {
                            "pid": (
                                int(parts[0]) if vol_version == "3" else int(parts[1])
                            ),
                            "ppid": (
                                int(parts[1]) if vol_version == "3" else int(parts[2])
                            ),
                            "name": parts[2] if vol_version == "3" else parts[0],
                            "threads": (
                                int(parts[3])
                                if vol_version == "3" and len(parts) > 3
                                else 0
                            ),
                        }
                    )
                except (ValueError, IndexError):
                    continue

        return sorted(
            processes, key=lambda proc: (proc.get("pid", 0), proc.get("name", ""))
        )

    def _detect_suspicious_processes(self, processes: List[Dict]) -> List[Dict]:
        """Detect suspicious process patterns"""
        suspicious = []

        suspicious_patterns = [
            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "psexec.exe",
            "mimikatz",
            "procdump",
        ]

        for proc in processes:
            name = proc.get("name", "").lower()

            # Check suspicious names
            if any(pattern in name for pattern in suspicious_patterns):
                suspicious.append({**proc, "reason": "suspicious_name"})

            # Check unusual parent-child relationships
            elif name == "svchost.exe" and proc.get("ppid") not in [0, 4]:
                suspicious.append({**proc, "reason": "unusual_parent"})

        return suspicious

    def _analyze_network(
        self, dump: Path, profile: str, vol_version: str
    ) -> List[Dict]:
        """Analyze network connections"""
        findings = []

        if vol_version == "3":
            cmd = ["vol", "-f", str(dump), "windows.netscan"]
        else:
            cmd = ["vol.py", "-f", str(dump), "--profile", profile, "netscan"]

        try:
            stdout, stderr, rc = self._run_command(cmd, timeout=300)

            connections = self._parse_network_connections(stdout, vol_version)

            # Save connections
            network_file = self.output_dir / "network_connections.json"
            with open(network_file, "w") as f:
                json.dump(connections, f, indent=2, sort_keys=True)

            findings.append(
                {
                    "type": "network_connections",
                    "description": f"Found {len(connections)} network connections",
                    "total": len(connections),
                    "output_file": str(network_file),
                    "connections": connections[:20],
                }
            )

            # Detect suspicious connections
            suspicious_conns = self._detect_suspicious_connections(connections)
            if suspicious_conns:
                findings.append(
                    {
                        "type": "suspicious_connections",
                        "description": f"Found {len(suspicious_conns)} suspicious connections",
                        "severity": "high",
                        "connections": suspicious_conns,
                    }
                )

        except Exception as e:
            self.logger.warning(f"Network analysis failed: {e}")

        return findings

    def _parse_network_connections(self, output: str, vol_version: str) -> List[Dict]:
        """Parse network connection output"""
        connections = []

        lines = output.splitlines()

        for line in lines:
            if "Offset" in line or "---" in line or not line.strip():
                continue

            # Extract IP:Port pairs
            matches = re.findall(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            if matches:
                local = matches[0] if matches else ("", "")
                remote = matches[1] if len(matches) > 1 else ("", "")

                # Extract PID
                pid_match = re.search(r"\s(\d+)\s+", line)
                pid = int(pid_match.group(1)) if pid_match else 0

                connections.append(
                    {
                        "local_addr": local[0],
                        "local_port": int(local[1]) if local[1] else 0,
                        "remote_addr": remote[0],
                        "remote_port": int(remote[1]) if remote[1] else 0,
                        "pid": pid,
                        "state": self._extract_state(line),
                    }
                )

        return connections

    def _extract_state(self, line: str) -> str:
        """Extract connection state from line"""
        states = ["ESTABLISHED", "LISTENING", "CLOSE_WAIT", "TIME_WAIT", "CLOSED"]
        for state in states:
            if state in line:
                return state
        return "UNKNOWN"

    def _detect_suspicious_connections(self, connections: List[Dict]) -> List[Dict]:
        """Detect suspicious network connections"""
        suspicious = []

        for conn in connections:
            remote_addr = conn.get("remote_addr", "")
            remote_port = conn.get("remote_port", 0)

            # Check for private IPs connecting outbound
            if remote_addr and not self._is_private_ip(remote_addr):
                # Check suspicious ports
                if remote_port in [4444, 5555, 6666, 7777, 8080, 8888, 9999]:
                    suspicious.append({**conn, "reason": "suspicious_port"})
                # IRC ports
                elif remote_port in [6667, 6668, 6669]:
                    suspicious.append({**conn, "reason": "irc_port"})

        return suspicious

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False

        try:
            octets = [int(p) for p in parts]

            # 10.0.0.0/8
            if octets[0] == 10:
                return True
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True

            return False
        except ValueError:
            return False

    def _analyze_registry(
        self, dump: Path, profile: str, vol_version: str
    ) -> List[Dict]:
        """Extract registry information"""
        findings = []

        # Extract registry hives
        if vol_version == "3":
            cmd = ["vol", "-f", str(dump), "windows.registry.hivelist"]
        else:
            cmd = ["vol.py", "-f", str(dump), "--profile", profile, "hivelist"]

        try:
            stdout, stderr, rc = self._run_command(cmd, timeout=180)

            hives = []
            for line in stdout.splitlines():
                if "Registry" in line or "HKEY" in line:
                    hives.append(line.strip())

            findings.append(
                {
                    "type": "registry_hives",
                    "description": f"Found {len(hives)} registry hives",
                    "hives": hives[:10],
                }
            )

        except Exception as e:
            self.logger.warning(f"Registry analysis failed: {e}")

        return findings

    def _detect_malware(self, dump: Path, profile: str, vol_version: str) -> List[Dict]:
        """Detect malware indicators"""
        findings = []

        # Run malfind
        if vol_version == "3":
            cmd = ["vol", "-f", str(dump), "windows.malfind"]
        else:
            cmd = ["vol.py", "-f", str(dump), "--profile", profile, "malfind"]

        try:
            stdout, stderr, rc = self._run_command(cmd, timeout=600)

            # Parse malfind output
            injections = []
            current_proc = {}

            for line in stdout.splitlines():
                if "Process:" in line:
                    if current_proc:
                        injections.append(current_proc)
                    current_proc = {"process": line.split("Process:")[1].strip()}
                elif "PID:" in line:
                    current_proc["pid"] = line.split("PID:")[1].strip()
                elif "0x" in line and len(line) > 20:
                    current_proc["address"] = line.split()[0]

            if current_proc:
                injections.append(current_proc)

            if injections:
                findings.append(
                    {
                        "type": "code_injection",
                        "description": f"Found {len(injections)} potential code injections",
                        "severity": "critical",
                        "injections": injections,
                    }
                )

        except Exception as e:
            self.logger.warning(f"Malware detection failed: {e}")

        return findings

    def _extract_strings(self, dump: Path) -> Optional[Path]:
        """Extract strings from memory dump"""
        strings_file = self.output_dir / "memory_strings.txt"

        cmd = ["strings", "-a", "-t", "d", str(dump)]

        try:
            with open(strings_file, "w") as f:
                # TODO: use forensic.tools.volatility wrapper for string extraction
                subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=600)

            return strings_file
        except Exception as e:
            self.logger.warning(f"String extraction failed: {e}")
            return None

    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate analysis summary"""
        summary = {}

        for finding in findings:
            ftype = finding.get("type")

            if ftype == "processes":
                summary["total_processes"] = finding.get("total", 0)
            elif ftype == "network_connections":
                summary["total_connections"] = finding.get("total", 0)
            elif ftype == "suspicious_processes":
                summary["suspicious_processes"] = len(finding.get("processes", []))
            elif ftype == "suspicious_connections":
                summary["suspicious_connections"] = len(finding.get("connections", []))
            elif ftype == "code_injection":
                summary["code_injections"] = len(finding.get("injections", []))

        return summary
