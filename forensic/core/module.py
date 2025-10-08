#!/usr/bin/env python3
"""
Forensic Module Base Class
All forensic modules inherit from this base
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .evidence import Evidence


@dataclass
class ModuleResult:
    """Result of module execution"""
    result_id: str
    module_name: str
    status: str  # success, failed, partial
    timestamp: str
    output_path: Optional[Path] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class ForensicModule(ABC):
    """
    Base class for all forensic modules
    
    All modules must implement:
    - name property
    - description property
    - validate_params method
    - run method
    """
    
    def __init__(self, case_dir: Path, config: Dict):
        """
        Initialize module
        
        Args:
            case_dir: Case directory
            config: Framework configuration
        """
        self.case_dir = case_dir
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Module output directory
        self.output_dir = case_dir / "analysis" / self.name
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Module name"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Module description"""
        pass
    
    @property
    def version(self) -> str:
        """Module version"""
        return "1.0.0"
    
    @property
    def author(self) -> str:
        """Module author"""
        return "Forensic-Playbook"
    
    @property
    def requires_root(self) -> bool:
        """Whether module requires root privileges"""
        return False
    
    @property
    def supported_evidence_types(self) -> List[str]:
        """List of supported evidence types"""
        return []
    
    @abstractmethod
    def validate_params(self, params: Dict) -> bool:
        """
        Validate module parameters
        
        Args:
            params: Parameters dictionary
        
        Returns:
            True if valid, False otherwise
        """
        pass
    
    @abstractmethod
    def run(self, evidence: Optional[Evidence], params: Dict) -> ModuleResult:
        """
        Execute module logic
        
        Args:
            evidence: Evidence object (if applicable)
            params: Module parameters
        
        Returns:
            ModuleResult object
        """
        pass
    
    def execute(self, evidence: Optional[Evidence] = None, params: Optional[Dict] = None) -> ModuleResult:
        """
        Execute module with pre/post processing
        
        This method should not be overridden. Override run() instead.
        
        Args:
            evidence: Evidence object
            params: Module parameters
        
        Returns:
            ModuleResult
        """
        params = params or {}
        
        # Validate parameters
        if not self.validate_params(params):
            return ModuleResult(
                result_id=self._generate_result_id(),
                module_name=self.name,
                status="failed",
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=["Parameter validation failed"]
            )
        
        # Check root requirement
        if self.requires_root and not self._is_root():
            return ModuleResult(
                result_id=self._generate_result_id(),
                module_name=self.name,
                status="failed",
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=["Module requires root privileges"]
            )
        
        # Pre-execution hook
        self.pre_execute(evidence, params)
        
        # Execute
        self.logger.info(f"Executing module: {self.name}")
        try:
            result = self.run(evidence, params)
            self.logger.info(f"Module execution complete: {self.name} - {result.status}")
        except Exception as e:
            self.logger.error(f"Module execution failed: {self.name} - {e}")
            result = ModuleResult(
                result_id=self._generate_result_id(),
                module_name=self.name,
                status="failed",
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=[str(e)]
            )
        
        # Post-execution hook
        self.post_execute(result)
        
        return result
    
    def pre_execute(self, evidence: Optional[Evidence], params: Dict):
        """Pre-execution hook (can be overridden)"""
        pass
    
    def post_execute(self, result: ModuleResult):
        """Post-execution hook (can be overridden)"""
        pass
    
    def _generate_result_id(self) -> str:
        """Generate unique result ID"""
        return f"{self.name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    def _is_root(self) -> bool:
        """Check if running as root"""
        import os
        return os.geteuid() == 0
    
    def _run_command(self, cmd: List[str], timeout: int = 300) -> tuple:
        """
        Run external command
        
        Args:
            cmd: Command as list
            timeout: Timeout in seconds
        
        Returns:
            (stdout, stderr, returncode)
        """
        import subprocess
        
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {' '.join(cmd)}")
            raise
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            raise
    
    def _compute_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Compute file hash"""
        import hashlib
        
        h = getattr(hashlib, algorithm)()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        
        return h.hexdigest()
    
    def _verify_tool(self, tool_name: str) -> bool:
        """Verify that required tool is installed"""
        import shutil
        return shutil.which(tool_name) is not None
    
    def save_result(self, result: ModuleResult, filename: str = "result.json"):
        """
        Save result to file
        
        Args:
            result: ModuleResult object
            filename: Output filename
        """
        import json
        
        output_file = self.output_dir / filename
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        
        self.logger.info(f"Result saved: {output_file}")
    
    def log_finding(self, finding: Dict[str, Any]):
        """
        Log a finding
        
        Args:
            finding: Finding dictionary
        """
        self.logger.info(f"Finding: {finding}")


# Helper classes for common module patterns

class AcquisitionModule(ForensicModule):
    """Base class for data acquisition modules"""
    
    @property
    def category(self) -> str:
        return "acquisition"


class AnalysisModule(ForensicModule):
    """Base class for analysis modules"""
    
    @property
    def category(self) -> str:
        return "analysis"


class TriageModule(ForensicModule):
    """Base class for triage modules"""
    
    @property
    def category(self) -> str:
        return "triage"


class ReportingModule(ForensicModule):
    """Base class for reporting modules"""
    
    @property
    def category(self) -> str:
        return "reporting"
