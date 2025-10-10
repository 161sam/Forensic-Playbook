#!/usr/bin/env python3
"""Forensic module base classes and guard helpers."""

from __future__ import annotations

import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from forensic.utils.hashing import compute_hash

from .evidence import Evidence
from .time_utils import isoformat_with_timezone, utc_slug


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

    @property
    def timezone(self) -> str:
        """Return the configured timezone for timestamp formatting."""

        tz_value = (
            self.config.get("timezone") if isinstance(self.config, dict) else None
        )
        return str(tz_value) if tz_value else "UTC"

    def tool_versions(self) -> Dict[str, str]:
        """Return tool version metadata for provenance logging."""

        return {}

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

    def execute(
        self, evidence: Optional[Evidence] = None, params: Optional[Dict] = None
    ) -> ModuleResult:
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
                timestamp=self.current_timestamp(),
                errors=["Parameter validation failed"],
            )

        # Check root requirement
        if self.requires_root:
            guard = self.require_root()
            if guard is not None:
                return guard

        # Pre-execution hook
        self.pre_execute(evidence, params)

        # Execute
        self.logger.info(f"Executing module: {self.name}")
        try:
            result = self.run(evidence, params)
            self.logger.info(
                f"Module execution complete: {self.name} - {result.status}"
            )
        except Exception as e:
            self.logger.error(f"Module execution failed: {self.name} - {e}")
            result = ModuleResult(
                result_id=self._generate_result_id(),
                module_name=self.name,
                status="failed",
                timestamp=self.current_timestamp(),
                errors=[str(e)],
            )

        # Post-execution hook
        self.post_execute(result)

        return result

    def _module_config(self, *aliases: str) -> Dict[str, Any]:
        """Return merged configuration defaults for the module.

        The configuration precedence is::

            modules.<alias>
            modules.<module-name>
            <alias>
            <module-name>

        Earlier lookups in the list provide the baseline while later
        lookups override previously discovered defaults.  This enables a
        shared section such as ``network`` to provide organisation-wide
        defaults while module specific sections (for example
        ``network_capture``) can refine individual parameters.
        """

        config: Dict[str, Any] = dict(self.config or {})
        modules_section = config.get("modules")

        ordered_aliases = list(aliases)
        if self.name not in ordered_aliases:
            ordered_aliases.append(self.name)

        def _iter_sections(root: Optional[Dict[str, Any]], keys: list[str]):
            if not isinstance(root, dict):
                return
            for key in keys:
                section = root.get(key)
                if isinstance(section, dict):
                    yield section

        sections = []
        # Shared ``modules`` section first so module specific overrides
        # replace organisation defaults.
        if isinstance(modules_section, dict):
            sections.extend(_iter_sections(modules_section, ordered_aliases))

        # Top-level aliases allow referencing sections without the
        # ``modules`` indirection.
        sections.extend(_iter_sections(config, ordered_aliases))

        merged: Dict[str, Any] = {}
        for section in sections:
            merged.update(section)

        return merged

    def pre_execute(self, evidence: Optional[Evidence], params: Dict) -> None:
        """Pre-execution hook (can be overridden)."""
        _ = (evidence, params)
        return None

    def post_execute(self, result: ModuleResult) -> None:
        """Post-execution hook (can be overridden)."""
        _ = result
        return None

    def _generate_result_id(self) -> str:
        """Generate unique result ID"""
        return f"{self.name}_{utc_slug()}_{uuid.uuid4().hex[:8]}"

    def current_timestamp(self) -> str:
        """Return an ISO-8601 timestamp respecting the configured timezone."""

        return isoformat_with_timezone(self.timezone)

    def _is_root(self) -> bool:
        """Check if running as root"""
        return os.geteuid() == 0

    def resolve_param(
        self,
        name: str,
        *paths: str,
        params: Optional[Mapping[str, Any]] = None,
        default: Any = None,
    ) -> Any:
        """Resolve ``name`` honouring CLI parameters before configuration.

        Args:
            name: Parameter name to resolve.
            *paths: Optional configuration section aliases passed to
                :meth:`_module_config`.
            params: Explicit CLI parameters provided to the module.
            default: Default value returned when no overrides are present.

        Returns:
            The resolved parameter value following the precedence rules.
        """

        params = params or {}
        if name in params and params[name] is not None:
            return params[name]

        config_defaults = self._module_config(*paths)
        if name in config_defaults:
            return config_defaults[name]

        return default

    def dry_run_notice(self, steps: Sequence[str] | None = None) -> Dict[str, Any]:
        """Log the steps that would be executed during a dry-run."""

        step_list = [step for step in list(steps or []) if step]
        if step_list:
            self.logger.info("Dry-run mode active. Planned steps:")
            for step in step_list:
                self.logger.info("  • %s", step)
        else:
            self.logger.info("Dry-run mode active. No actions will be performed.")

        return {"dry_run": True, "planned_steps": step_list}

    def guard_result(
        self,
        message: str,
        hints: Optional[Sequence[str]] = None,
        *,
        status: str = "skipped",
        metadata: Optional[Dict[str, Any]] = None,
        result_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> ModuleResult:
        """Return a friendly guard result without raising errors."""

        hint_list = [hint for hint in (hints or []) if hint]
        diagnostics_hint = "Run `forensic-cli diagnostics` to inspect guard status."
        if diagnostics_hint not in hint_list:
            hint_list.append(diagnostics_hint)

        self.logger.warning(message)
        for hint in hint_list:
            self.logger.info("Hint: %s", hint)

        guard_meta = {
            "message": message,
            "hints": hint_list,
        }

        meta = dict(metadata or {})
        existing_guard = meta.get("guard")
        if isinstance(existing_guard, dict):
            guard_meta = {**existing_guard, **guard_meta}
        resolved_timestamp = timestamp or self.current_timestamp()
        guard_meta.setdefault("timestamp", resolved_timestamp)
        meta["guard"] = guard_meta

        return ModuleResult(
            result_id=result_id or self._generate_result_id(),
            module_name=self.name,
            status=status,
            timestamp=resolved_timestamp,
            findings=[],
            metadata=meta,
            errors=[],
        )

    def require_tools(
        self,
        tools: Sequence[str] | str,
        *,
        guidance: Optional[str] = None,
        status: str = "skipped",
    ) -> Optional[ModuleResult]:
        """Verify external tooling is available and return a guard result when missing."""

        tool_names = [tools] if isinstance(tools, str) else list(tools)
        missing = sorted(tool for tool in tool_names if not self._verify_tool(tool))
        if not missing:
            return None

        hints: list[str] = []
        if guidance:
            hints.append(guidance)
        hints.append(f"Install or expose the tool(s): {', '.join(missing)}")

        metadata = {"missing_tools": missing}
        return self.guard_result(
            f"Missing required tool(s): {', '.join(missing)}",
            hints=hints,
            status=status,
            metadata=metadata,
        )

    def require_root(self) -> Optional[ModuleResult]:
        """Ensure the module is executed with root privileges when required."""

        if self._is_root():
            return None

        hints = ["Re-run the command with elevated privileges (e.g. sudo)."]
        metadata = {"requires_root": True}
        return self.guard_result(
            "Module requires root privileges to continue.",
            hints=hints,
            metadata=metadata,
        )

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
                cmd, capture_output=True, text=True, timeout=timeout, check=False
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

        return compute_hash(Path(file_path), algorithm)

    def _verify_tool(self, tool_name: str) -> bool:
        """Verify that required tool is installed"""
        import shutil

        return shutil.which(tool_name) is not None

    def _missing_tool_result(
        self,
        result_id: str,
        tools: str | Sequence[str],
        *,
        metadata: Optional[Dict[str, Any]] = None,
        guidance: Optional[str] = None,
        status: str = "skipped",
        timestamp: Optional[str] = None,
    ) -> ModuleResult:
        """Return a consistent result when required tooling is unavailable."""

        tool_list = [tools] if isinstance(tools, str) else list(tools)
        message = guidance or f"Missing required tool(s): {', '.join(tool_list)}"
        meta = dict(metadata or {})
        meta.setdefault("missing_tools", tool_list)
        hints: list[str] = []
        if guidance:
            hints.append(guidance)
        hints.append(f"Install or expose the tool(s): {', '.join(tool_list)}")

        return self.guard_result(
            message,
            hints=hints,
            status=status,
            metadata=meta,
            result_id=result_id,
            timestamp=timestamp,
        )

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
            json.dump(asdict(result), f, indent=2, default=str, sort_keys=True)

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
