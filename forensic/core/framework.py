#!/usr/bin/env python3
"""
Forensic Framework Core
Central orchestrator for forensic investigations
"""

import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, Iterable, List, Optional, Set, Type

# ``PyYAML`` is optional at runtime. Import lazily and provide a helpful
# message if pipeline definitions rely on it while the dependency is missing.
try:  # pragma: no cover - behaviour depends on environment
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    yaml = None  # type: ignore[assignment]

from forensic.utils.hashing import compute_hash

from .chain_of_custody import ChainOfCustody
from .chain_of_custody import append_coc as append_coc_record
from .config import FrameworkConfig, get_config, load_yaml
from .evidence import Evidence, EvidenceType
from .logger import setup_logging
from .module import ForensicModule, ModuleResult
from .time_utils import utc_isoformat, utc_slug


@dataclass
class Case:
    """Forensic case representation"""

    case_id: str
    name: str
    description: str
    investigator: str
    created_at: str
    case_dir: Path
    evidence: List[Evidence] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ForensicFramework:
    """
    Main forensic framework orchestrator

    Features:
    - Case management
    - Module registration and execution
    - Pipeline execution
    - Chain of custody tracking
    - Evidence management
    - Reporting
    """

    def __init__(
        self, config_file: Optional[Path] = None, workspace: Optional[Path] = None
    ):
        """
        Initialize framework

        Args:
            config_file: Path to configuration file
            workspace: Workspace directory
        """
        self.workspace = workspace or Path.cwd() / "forensic_workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)

        # Load configuration
        self.config_obj: FrameworkConfig = self._load_config(config_file)
        self.config = self.config_obj.as_dict()

        # Setup logging
        self.logger = setup_logging(
            self.workspace / "logs", level=self.config.get("log_level", "INFO")
        )

        # Initialize database
        self.db_path = self.workspace / "cases.db"
        self._init_database()

        # Module registry
        self._modules: Dict[str, Type[ForensicModule]] = {}

        # Chain of custody
        self.coc = ChainOfCustody(self.workspace / "chain_of_custody.db")

        # Current case
        self.current_case: Optional[Case] = None

        self.logger.info(f"Forensic Framework initialized. Workspace: {self.workspace}")

    def _load_config(self, config_file: Optional[Path]) -> FrameworkConfig:
        """Load configuration via :mod:`forensic.core.config`."""

        overrides: Dict[str, Any] = {}
        config_root: Optional[Path] = None

        if config_file:
            config_file = config_file.expanduser()
            if config_file.is_file():
                try:
                    overrides = load_yaml(config_file)
                except Exception as exc:  # pragma: no cover - rare path
                    print(
                        f"Warning: Failed to load config {config_file}: {exc}",
                        file=sys.stderr,
                    )
                config_root = config_file.parent
            elif config_file.is_dir():
                config_root = config_file

        return get_config(config_root=config_root, overrides=overrides)

    def _init_database(self):
        """Initialize SQLite database for case management"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                investigator TEXT,
                created_at TEXT,
                case_dir TEXT,
                metadata TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT,
                evidence_type TEXT,
                source_path TEXT,
                description TEXT,
                collected_at TEXT,
                hash_sha256 TEXT,
                metadata TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS module_results (
                result_id TEXT PRIMARY KEY,
                case_id TEXT,
                module_name TEXT,
                executed_at TEXT,
                status TEXT,
                output_path TEXT,
                metadata TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
        """
        )

        conn.commit()
        conn.close()

    def register_module(self, name: str, module_class: Type[ForensicModule]):
        """
        Register a forensic module

        Args:
            name: Module name
            module_class: Module class (subclass of ForensicModule)
        """
        if not issubclass(module_class, ForensicModule):
            raise TypeError(f"{module_class} must be subclass of ForensicModule")

        self._modules[name] = module_class
        self.logger.info(f"Registered module: {name}")

    def create_case(
        self,
        name: str,
        description: str,
        investigator: str,
        case_id: Optional[str] = None,
    ) -> Case:
        """
        Create new forensic case

        Args:
            name: Case name
            description: Case description
            investigator: Investigator name
            case_id: Optional case ID (auto-generated if not provided)

        Returns:
            Case object
        """
        if case_id is None:
            case_id = f"CASE_{utc_slug()}"

        case_dir = self.workspace / "cases" / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        # Create case subdirectories
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "analysis").mkdir(exist_ok=True)
        (case_dir / "reports").mkdir(exist_ok=True)
        (case_dir / "logs").mkdir(exist_ok=True)
        (case_dir / "meta").mkdir(exist_ok=True)

        case = Case(
            case_id=case_id,
            name=name,
            description=description,
            investigator=investigator,
            created_at=utc_isoformat(),
            case_dir=case_dir,
        )

        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO cases (case_id, name, description, investigator, created_at, case_dir, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.case_id,
                case.name,
                case.description,
                case.investigator,
                case.created_at,
                str(case.case_dir),
                json.dumps(case.metadata, sort_keys=True),
            ),
        )
        conn.commit()
        conn.close()

        # Log to CoC
        if self.config.get("enable_coc"):
            self.coc.log_event(
                event_type="CASE_CREATED",
                case_id=case_id,
                description=f"Case created: {name}",
                actor=investigator,
            )

        self.current_case = case
        self.logger.info(f"Created case: {case_id} - {name}")

        return case

    def load_case(self, case_id: str) -> Case:
        """Load existing case from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise ValueError(f"Case not found: {case_id}")

        case = Case(
            case_id=row[0],
            name=row[1],
            description=row[2],
            investigator=row[3],
            created_at=row[4],
            case_dir=Path(row[5]),
            metadata=json.loads(row[6]) if row[6] else {},
        )

        self.current_case = case
        self.logger.info(f"Loaded case: {case_id}")

        return case

    def add_evidence(
        self,
        evidence_type: EvidenceType,
        source_path: Path,
        description: str,
        metadata: Optional[Dict] = None,
    ) -> Evidence:
        """
        Add evidence to current case

        Args:
            evidence_type: Type of evidence
            source_path: Path to evidence
            description: Description
            metadata: Additional metadata

        Returns:
            Evidence object
        """
        if not self.current_case:
            raise RuntimeError("No active case. Create or load a case first.")

        evidence = Evidence(
            evidence_type=evidence_type,
            source_path=source_path,
            description=description,
            metadata=metadata or {},
        )

        # Copy to case evidence directory
        dest_path = self.current_case.case_dir / "evidence" / source_path.name
        if source_path.is_file():
            import shutil

            shutil.copy2(source_path, dest_path)
            evidence.hash_sha256 = self._compute_hash(dest_path)

        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO evidence (
                evidence_id, case_id, evidence_type, source_path,
                description, collected_at, hash_sha256, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.evidence_id,
                self.current_case.case_id,
                evidence.evidence_type.value,
                str(source_path),
                description,
                evidence.collected_at,
                evidence.hash_sha256,
                json.dumps(evidence.metadata, sort_keys=True),
            ),
        )
        conn.commit()
        conn.close()

        # Log to CoC
        if self.config.get("enable_coc"):
            self.coc.log_event(
                event_type="EVIDENCE_ADDED",
                case_id=self.current_case.case_id,
                evidence_id=evidence.evidence_id,
                description=f"Evidence added: {description}",
                actor=self.current_case.investigator,
                metadata={"hash": evidence.hash_sha256},
            )

        self.current_case.evidence.append(evidence)
        self.logger.info(f"Added evidence: {evidence.evidence_id}")

        return evidence

    def execute_module(
        self,
        module_name: str,
        evidence: Optional[Evidence] = None,
        params: Optional[Dict] = None,
    ) -> ModuleResult:
        """
        Execute a forensic module

        Args:
            module_name: Name of registered module
            evidence: Evidence to analyze
            params: Module parameters

        Returns:
            ModuleResult
        """
        if not self.current_case:
            raise RuntimeError("No active case")

        if module_name not in self._modules:
            raise ValueError(f"Module not registered: {module_name}")

        params = params or {}

        # Instantiate module
        module_class = self._modules[module_name]
        module = module_class(case_dir=self.current_case.case_dir, config=self.config)

        module_versions = self._resolve_tool_versions(module)
        start_ts = utc_isoformat()
        start_time = perf_counter()
        result: Optional[ModuleResult] = None
        artifact_records: List[Dict[str, str]] = []
        error: Optional[Exception] = None

        self.logger.info(f"Executing module: {module_name}")

        # Log to CoC
        if self.config.get("enable_coc"):
            self.coc.log_event(
                event_type="MODULE_EXECUTION_START",
                case_id=self.current_case.case_id,
                description=f"Module execution started: {module_name}",
                actor=self.current_case.investigator,
            )

        try:
            result = module.execute(evidence=evidence, params=params)

            # Save result to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO module_results (
                    result_id, case_id, module_name, executed_at,
                    status, output_path, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.result_id,
                    self.current_case.case_id,
                    module_name,
                    result.timestamp,
                    result.status,
                    str(result.output_path) if result.output_path else None,
                    json.dumps(result.metadata, sort_keys=True),
                ),
            )
            conn.commit()
            conn.close()

            artifact_paths = self._collect_artifact_paths(result)
            artifact_records = [
                {"path": str(path), "sha256": compute_hash(path)}
                for path in artifact_paths
            ]

            # Log to CoC
            if self.config.get("enable_coc"):
                metadata = {"result_id": result.result_id}
                if artifact_records:
                    metadata["artifacts"] = artifact_records
                    for artifact in artifact_records:
                        self.append_coc(artifact["path"], artifact["sha256"])
                self.coc.log_event(
                    event_type="MODULE_EXECUTION_COMPLETE",
                    case_id=self.current_case.case_id,
                    description=f"Module execution completed: {module_name} - {result.status}",
                    actor=self.current_case.investigator,
                    metadata=metadata,
                )

            self.logger.info(f"Module executed: {module_name} - {result.status}")

            return result
        except Exception as e:
            error = e
            self.logger.error(f"Module execution failed: {module_name} - {e}")

            if self.config.get("enable_coc"):
                self.coc.log_event(
                    event_type="MODULE_EXECUTION_FAILED",
                    case_id=self.current_case.case_id,
                    description=f"Module execution failed: {module_name} - {str(e)}",
                    actor=self.current_case.investigator,
                )

            raise
        finally:
            duration = perf_counter() - start_time
            try:
                self._record_provenance(
                    ts=start_ts,
                    module=module_name,
                    params=params,
                    tool_versions=module_versions,
                    inputs=self._build_input_metadata(evidence),
                    outputs=[entry["path"] for entry in artifact_records],
                    sha256=artifact_records,
                    duration=duration,
                    exit_code=self._status_to_exit_code(result, error),
                    result=result,
                )
            except Exception as provenance_error:  # pragma: no cover - defensive
                self.logger.warning(
                    f"Failed to record provenance for {module_name}: {provenance_error}"
                )

    def execute_pipeline(self, pipeline_file: Path):
        """
        Execute a forensic pipeline

        Pipeline YAML format:
            name: "Incident Response Pipeline"
            description: "Full IR workflow"
            modules:
              - name: disk_imaging
                params:
                  source: /dev/sdb
                  output: disk.img
              - name: memory_analysis
                params:
                  dump: memory.dmp
        """
        if not self.current_case:
            raise RuntimeError("No active case")

        if yaml is None:
            raise RuntimeError(
                "PyYAML is required to load pipeline definitions. Install it via "
                "'pip install pyyaml'."
            )

        with open(pipeline_file) as f:
            pipeline = yaml.safe_load(f)

        self.logger.info(f"Executing pipeline: {pipeline.get('name', 'Unnamed')}")

        results = []
        for step in pipeline.get("modules", []):
            module_name = step.get("name")
            params = step.get("params", {})

            try:
                result = self.execute_module(module_name, params=params)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Pipeline step failed: {module_name} - {e}")
                if not step.get("continue_on_error", False):
                    raise

        return results

    def generate_report(self, output_path: Optional[Path] = None, format: str = "html"):
        """Generate case report"""
        if not self.current_case:
            raise RuntimeError("No active case")

        if output_path is None:
            output_path = (
                self.current_case.case_dir / "reports" / f"report_{utc_slug()}.{format}"
            )

        # TODO: Implement report generation with Jinja2 templates
        self.logger.info(f"Generating report: {output_path}")

    def _resolve_tool_versions(self, module: ForensicModule) -> Dict[str, str]:
        versions: Dict[str, str] = {}
        try:
            reported = module.tool_versions()
        except Exception:  # pragma: no cover - defensive
            reported = {}

        if isinstance(reported, dict):
            for key, value in reported.items():
                versions[str(key)] = str(value)

        versions.setdefault(module.name, getattr(module, "version", ""))
        return versions

    def _build_input_metadata(self, evidence: Optional[Evidence]) -> Dict[str, Any]:
        if evidence is None:
            return {}

        payload: Dict[str, Any] = {}
        evidence_id = getattr(evidence, "evidence_id", None)
        if evidence_id:
            payload["evidence_id"] = evidence_id

        source_path = getattr(evidence, "source_path", None)
        if source_path:
            payload["source_path"] = str(source_path)

        evidence_type = getattr(evidence, "evidence_type", None)
        if evidence_type is not None:
            payload["type"] = getattr(evidence_type, "value", str(evidence_type))

        return payload

    def _resolve_artifact_path(self, value: Any) -> Optional[Path]:
        if not value or not self.current_case:
            return None

        try:
            candidate = Path(value)
        except TypeError:
            return None

        candidate = candidate.expanduser()
        if not candidate.is_absolute():
            candidate = (self.current_case.case_dir / candidate).resolve()
        else:
            candidate = candidate.resolve()

        if candidate.exists() and candidate.is_file():
            return candidate
        return None

    def _collect_artifact_paths(self, result: ModuleResult) -> List[Path]:
        paths: Set[Path] = set()

        if result.output_path:
            resolved = self._resolve_artifact_path(result.output_path)
            if resolved:
                paths.add(resolved)

        metadata = result.metadata or {}
        for key in ("artifacts", "outputs", "files"):
            value = metadata.get(key)
            if isinstance(value, list | tuple | set):
                for item in value:
                    resolved = self._resolve_artifact_path(item)
                    if resolved:
                        paths.add(resolved)
            else:
                resolved = self._resolve_artifact_path(value)
                if resolved:
                    paths.add(resolved)

        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            for key in ("output_file", "artifact", "path", "file"):
                resolved = self._resolve_artifact_path(finding.get(key))
                if resolved:
                    paths.add(resolved)

        return sorted(paths, key=lambda item: str(item))

    def _status_to_exit_code(
        self, result: Optional[ModuleResult], error: Optional[Exception]
    ) -> int:
        if result is None:
            return -1 if error else 1

        mapping = {"success": 0, "partial": 2, "failed": 1}
        return mapping.get(result.status.lower(), 1)

    def _record_provenance(
        self,
        *,
        ts: str,
        module: str,
        params: Dict[str, Any],
        tool_versions: Dict[str, str],
        inputs: Dict[str, Any],
        outputs: Iterable[str],
        sha256: Iterable[Dict[str, str]],
        duration: float,
        exit_code: int,
        result: Optional[ModuleResult],
    ) -> None:
        if not self.current_case:
            return

        outputs_list = sorted({str(path) for path in outputs})
        sha_entries = sorted(
            ({"path": entry["path"], "sha256": entry["sha256"]} for entry in sha256),
            key=lambda item: item["path"],
        )

        record: Dict[str, Any] = {
            "ts": ts,
            "module": module,
            "params": params,
            "tool_versions": dict(sorted(tool_versions.items())),
            "inputs": inputs,
            "outputs": outputs_list,
            "sha256": sha_entries,
            "duration": round(duration, 6),
            "exit_code": exit_code,
        }

        if result is not None:
            record["result_id"] = result.result_id
            record["status"] = result.status

        self.append_provenance(record)

    def append_provenance(self, entry: Dict[str, Any]) -> None:
        """Append ``entry`` to the case provenance log without duplicates."""

        if not self.current_case:
            return

        provenance_dir = self.current_case.case_dir / "meta"
        provenance_dir.mkdir(exist_ok=True)
        provenance_file = provenance_dir / "provenance.jsonl"

        canonical = json.dumps(entry, sort_keys=True)
        result_id = entry.get("result_id")

        if provenance_file.exists():
            with provenance_file.open("r", encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if result_id:
                        try:
                            existing = json.loads(stripped)
                        except json.JSONDecodeError:
                            continue
                        if existing.get("result_id") == result_id:
                            return
                        existing_canonical = json.dumps(existing, sort_keys=True)
                        if existing_canonical == canonical:
                            return
                    elif stripped == canonical:
                        return

        with provenance_file.open("a", encoding="utf-8") as handle:
            handle.write(canonical + "\n")

    def append_coc(self, path: str | Path, sha256: str) -> None:
        """Record artifact metadata in the case chain-of-custody log."""

        if not self.current_case:
            return

        meta_dir = self.current_case.case_dir / "meta"
        meta_dir.mkdir(exist_ok=True)
        coc_file = meta_dir / "chain_of_custody.jsonl"
        append_coc_record(coc_file, str(Path(path)), sha256)

    def _compute_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Compute file hash"""

        return compute_hash(Path(file_path), algorithm)

    def list_cases(self) -> List[Dict]:
        """List all cases"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT case_id, name, description, investigator, created_at FROM cases"
        )
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "case_id": row[0],
                "name": row[1],
                "description": row[2],
                "investigator": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    def list_modules(self) -> List[str]:
        """List registered modules"""
        return list(self._modules.keys())
