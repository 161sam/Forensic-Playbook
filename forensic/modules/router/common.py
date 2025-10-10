"""Shared helpers and base classes for guarded router modules."""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from forensic.core.config import load_yaml
from forensic.core.module import ForensicModule
from forensic.core.time_utils import utc_isoformat, utc_slug
from forensic.utils.hashing import compute_hash


def _candidate_config_roots() -> List[Path]:
    """Return candidate configuration roots in deterministic order."""

    candidates: List[Path] = []
    env_specific = os.environ.get("FORENSIC_ROUTER_CONFIG")
    if env_specific:
        candidates.append(Path(env_specific).expanduser())

    env_dir = os.environ.get("FORENSIC_CONFIG_DIR")
    if env_dir:
        candidates.append(Path(env_dir).expanduser())

    package_root = Path(__file__).resolve().parents[2] / "config"
    candidates.append(package_root)

    cwd_config = Path.cwd() / "config"
    if cwd_config not in candidates:
        candidates.append(cwd_config)

    normalized: List[Path] = []
    for candidate in candidates:
        resolved = Path(candidate).resolve()
        if resolved not in normalized:
            normalized.append(resolved)
    return normalized


def load_router_defaults(name: str) -> Dict[str, Any]:
    """Load router module defaults from YAML configuration files."""

    filenames: List[Path] = [
        Path("modules") / "router" / f"{name}.yaml",
        Path("modules") / f"router_{name}.yaml",
        Path("router") / f"{name}.yaml",
        Path(f"router_{name}.yaml"),
    ]

    for root in _candidate_config_roots():
        for relative in filenames:
            candidate = root / relative
            if candidate.exists():
                try:
                    data = load_yaml(candidate)
                except Exception:  # pragma: no cover - configuration parsing is validated elsewhere
                    continue
                if isinstance(data, Mapping):
                    return dict(data)
    return {}


def resolve_parameters(
    cli_params: Mapping[str, Any],
    config_defaults: Mapping[str, Any],
    builtin_defaults: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Merge parameters with precedence CLI > config > built-in defaults."""

    resolved: Dict[str, Any] = {}
    sources: Dict[str, str] = {}

    def _update(key: str, value: Any, source: str) -> None:
        if value in (None, ""):
            return
        resolved[key] = value
        sources[key] = source

    for key, builtin in builtin_defaults.items():
        if key in cli_params and cli_params[key] not in (None, ""):
            _update(key, cli_params[key], "cli")
            continue
        if key in config_defaults and config_defaults[key] not in (None, ""):
            _update(key, config_defaults[key], "config")
            continue
        _update(key, builtin, "default")

    for key, value in config_defaults.items():
        if key in resolved or value in (None, ""):
            continue
        _update(key, value, "config")

    for key, value in cli_params.items():
        if value in (None, ""):
            continue
        _update(key, value, "cli")

    return resolved, sources


def ensure_directory(path: Path, *, dry_run: bool = False) -> Path:
    """Create ``path`` unless ``dry_run`` is active."""

    path = Path(path)
    if dry_run:
        return path
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_bool(value: Any) -> bool:
    """Coerce common truthy/falsy values to booleans."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    return bool(value)


def format_plan(steps: Iterable[str]) -> List[str]:
    """Return formatted plan entries for CLI output."""

    formatted: List[str] = []
    for step in steps:
        step = str(step).strip()
        if not step:
            continue
        formatted.append(f"• {step}")
    return formatted


def legacy_invocation(
    script_name: str,
    args: Sequence[str],
    *,
    dry_run: bool = False,
    timeout: int = 900,
) -> "RouterResult":
    """Execute a legacy router script with safeguards."""

    result = RouterResult(status="skipped")
    scripts_root = Path(__file__).resolve().parents[3] / "router" / "scripts"
    script_path = scripts_root / script_name

    if not script_path.exists():
        return result.guard(
            f"Legacy script {script_name} is not available.",
            hints=["Ensure router/scripts is present in the repository."],
        )

    command = [str(script_path), *map(str, args)]
    rendered = " ".join(shlex.quote(part) for part in command)

    if dry_run:
        result.status = "skipped"
        result.message = "Dry-run: legacy command preview"
        result.add_detail(rendered)
        result.data["legacy_command"] = command
        return result

    try:
        completed = subprocess.run(  # noqa: S603,S607 - guarded invocation
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return result.guard(
            f"Unable to execute legacy script {script_name}.",
            hints=["Verify the script is executable."],
        )
    except subprocess.TimeoutExpired:
        return result.guard(
            f"Legacy script {script_name} timed out after {timeout} seconds.",
            status="failed",
        )

    if completed.stdout:
        result.add_detail("[legacy stdout]", completed.stdout.strip())
    if completed.stderr:
        result.add_detail("[legacy stderr]", completed.stderr.strip())

    if completed.returncode != 0:
        return result.guard(
            f"Legacy script {script_name} exited with {completed.returncode}.",
            status="failed",
        )

    result.status = "success"
    result.message = f"Legacy script {script_name} executed successfully."
    result.data["legacy_command"] = command
    return result


def _deterministic(value: Any) -> Any:
    """Return ``value`` converted into a deterministic structure."""

    if isinstance(value, dict):
        return {key: _deterministic(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple, set)):
        return [_deterministic(item) for item in sorted(value, key=lambda item: json.dumps(item, sort_keys=True))]
    return value


def _append_jsonl(entry_path: Path, entry: Mapping[str, Any]) -> None:
    """Append ``entry`` to ``entry_path`` if it does not already exist."""

    entry_path = Path(entry_path)
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(_deterministic(dict(entry)), sort_keys=True)

    if entry_path.exists():
        with entry_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip() == canonical:
                    return

    with entry_path.open("a", encoding="utf-8") as handle:
        handle.write(canonical + "\n")


def record_provenance(case_dir: Path, entry: Mapping[str, Any]) -> None:
    """Append a provenance ``entry`` for ``case_dir``."""

    meta_dir = Path(case_dir) / "meta"
    _append_jsonl(meta_dir / "provenance.jsonl", entry)


def record_chain_of_custody(case_dir: Path, artifact: Mapping[str, Any]) -> None:
    """Record chain-of-custody metadata for an artifact."""

    meta_dir = Path(case_dir) / "meta"
    record = {
        "ts": utc_isoformat(),
        "path": str(artifact.get("path")),
        "sha256": artifact.get("sha256"),
        "size": artifact.get("size"),
        "label": artifact.get("label"),
    }
    _append_jsonl(meta_dir / "chain_of_custody.jsonl", record)


@dataclass
class RouterResult:
    """Result payload returned by router helper functions."""

    status: str = "success"
    message: str = ""
    details: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_isoformat)

    def guard(
        self,
        message: str,
        *,
        status: str = "skipped",
        hints: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "RouterResult":
        """Populate the result as a guard message."""

        self.status = status
        self.message = message
        if hints:
            self.details.extend(str(hint) for hint in hints if hint)
        if metadata:
            merged = dict(self.data)
            merged.update(metadata)
            self.data = merged
        return self

    def add_detail(self, *lines: str) -> None:
        for line in lines:
            if line and line not in self.details:
                self.details.append(line)

    def add_error(self, *lines: str) -> None:
        for line in lines:
            if line and line not in self.errors:
                self.errors.append(line)

    def add_input(self, key: str, value: Any) -> None:
        self.inputs[key] = value

    def add_output(self, *paths: str | Path) -> None:
        existing = {str(path) for path in self.outputs}
        for path in paths:
            text = str(path)
            if text not in existing:
                self.outputs.append(text)
                existing.add(text)
        self.outputs.sort()

    def add_artifact(
        self,
        path: Path,
        *,
        label: Optional[str] = None,
        dry_run: bool = False,
        case_dir: Optional[Path] = None,
        hash_algorithm: str = "sha256",
    ) -> Dict[str, Any]:
        """Register ``path`` as an artifact with optional provenance tracking."""

        artifact_path = Path(path)
        record: Dict[str, Any] = {
            "path": str(artifact_path),
            "label": label or artifact_path.name,
        }

        if not dry_run and artifact_path.exists():
            try:
                digest = compute_hash(artifact_path, algorithm=hash_algorithm)
            except Exception as exc:  # pragma: no cover - IO failures are rare
                self.add_error(f"Failed to hash {artifact_path}: {exc}")
            else:
                record[hash_algorithm] = digest
                record["sha256"] = digest
                record["size"] = artifact_path.stat().st_size
                if case_dir:
                    record_chain_of_custody(case_dir, record)
        elif not dry_run:
            self.add_error(f"Artifact {artifact_path} does not exist")

        if record not in self.artifacts:
            self.artifacts.append(record)
        self.add_output(record["path"])
        self.data.setdefault("artifacts", self.artifacts)
        return record

    def to_cli_kwargs(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message or None,
            "details": self.details,
            "data": self.data or None,
            "errors": self.errors or None,
        }


class RouterModule(ForensicModule):
    """Base class for guarded router modules."""

    module: str = "router.base"
    description_text: str = "Guarded router module"

    def __init__(
        self,
        case_dir: Path,
        config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.case_dir = Path(case_dir)
        self.config = dict(config or {})
        self.logger = logging.getLogger(self.__class__.__name__)
        self.output_dir = self.case_dir / self.config.get("output_dir", "router")
        self._validation_errors: list[str] = []

    @property
    def name(self) -> str:  # pragma: no cover - tiny accessor
        return self.module

    @property
    def description(self) -> str:  # pragma: no cover - tiny accessor
        return self.description_text

    def validate_params(self, params: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate parameters and return a sanitized dictionary."""

        raise NotImplementedError

    def tool_versions(self) -> Dict[str, str]:
        """Return detected tool versions/paths."""

        return {}

    def _timestamp(self, params: Mapping[str, Any]) -> str:
        if "timestamp" in params and params["timestamp"]:
            return str(params["timestamp"])
        fmt = self.config.get("timestamp_format")
        if isinstance(fmt, str) and fmt:
            return time.strftime(fmt, time.gmtime())
        return utc_slug()

    def _router_dir(self) -> Path:
        base = self.case_dir / self.config.get("output_dir", "router")
        return base

    def _case_meta_dir(self) -> Path:
        return self.case_dir / "meta"

    def _log_provenance(
        self,
        *,
        ts: str,
        params: Mapping[str, Any],
        tool_versions: Mapping[str, Any],
        result: RouterResult,
        inputs: Mapping[str, Any],
        duration_ms: int,
        exit_code: int,
    ) -> None:
        entry: Dict[str, Any] = {
            "ts": ts,
            "module": self.module,
            "params": _deterministic(dict(params)),
            "tool_versions": _deterministic(dict(tool_versions)),
            "inputs": _deterministic(dict(inputs)),
            "outputs": sorted(result.outputs),
            "sha256": sorted(
                (
                    {"path": artifact["path"], "sha256": artifact.get("sha256")}
                    for artifact in result.artifacts
                    if artifact.get("sha256")
                ),
                key=lambda item: item["path"],
            ),
            "duration_ms": int(duration_ms),
            "exit_code": int(exit_code),
        }
        record_provenance(self.case_dir, entry)

    def run(
        self,
        framework: Any,
        case: Path | str,
        params: Mapping[str, Any],
    ) -> RouterResult:
        """Execute the guarded router module."""

        raise NotImplementedError


def detect_tools(*tools: str) -> Dict[str, str]:
    """Return a mapping of ``tool`` to the detected executable path."""

    discovered: Dict[str, str] = {}
    for tool in tools:
        path = shutil.which(tool)
        if path:
            discovered[tool] = path
    return discovered


__all__ = [
    "RouterModule",
    "RouterResult",
    "detect_tools",
    "ensure_directory",
    "format_plan",
    "legacy_invocation",
    "load_router_defaults",
    "normalize_bool",
    "record_chain_of_custody",
    "record_provenance",
    "resolve_parameters",
]
