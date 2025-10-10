"""Shared helpers for router forensic modules."""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from forensic.core.chain_of_custody import append_coc
from forensic.core.config import load_yaml
from forensic.core.time_utils import utc_isoformat
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
        if not candidate:
            continue
        resolved = candidate.resolve()
        if resolved not in normalized:
            normalized.append(resolved)
    return normalized


def load_router_defaults(name: str) -> Dict[str, Any]:
    """Load router module defaults from YAML configuration files.

    The lookup order honours nested ``config/modules/router/<name>.yaml``
    locations before falling back to legacy ``config/modules/router_<name>.yaml``
    layouts. Missing files simply result in an empty dictionary.
    """

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
                except Exception:  # pragma: no cover - config parse errors surface later
                    continue
                if isinstance(data, Mapping):
                    return dict(data)
    return {}


@dataclass
class RouterResult:
    """Result payload returned by router helper functions."""

    status: str = "success"
    message: str = ""
    details: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
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

    def add_artifact(
        self,
        path: Path,
        *,
        label: Optional[str] = None,
        dry_run: bool = False,
        hash_algorithm: str = "sha256",
        coc_log: Optional[Path] = None,
    ) -> None:
        """Register ``path`` as an artifact with optional provenance tracking."""

        artifact_path = Path(path)
        record: Dict[str, Any] = {
            "path": str(artifact_path),
            "label": label or artifact_path.name,
        }

        if not dry_run and artifact_path.exists():
            try:
                digest = compute_hash(artifact_path, algorithm=hash_algorithm)
            except Exception as exc:  # pragma: no cover - disk errors are rare
                self.add_error(f"Failed to hash {artifact_path}: {exc}")
            else:
                record[hash_algorithm] = digest
                if coc_log:
                    try:
                        append_coc(coc_log, path=str(artifact_path), sha256=digest)
                    except Exception as exc:  # pragma: no cover - IO heavy
                        self.add_error(f"Failed to update chain of custody: {exc}")

        if record not in self.artifacts:
            self.artifacts.append(record)
        self.data.setdefault("artifacts", self.artifacts)

    def to_cli_kwargs(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message or None,
            "details": self.details,
            "data": self.data or None,
            "errors": self.errors or None,
        }


def resolve_parameters(
    cli_params: Mapping[str, Any],
    config_defaults: Mapping[str, Any],
    builtin_defaults: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Merge parameters with precedence CLI > config > built-in defaults."""

    resolved: Dict[str, Any] = {}
    sources: Dict[str, str] = {}

    def _update(key: str, value: Any, source: str) -> None:
        if value is None:
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


def legacy_invocation(
    script_name: str,
    args: Sequence[str],
    *,
    dry_run: bool = False,
    timeout: int = 900,
) -> RouterResult:
    """Execute a legacy router script with safeguards."""

    result = RouterResult()
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
        result.message = "Dry-run: legacy command preview"
        result.add_detail(rendered)
        result.data["legacy_command"] = command
        return result

    try:
        completed = subprocess.run(  # noqa: S603,S607 - guarded execution
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
        result.add_detail("[legacy stdout]" , completed.stdout.strip())
    if completed.stderr:
        result.add_detail("[legacy stderr]", completed.stderr.strip())

    if completed.returncode != 0:
        return result.guard(
            f"Legacy script {script_name} exited with {completed.returncode}.",
            status="failed",
        )

    result.message = f"Legacy script {script_name} executed successfully."
    result.data["legacy_command"] = command
    return result


def format_plan(steps: Iterable[str]) -> List[str]:
    """Return formatted plan entries for CLI output."""

    formatted: List[str] = []
    for step in steps:
        step = step.strip()
        if not step:
            continue
        formatted.append(f"• {step}")
    return formatted
