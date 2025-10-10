"""Common helpers for the forensic notebook labs.

These helpers intentionally avoid any non-standard dependencies and are
careful to create deterministic artefacts under ``.labs/<lab_id>``.
"""
from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence, Tuple, Union

try:  # Optional dependency used across the repository
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    yaml = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = REPO_ROOT / "config"
FRAMEWORK_CONFIG = CONFIG_ROOT / "framework.yaml"
DEFAULT_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
RUN_TIMEOUT = 30  # seconds


def lab_root(lab_id: str) -> Path:
    """Return the deterministic artefact root for a lab and ensure it exists."""

    safe_id = lab_id.strip().lower().replace(" ", "-")
    base = REPO_ROOT / ".labs" / safe_id
    base.mkdir(parents=True, exist_ok=True)
    return base


def _load_timestamp_format() -> str:
    """Load the timestamp format from configuration with a sensible fallback."""

    if FRAMEWORK_CONFIG.exists() and yaml is not None:
        try:
            with FRAMEWORK_CONFIG.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            if isinstance(data, MutableMapping):
                fmt = data.get("timestamp_format")
                if isinstance(fmt, str) and fmt:
                    return fmt
                timezone_cfg = data.get("timezone")
                if isinstance(timezone_cfg, MutableMapping):
                    fmt = timezone_cfg.get("format")
                    if isinstance(fmt, str) and fmt:
                        return fmt
        except Exception:  # pragma: no cover - configuration edge cases
            pass

    router_common = CONFIG_ROOT / "modules" / "router" / "common.yaml"
    if router_common.exists() and yaml is not None:
        try:
            with router_common.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            if isinstance(data, MutableMapping):
                fmt = data.get("timestamp_format")
                if isinstance(fmt, str) and fmt:
                    return fmt
        except Exception:  # pragma: no cover - configuration edge cases
            pass

    return DEFAULT_TIMESTAMP_FORMAT


_TIMESTAMP_FORMAT = _load_timestamp_format()


def _ts() -> str:
    """Return a deterministic UTC timestamp string based on configuration."""

    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def _sorted_structure(value):
    if isinstance(value, Mapping):
        return {k: _sorted_structure(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_sorted_structure(item) for item in sorted(value, key=_sort_key)]
    return value


def _sort_key(value):
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def json_dump_sorted(obj, path: Union[str, Path]) -> Path:
    """Write JSON with deterministically ordered keys and list items."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_obj = _sorted_structure(obj)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(sorted_obj, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return path


def csv_write_rows_sorted(
    rows: Iterable[Union[Sequence[str], Mapping[str, str]]],
    path: Union[str, Path],
    header: Sequence[str],
) -> Path:
    """Write CSV rows deterministically sorted by their serialised representation."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    serialised: list[Tuple[str, Sequence[str]]] = []
    for row in rows:
        if isinstance(row, Mapping):
            ordered = [str(row.get(col, "")) for col in header]
        else:
            ordered = [str(value) for value in row]
        serialised.append(("|".join(ordered), ordered))

    serialised.sort(key=lambda item: item[0])

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([str(col) for col in header])
        for _, ordered in serialised:
            writer.writerow(ordered)

    return path


def shell_available(cmd: str) -> bool:
    """Return ``True`` if ``cmd`` can be resolved in the current PATH."""

    from shutil import which

    return which(cmd) is not None


@dataclass
class CliResult:
    returncode: int
    stdout: str
    stderr: str


def run_cli(cmd: Sequence[str], tolerate: bool = True) -> CliResult:
    """Execute a CLI command with deterministic handling.

    The command is executed without shell involvement. When ``tolerate`` is
    ``True`` (the default) the return code is surfaced but not raised. When
    ``False`` a non-zero exit status raises ``RuntimeError`` for the caller to
    handle explicitly.
    """

    if not isinstance(cmd, (list, tuple)):
        raise TypeError("cmd must be a sequence of strings")

    try:
        completed = subprocess.run(
            list(cmd),
            check=False,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT,
        )
    except FileNotFoundError as exc:
        result = CliResult(returncode=127, stdout="", stderr=str(exc))
        if tolerate:
            return result
        raise RuntimeError(f"Command not found: {cmd!r}") from exc
    except subprocess.TimeoutExpired as exc:
        stderr = getattr(exc, "stderr", "") or "Command timed out"
        result = CliResult(returncode=-1, stdout=getattr(exc, "stdout", ""), stderr=stderr)
        if tolerate:
            return result
        raise RuntimeError(f"Command timed out: {cmd!r}") from exc

    result = CliResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )

    if completed.returncode != 0 and not tolerate:
        raise RuntimeError(
            f"Command failed with exit code {completed.returncode}: {cmd!r}\n{completed.stderr}"
        )

    return result


def preview(path: Union[str, Path], max_bytes: int = 4096) -> str:
    """Return a UTF-8 preview of a file, limited to ``max_bytes``."""

    path = Path(path)
    if not path.exists():
        return f"<missing: {path}>"

    with path.open("rb") as handle:
        snippet = handle.read(max_bytes)

    try:
        return snippet.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - encoding edge case
        return "<binary data>"


__all__ = [
    "CliResult",
    "CONFIG_ROOT",
    "DRY_RUN",
    "FRAMEWORK_CONFIG",
    "REPO_ROOT",
    "RUN_TIMEOUT",
    "_ts",
    "csv_write_rows_sorted",
    "json_dump_sorted",
    "lab_root",
    "preview",
    "run_cli",
    "shell_available",
]

DRY_RUN = True
