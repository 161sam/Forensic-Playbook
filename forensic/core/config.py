"""Framework configuration helpers.

This module provides deterministic configuration loading with sensible
defaults. Configuration is sourced from (in order of precedence):

1. Explicit configuration dictionaries provided to :func:`get_config`.
2. Environment variables prefixed with ``FORENSIC_``.
3. YAML files located in ``config/`` or ``$FORENSIC_CONFIG_DIR``.
4. Built-in framework defaults.

The loader is intentionally light-weight and does not depend on external
packages beyond ``PyYAML`` which is already a dependency of the
framework. All helpers are designed to be idempotent and safe to call
multiple times. Missing configuration files simply result in the default
configuration being used.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "log_level": "INFO",
    "parallel_execution": True,
    "max_workers": 4,
    "output_formats": ["json", "html"],
    "enable_coc": True,
    "hash_algorithm": "sha256",
    "timezone": "UTC",
    "workspace_name": "forensic_workspace",
}


def load_yaml(path: Path) -> dict[str, Any]:
    """Safely load YAML configuration from ``path``.

    The function returns an empty dictionary when the file does not exist
    or is empty. Parsing errors are surfaced to aid debugging.
    """

    if not path or not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, Mapping):
        raise TypeError(f"Config file must contain a mapping: {path}")

    return dict(data)


def merge_dicts(*dicts: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge mappings with later dictionaries taking precedence."""

    merged: dict[str, Any] = {}

    for current in dicts:
        for key, value in current.items():
            if (
                key in merged
                and isinstance(merged[key], MutableMapping)
                and isinstance(value, Mapping)
            ):
                merged[key] = merge_dicts(merged[key], value)  # type: ignore[arg-type]
            else:
                merged[key] = value

    return merged


def _iter_candidate_configs(root: Path) -> Iterable[Path]:
    """Yield configuration files in deterministic order."""

    files = [root / "framework.yaml"]
    module_dir = root / "modules"
    if module_dir.exists():
        files.extend(sorted(module_dir.glob("*.yaml")))
    return (path for path in files if path.exists())


def _load_env_config(prefix: str = "FORENSIC_") -> dict[str, Any]:
    """Load configuration overrides from environment variables."""

    env_config: dict[str, Any] = {}
    prefix_len = len(prefix)

    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        config_key = key[prefix_len:].lower()
        env_config[config_key] = _coerce_env_value(value)

    return env_config


def _coerce_env_value(value: str) -> Any:
    """Attempt to cast environment variable values to richer types."""

    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"

    if lowered.isdigit():
        try:
            return int(lowered)
        except ValueError:
            pass

    return value


@dataclass(frozen=True)
class FrameworkConfig:
    """Strongly typed configuration representation."""

    log_level: str = DEFAULT_CONFIG["log_level"]
    parallel_execution: bool = DEFAULT_CONFIG["parallel_execution"]
    max_workers: int = DEFAULT_CONFIG["max_workers"]
    output_formats: Iterable[str] = field(
        default_factory=lambda: tuple(DEFAULT_CONFIG["output_formats"])
    )
    enable_coc: bool = DEFAULT_CONFIG["enable_coc"]
    hash_algorithm: str = DEFAULT_CONFIG["hash_algorithm"]
    timezone: str = DEFAULT_CONFIG["timezone"]
    workspace_name: str = DEFAULT_CONFIG["workspace_name"]
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        data = {
            "log_level": self.log_level,
            "parallel_execution": self.parallel_execution,
            "max_workers": self.max_workers,
            "output_formats": list(self.output_formats),
            "enable_coc": self.enable_coc,
            "hash_algorithm": self.hash_algorithm,
            "timezone": self.timezone,
            "workspace_name": self.workspace_name,
        }
        data.update(self.extra)
        return data


def get_config(
    config_root: Optional[Path] = None,
    overrides: Optional[Mapping[str, Any]] = None,
) -> FrameworkConfig:
    """Load framework configuration.

    Args:
        config_root: Optional directory containing YAML configuration.
        overrides: Explicit overrides that take highest precedence.

    Returns:
        A :class:`FrameworkConfig` instance.
    """

    config_root = _resolve_config_root(config_root)

    yaml_config: dict[str, Any] = {}
    if config_root:
        for candidate in _iter_candidate_configs(config_root):
            yaml_config = merge_dicts(yaml_config, load_yaml(candidate))

    env_config = _load_env_config()
    explicit_overrides = dict(overrides or {})

    merged = merge_dicts(DEFAULT_CONFIG, yaml_config, env_config, explicit_overrides)

    known_keys = {
        "log_level",
        "parallel_execution",
        "max_workers",
        "output_formats",
        "enable_coc",
        "hash_algorithm",
        "timezone",
        "workspace_name",
    }

    extra = {k: v for k, v in merged.items() if k not in known_keys}

    return FrameworkConfig(
        log_level=str(merged["log_level"]),
        parallel_execution=bool(merged["parallel_execution"]),
        max_workers=int(merged["max_workers"]),
        output_formats=tuple(merged.get("output_formats", [])),
        enable_coc=bool(merged["enable_coc"]),
        hash_algorithm=str(merged["hash_algorithm"]),
        timezone=str(merged["timezone"]),
        workspace_name=str(merged["workspace_name"]),
        extra=extra,
    )


def _resolve_config_root(config_root: Optional[Path]) -> Optional[Path]:
    """Determine the configuration directory to use."""

    if config_root and config_root.exists():
        return config_root

    env_root = os.environ.get("FORENSIC_CONFIG_DIR")
    if env_root:
        candidate = Path(env_root).expanduser()
        if candidate.exists():
            return candidate

    repo_root = Path(__file__).resolve().parents[2]
    default_root = repo_root / "config"
    if default_root.exists():
        return default_root

    return None


__all__ = [
    "DEFAULT_CONFIG",
    "FrameworkConfig",
    "get_config",
    "load_yaml",
    "merge_dicts",
]
