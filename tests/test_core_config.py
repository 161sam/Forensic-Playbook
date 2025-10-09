from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic.core import config


@pytest.fixture(autouse=True)
def clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORENSIC_CONFIG_DIR", raising=False)
    for key in list(os.environ):
        if key.startswith("FORENSIC_") and key != "FORENSIC_CONFIG_DIR":
            monkeypatch.delenv(key, raising=False)


def test_merge_dicts_nested_precedence() -> None:
    base = {"network": {"interface": "eth0", "timeout": 5}, "log_level": "INFO"}
    override = {"network": {"timeout": 10}, "log_level": "DEBUG", "extra": True}

    result = config.merge_dicts(base, override)

    assert result["network"] == {"interface": "eth0", "timeout": 10}
    assert result["log_level"] == "DEBUG"
    assert result["extra"] is True


def test_coerce_env_value() -> None:
    assert config._coerce_env_value("TRUE") is True
    assert config._coerce_env_value("false") is False
    assert config._coerce_env_value("42") == 42
    assert config._coerce_env_value("not-a-number") == "not-a-number"


def test_load_env_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIC_LOG_LEVEL", "debug")
    monkeypatch.setenv("FORENSIC_PARALLEL_EXECUTION", "FALSE")

    env_config = config._load_env_config()

    assert env_config == {"log_level": "debug", "parallel_execution": False}


def test_load_yaml_without_pyyaml_warns(tmp_path: Path) -> None:
    target = tmp_path / "config.yaml"
    target.write_text("log_level: DEBUG", encoding="utf-8")

    with pytest.warns(RuntimeWarning):
        assert config.load_yaml(target) == {}


def test_load_yaml_raises_for_non_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "config.yaml"
    target.write_text("items", encoding="utf-8")

    monkeypatch.setattr(config, "yaml", SimpleNamespace(safe_load=lambda handle: [1, 2, 3]))

    with pytest.raises(TypeError):
        config.load_yaml(target)


def test_get_config_merges_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    yaml_file = config_dir / "framework.yaml"
    yaml_file.write_text("log_level: DEBUG\nmax_workers: 2", encoding="utf-8")

    def fake_safe_load(handle):
        text = handle.read()
        data: dict[str, object] = {}
        for line in text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                data[key.strip()] = value.strip()
        return data

    monkeypatch.setattr(config, "yaml", SimpleNamespace(safe_load=fake_safe_load))
    monkeypatch.setenv("FORENSIC_MAX_WORKERS", "8")

    overrides = {"workspace_name": "custom"}
    cfg = config.get_config(config_root=config_dir, overrides=overrides)

    assert cfg.log_level == "DEBUG"
    assert cfg.max_workers == 8
    assert cfg.workspace_name == "custom"
    assert "network" in cfg.extra
    assert cfg.extra["network"]["default_tool"] == "tcpdump"
    assert cfg.as_dict()["log_level"] == "DEBUG"


def test_resolve_config_root_prefers_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit"
    explicit.mkdir()

    result = config._resolve_config_root(explicit)
    assert result == explicit

    env_dir = tmp_path / "env"
    env_dir.mkdir()
    monkeypatch.setenv("FORENSIC_CONFIG_DIR", str(env_dir))
    result = config._resolve_config_root(None)
    assert result == env_dir
