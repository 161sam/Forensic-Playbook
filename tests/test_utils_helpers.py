"""Tests for utility helper modules."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from io import BytesIO
from pathlib import Path

import pytest

from forensic.utils import io as io_utils
from forensic.utils import paths as paths_utils
from forensic.utils import timefmt
from forensic.utils import hashing


def test_read_text_returns_empty_for_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"
    assert io_utils.read_text(missing) == ""


def test_write_text_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "file.txt"
    io_utils.write_text(target, "hello world")
    assert target.exists()
    assert target.read_text() == "hello world"


def test_write_json_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    data = {"b": 1, "a": 2}
    io_utils.write_json(target, data)
    assert json.loads(target.read_text()) == data


def test_ensure_directory_returns_existing_path(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    result = paths_utils.ensure_directory(target)
    assert result == target
    assert target.exists()


def test_resolve_workspace_creates_directory(tmp_path: Path) -> None:
    base = tmp_path / "base"
    name = "module"
    workspace = paths_utils.resolve_workspace(base, name)
    assert workspace == base / name
    assert workspace.exists()


def test_resolve_config_paths_filters_existing_files(tmp_path: Path) -> None:
    existing = tmp_path / "existing.yml"
    existing.write_text("content")
    missing = "missing.yml"
    paths = list(paths_utils.resolve_config_paths(tmp_path, [existing.name, missing]))
    assert paths == [existing]


def test_optional_path_expands_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    user_path = "~/documents"
    resolved = paths_utils.optional_path(user_path)
    assert resolved == (tmp_path / "documents")


def test_optional_path_returns_none_for_empty_value() -> None:
    assert paths_utils.optional_path(None) is None
    assert paths_utils.optional_path("") is None


def test_to_iso_handles_naive_and_aware_datetimes() -> None:
    naive = datetime(2020, 1, 1, 12, 30, 45)
    aware = datetime(2020, 1, 1, 12, 30, 45, tzinfo=timezone(timedelta(hours=2)))
    assert timefmt.to_iso(naive) == "2020-01-01T12:30:45Z"
    assert timefmt.to_iso(aware) == "2020-01-01T10:30:45Z"


def test_to_iso_returns_none_for_missing_datetime() -> None:
    assert timefmt.to_iso(None) is None


def test_compute_stream_hash_validates_inputs() -> None:
    stream = BytesIO(b"data")
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(stream, chunk_size=0)
    stream.seek(0)
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(stream, algorithm="sha512")


def test_compute_hashes(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("sample data")
    hashes = hashing.compute_hashes(file_path, ["md5", "sha1", "sha256"])
    assert set(hashes.keys()) == {"md5", "sha1", "sha256"}
    # Ensure values are produced for every algorithm
    assert all(len(value) > 0 for value in hashes.values())

