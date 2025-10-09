from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from forensic.utils import hashing


def test_compute_stream_hash_validates_chunk_size() -> None:
    stream = io.BytesIO(b"data")
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(stream, chunk_size=0)


def test_compute_stream_hash_rejects_unknown_algorithm() -> None:
    stream = io.BytesIO(b"payload")
    with pytest.raises(ValueError):
        hashing.compute_stream_hash(stream, algorithm="sha512")


def test_compute_hashes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world")

    results = hashing.compute_hashes(sample, ["md5", "sha1", "sha256"])

    assert set(results) == {"md5", "sha1", "sha256"}
    assert results["md5"] == hashlib.md5(b"hello world").hexdigest()
    assert results["sha1"] == hashlib.sha1(b"hello world").hexdigest()
    assert results["sha256"] == hashlib.sha256(b"hello world").hexdigest()
