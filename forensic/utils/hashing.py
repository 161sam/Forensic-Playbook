"""Hash helper utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha256"}


def compute_hash(path: Path, algorithm: str = "sha256") -> str:
    """Compute the hash of ``path`` using ``algorithm``."""

    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    hasher = getattr(hashlib, algorithm)()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_hashes(path: Path, algorithms: Iterable[str]) -> dict:
    """Compute multiple hashes and return a mapping."""

    return {algo: compute_hash(path, algo) for algo in algorithms}


__all__ = ["SUPPORTED_ALGORITHMS", "compute_hash", "compute_hashes"]
