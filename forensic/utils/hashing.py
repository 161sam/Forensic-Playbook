"""Hash helper utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Iterable

SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha256"}

_DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _get_hasher(algorithm: str) -> hashlib._Hash:
    """Return a configured :mod:`hashlib` object for ``algorithm``."""

    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return getattr(hashlib, algorithm)()


def compute_stream_hash(
    stream: BinaryIO,
    *,
    algorithm: str = "sha256",
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> str:
    """Hash the contents of ``stream`` in a memory efficient manner.

    The caller remains responsible for rewinding or closing ``stream``.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    hasher = _get_hasher(algorithm)
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        if chunk:
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_hash(
    path: Path, algorithm: str = "sha256", *, chunk_size: int = _DEFAULT_CHUNK_SIZE
) -> str:
    """Compute the hash of ``path`` using ``algorithm`` with streaming I/O."""

    with Path(path).open("rb") as handle:
        return compute_stream_hash(handle, algorithm=algorithm, chunk_size=chunk_size)


def compute_hashes(
    path: Path,
    algorithms: Iterable[str],
    *,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> dict:
    """Compute multiple hashes in a single streaming pass.

    The file at ``path`` is read once and every requested hash algorithm is
    updated chunk-wise. This keeps memory usage low even for large files while
    avoiding redundant I/O.
    """

    algorithms = list(dict.fromkeys(algo.lower() for algo in algorithms))
    if not algorithms:
        return {}

    hashers = {algo: _get_hasher(algo) for algo in algorithms}

    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)

    return {algo: hashers[algo].hexdigest() for algo in algorithms}


__all__ = [
    "SUPPORTED_ALGORITHMS",
    "compute_hash",
    "compute_hashes",
    "compute_stream_hash",
]
