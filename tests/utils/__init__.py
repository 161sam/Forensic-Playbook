"""Utility helpers for test fixtures."""

from __future__ import annotations

import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO, Tuple

from .pcap_synth import MINIMAL_PCAP_NAME


def invoke_pcap_synth(out_dir: Path) -> Tuple[Path | None, str]:
    """Run the runtime PCAP synthesizer and return its outputs."""

    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [sys.executable, "-m", "tests.utils.pcap_synth", "--out", str(out_dir)],
            capture_output=True,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - defensive
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise RuntimeError(f"PCAP synthesizer failed: {message}") from exc

    stdout = result.stdout.strip()
    pcap_path = out_dir / MINIMAL_PCAP_NAME

    if pcap_path.exists():
        return pcap_path, stdout

    if stdout:
        return None, stdout

    raise RuntimeError(
        "PCAP synthesizer did not produce output (expected file or JSON payload)."
    )


@contextmanager
def redirect_stdin(stream: TextIO) -> Iterator[None]:
    """Temporarily redirect :data:`sys.stdin` to ``stream``."""

    previous = sys.stdin
    try:
        sys.stdin = stream
        yield
    finally:
        sys.stdin = previous


__all__ = ["invoke_pcap_synth", "MINIMAL_PCAP_NAME", "redirect_stdin"]
