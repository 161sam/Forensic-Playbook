from __future__ import annotations

from datetime import datetime, timezone

from forensic.utils import timefmt


def test_to_iso_handles_none() -> None:
    assert timefmt.to_iso(None) is None


def test_to_iso_preserves_timezone() -> None:
    aware = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert timefmt.to_iso(aware) == "2024-01-01T12:00:00Z"
