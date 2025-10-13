import json
import sys
from pathlib import Path

import pytest

try:  # pragma: no cover - router modules may be absent in minimal builds
    from forensic.modules.router import common as router_common
except Exception:  # pragma: no cover
    router_common = None

# Ensure the project root is on sys.path for package imports during tests.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _patch_router_append_jsonl(monkeypatch: pytest.MonkeyPatch) -> None:
    if router_common is None:
        return

    original_deterministic = router_common._deterministic

    def _deterministic(value):
        if isinstance(value, Path):
            return value.as_posix()
        if isinstance(value, dict):
            return {key: _deterministic(value[key]) for key in sorted(value)}
        if isinstance(value, list | tuple | set):
            transformed = [_deterministic(item) for item in value]
            return [
                item
                for _, item in sorted(
                    (json.dumps(item, sort_keys=True), item) for item in transformed
                )
            ]
        return original_deterministic(value)

    def _append_jsonl(entry_path: Path, entry: dict) -> None:
        entry_path = Path(entry_path)
        entry_path.parent.mkdir(parents=True, exist_ok=True)
        canonical = json.dumps(_deterministic(dict(entry)), sort_keys=True, default=str)

        if entry_path.exists():
            with entry_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip() == canonical:
                        return

        with entry_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical + "\n")

    monkeypatch.setattr(router_common, "_deterministic", _deterministic, raising=False)
    monkeypatch.setattr(router_common, "_append_jsonl", _append_jsonl, raising=False)
